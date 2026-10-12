// MobSF Bug Bounty Windows launcher. GPL-3.0-only; upstream credits are retained.
package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"
)

//go:embed resources/source.zip
var sourceArchive []byte

const projectName = "mobsf-bounty-desktop"
const localURL = "http://127.0.0.1:8000/bounty/"

var containerID = regexp.MustCompile(`^[a-f0-9]{12,64}$`)
var reservedName = regexp.MustCompile(`^(COM|LPT)[1-9¹²³]$`)

func sourceID() string {
	digest := sha256.Sum256(sourceArchive)
	return hex.EncodeToString(digest[:])
}

func safeEntry(name string) bool {
	if name == "" || !utf8.ValidString(name) || strings.ContainsAny(name, `\:*?"<>|`) || strings.HasPrefix(name, "/") || path.Clean(name) != name {
		return false
	}
	for _, char := range name {
		if char < 32 {
			return false
		}
	}
	for _, part := range strings.Split(name, "/") {
		if part == "." || part == ".." || strings.TrimRight(part, " .") != part {
			return false
		}
		base := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || reservedName.MatchString(base) {
			return false
		}
	}
	return true
}

func extractArchive(data []byte, destination string) error {
	archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	if len(archive.File) > 10000 {
		return errors.New("source archive has too many entries")
	}
	seen := make(map[string]bool)
	var total uint64
	for _, file := range archive.File {
		name := strings.TrimSuffix(file.Name, "/")
		key := strings.ToLower(name)
		if !safeEntry(name) || seen[key] || file.Mode()&os.ModeSymlink != 0 || (!file.FileInfo().IsDir() && !file.Mode().IsRegular()) {
			return fmt.Errorf("unsafe or duplicate source archive entry: %q", file.Name)
		}
		seen[key] = true
		if file.UncompressedSize64 > 256<<20 || total > (512<<20)-file.UncompressedSize64 {
			return errors.New("source archive exceeds size limits")
		}
		total += file.UncompressedSize64
		target := filepath.Join(destination, filepath.FromSlash(name))
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0700); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return err
		}
		reader, err := file.Open()
		if err != nil {
			return err
		}
		writer, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, file.Mode().Perm())
		if err != nil {
			reader.Close()
			return err
		}
		_, copyErr := io.Copy(writer, io.LimitReader(reader, int64(file.UncompressedSize64)+1))
		closeReadErr := reader.Close()
		closeWriteErr := writer.Close()
		if err := errors.Join(copyErr, closeReadErr, closeWriteErr); err != nil {
			return err
		}
	}
	for _, required := range []string{"Dockerfile", "manage.py", "poetry.lock", "docker/desktop-compose.yml"} {
		info, err := os.Stat(filepath.Join(destination, filepath.FromSlash(required)))
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("source archive is missing %s", required)
		}
	}
	return nil
}

func ensureSource(home string) (string, error) {
	parent := filepath.Join(home, "app")
	if err := os.MkdirAll(parent, 0700); err != nil {
		return "", err
	}
	root := filepath.Join(parent, sourceID())
	if info, err := os.Lstat(root); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("source location is not a regular directory")
		}
		return root, nil
	}
	temporary, err := os.MkdirTemp(parent, "extract-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(temporary)
	if err := extractArchive(sourceArchive, temporary); err != nil {
		return "", err
	}
	if err := os.Rename(temporary, root); err != nil {
		return "", err
	}
	return root, nil
}

func ensureConfig(home string) (string, error) {
	if err := os.MkdirAll(home, 0700); err != nil {
		return "", err
	}
	location := filepath.Join(home, "desktop.env")
	info, err := os.Lstat(location)
	if err == nil {
		if !info.Mode().IsRegular() {
			return "", errors.New("configuration is not a regular file")
		}
		return location, nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	content := "MOBSF_ADMIN_PASSWORD=" + hex.EncodeToString(secret) + "\n" +
		"MOBSF_ANDROID_MODERN_DYNAMIC=0\nMOBSF_ANDROID_ALLOW_LOW_TARGET_INSTALL=0\nMOBSF_ANALYZER_IDENTIFIER=\n"
	file, err := os.OpenFile(location, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	_, writeErr := io.WriteString(file, content)
	return location, errors.Join(writeErr, file.Close())
}

func composeArgs(root, config string, args ...string) []string {
	base := []string{"compose", "--project-name", projectName, "--project-directory", root,
		"--env-file", config, "-f", filepath.Join(root, "docker", "desktop-compose.yml")}
	return append(base, args...)
}

func dockerOutput(ctx context.Context, docker string, args ...string) (string, error) {
	command := exec.CommandContext(ctx, docker, args...)
	command.Env = append(os.Environ(), "MOBSF_DESKTOP_SOURCE_ID="+sourceID())
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("Docker command failed (%s); run doctor or inspect Docker Desktop", args[0])
	}
	return strings.TrimSpace(string(output)), nil
}

func dockerRun(ctx context.Context, docker string, args ...string) error {
	command := exec.CommandContext(ctx, docker, args...)
	command.Env = append(os.Environ(), "MOBSF_DESKTOP_SOURCE_ID="+sourceID())
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	return command.Run()
}

func dockerReady(ctx context.Context) (string, error) {
	docker, err := exec.LookPath("docker")
	if err != nil {
		return "", errors.New("install Docker Desktop with WSL2 from https://www.docker.com/products/docker-desktop/ and reopen this launcher")
	}
	if kind, err := dockerOutput(ctx, docker, "info", "--format", "{{.OSType}}"); err != nil || kind != "linux" {
		return "", errors.New("start Docker Desktop and select Linux containers with the WSL2 backend")
	}
	if _, err := dockerOutput(ctx, docker, "compose", "version", "--short"); err != nil {
		return "", errors.New("Docker Compose v2 is required; update Docker Desktop")
	}
	return docker, nil
}

func waitReady(ctx context.Context, docker, root, config string) error {
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		id, err := dockerOutput(ctx, docker, composeArgs(root, config, "ps", "-q", "mobsf")...)
		if err == nil && containerID.MatchString(id) {
			state, err := dockerOutput(ctx, docker, "inspect", "--format", "{{.State.Health.Status}}", id)
			if err == nil && state == "healthy" {
				response, err := client.Get("http://127.0.0.1:8000/login/")
				if err == nil {
					body, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
					response.Body.Close()
					if response.StatusCode == http.StatusOK && readErr == nil && bytes.Contains(body, []byte("csrfmiddlewaretoken")) {
						return nil
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return errors.New("startup did not become ready; run the logs command (existing data is preserved)")
		case <-ticker.C:
		}
	}
}

func openBrowser() error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", localURL).Start()
	case "darwin":
		return exec.Command("open", localURL).Start()
	default:
		return exec.Command("xdg-open", localURL).Start()
	}
}

func selfTest() error {
	root, err := os.MkdirTemp("", "mobsf-launcher-self-test-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	if _, err := ensureSource(root); err != nil {
		return err
	}
	location, err := ensureConfig(root)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(location)
	if err != nil || !bytes.Contains(data, []byte("MOBSF_ADMIN_PASSWORD=")) {
		return errors.New("local configuration self-test failed")
	}
	fmt.Println("Embedded source and local configuration self-test passed; Docker was not started.")
	return nil
}

func run(args []string) error {
	action := "start"
	if len(args) > 1 {
		return errors.New("usage: MobSF-BugBounty.exe [start|stop|status|logs|doctor|android-check|credentials|password|self-test]")
	}
	if len(args) == 1 {
		action = args[0]
	}
	if action == "self-test" {
		return selfTest()
	}
	switch action {
	case "start", "stop", "status", "logs", "doctor", "android-check", "credentials", "password":
	default:
		return errors.New("unknown command; use start, stop, status, logs, doctor, android-check, credentials, password or self-test")
	}
	fmt.Println("MobSF Bug Bounty Edition — source SHA256:", sourceID())
	base, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	home := filepath.Join(base, "MobSF-BugBounty")
	if action == "credentials" {
		data, err := os.ReadFile(filepath.Join(home, "desktop.env"))
		if err != nil {
			return errors.New("no initial credentials found; run start first")
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "MOBSF_ADMIN_PASSWORD=") {
				fmt.Println("Username: mobsf\nInitial password:", strings.TrimPrefix(line, "MOBSF_ADMIN_PASSWORD="))
				fmt.Println("This is the initial password; password changes do not update this file.")
				return nil
			}
		}
		return errors.New("initial password is absent from local configuration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	docker, err := dockerReady(ctx)
	if err != nil {
		return err
	}
	if action == "doctor" {
		fmt.Println("Docker Desktop Linux engine and Compose v2 are available.")
		fmt.Println("Local configuration:", filepath.Join(home, "desktop.env"))
		fmt.Println("Use android-check for read-only diagnostics of your configured authorized Android device.")
		return nil
	}
	root, err := ensureSource(home)
	if err != nil {
		return err
	}
	config, err := ensureConfig(home)
	if err != nil {
		return err
	}
	switch action {
	case "start":
		fmt.Println("Starting this bundled edition with persistent local data. First startup builds the image, needs Internet and may take several minutes.")
		buildFlag := "--build"
		if _, err := dockerOutput(ctx, docker, "image", "inspect", "mobsf-bounty-desktop:"+sourceID()); err == nil {
			buildFlag = "--no-build"
		}
		if err := dockerRun(ctx, docker, composeArgs(root, config, "up", "-d", buildFlag)...); err != nil {
			return err
		}
		readyContext, readyCancel := context.WithTimeout(ctx, 10*time.Minute)
		defer readyCancel()
		if err := waitReady(readyContext, docker, root, config); err != nil {
			return err
		}
		fmt.Println("Workspace is ready at", localURL)
		fmt.Println("Username: mobsf. Run MobSF-BugBounty.exe credentials to view the initial password, or password to change it.")
		if err := openBrowser(); err != nil {
			fmt.Println("Could not open the browser automatically; open the local workspace address above.")
		}
	case "stop":
		return dockerRun(ctx, docker, composeArgs(root, config, "stop")...)
	case "status":
		return dockerRun(ctx, docker, composeArgs(root, config, "ps")...)
	case "logs":
		return dockerRun(ctx, docker, composeArgs(root, config, "logs", "--tail", "100", "mobsf")...)
	case "password":
		return dockerRun(ctx, docker, composeArgs(root, config, "exec", "mobsf", "python", "manage.py", "changepassword", "mobsf")...)
	case "android-check":
		return dockerRun(ctx, docker, composeArgs(root, config, "exec", "-T", "mobsf", "python", "manage.py", "android_preflight", "--json")...)
	}
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "MobSF:", err)
		if runtime.GOOS == "windows" && len(os.Args) == 1 {
			fmt.Fprintln(os.Stderr, "Press Enter to close.")
			fmt.Scanln()
		}
		os.Exit(1)
	}
}
