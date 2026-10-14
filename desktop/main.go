// MobSF Bug Bounty Windows launcher. GPL-3.0-only; upstream credits are retained.
package main

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"unicode/utf8"
)

//go:embed resources/source.zip
var sourceArchive []byte

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
	for _, required := range []string{"manage.py", "pyproject.toml", "poetry.lock", "scripts/native_windows.ps1", "scripts/native_runtime.py", "mobsf/StaticAnalyzer/migrations/0001_initial.py", "mobsf/StaticAnalyzer/migrations/__init__.py"} {
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
		"MOBSF_ANDROID_MODERN_DYNAMIC=0\nMOBSF_ANDROID_ALLOW_LOW_TARGET_INSTALL=0\nMOBSF_ANALYZER_IDENTIFIER=\n" +
		"MOBSF_CAPTURE_PROXY_PROVIDER=none\nMOBSF_CAPTURE_PROXY_URL=\nMOBSF_CAPTURE_PROXY_CA_FILE=\n"
	file, err := os.OpenFile(location, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	_, writeErr := io.WriteString(file, content)
	return location, errors.Join(writeErr, file.Close())
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
	fmt.Println("Embedded source and local configuration self-test passed; no runtime was installed or started.")
	return nil
}

// The command is fixed trusted code. Runtime values travel through environment
// variables so spaces, quotes and ampersands cannot become PowerShell syntax.
// No persistent execution policy or machine configuration is changed.
func nativeArgs() []string {
	return []string{"-NoLogo", "-NoProfile", "-Command",
		"& ([scriptblock]::Create([IO.File]::ReadAllText($env:MOBSF_DESKTOP_BOOTSTRAP))) " +
			"-SourceRoot $env:MOBSF_DESKTOP_SOURCE_ROOT -DataRoot $env:MOBSF_DESKTOP_DATA_ROOT -Action $env:MOBSF_DESKTOP_ACTION"}
}

func nativeEnv(root, home, action string) []string {
	values := map[string]string{
		"MOBSF_DESKTOP_BOOTSTRAP":   filepath.Join(root, "scripts", "native_windows.ps1"),
		"MOBSF_DESKTOP_SOURCE_ROOT": root,
		"MOBSF_DESKTOP_DATA_ROOT":   home,
		"MOBSF_DESKTOP_ACTION":      action,
	}
	result := []string{}
	for _, entry := range os.Environ() {
		name := strings.ToUpper(strings.SplitN(entry, "=", 2)[0])
		if _, replaced := values[name]; !replaced {
			result = append(result, entry)
		}
	}
	for name, value := range values {
		result = append(result, name+"="+value)
	}
	return result
}

func run(args []string) error {
	action := "start"
	if len(args) > 1 {
		return errors.New("usage: MobSF-BugBounty.exe [install|start|doctor|android-check|proxy-check|credentials|password|self-test]")
	}
	if len(args) == 1 {
		action = args[0]
	}
	if action == "self-test" {
		return selfTest()
	}
	switch action {
	case "install", "start", "doctor", "android-check", "proxy-check", "credentials", "password":
	case "stop":
		return errors.New("native MobSF runs in its own console; press Ctrl+C there to stop it and preserve data")
	case "logs":
		return errors.New("native server logs appear in its running console; analysis logs are in %APPDATA%\\MobSF-BugBounty\\data")
	default:
		return errors.New("unknown command; use install, start, doctor, android-check, proxy-check, credentials, password or self-test")
	}
	fmt.Println("MobSF Bug Bounty Edition — native Windows, source SHA256:", sourceID())
	base, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	home := filepath.Join(base, "MobSF-BugBounty")
	if action == "credentials" {
		data, err := os.ReadFile(filepath.Join(home, "desktop.env"))
		if err != nil {
			return errors.New("no initial credentials found; run install first")
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
	if runtime.GOOS != "windows" {
		return errors.New("native desktop runtime requires Windows x64; use the source installation on Linux")
	}
	root, err := ensureSource(home)
	if err != nil {
		return err
	}
	if _, err := ensureConfig(home); err != nil {
		return err
	}
	// System PowerShell is selected by absolute path, never from extracted source.
	powershell := filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	command := exec.Command(powershell, nativeArgs()...)
	command.Env = nativeEnv(root, home, action)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	return command.Run()
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
