package main

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func makeArchive(t *testing.T, names []string, symlink bool) []byte {
	t.Helper()
	var data bytes.Buffer
	writer := zip.NewWriter(&data)
	for _, name := range names {
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		if symlink {
			header.SetMode(os.ModeSymlink | 0777)
		} else {
			header.SetMode(0644)
		}
		file, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte("synthetic content")); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return data.Bytes()
}

func TestUnsafeArchivePaths(t *testing.T) {
	for _, name := range []string{"../escape", "/root/file", `C:\escape`, `folder\..\escape`, "folder/../escape", "file:stream", "CON.txt", "folder/aux", "name. ", "foo//bar"} {
		t.Run(name, func(t *testing.T) {
			if safeEntry(name) {
				t.Fatalf("accepted unsafe Windows archive name %q", name)
			}
			if err := extractArchive(makeArchive(t, []string{name}, false), t.TempDir()); err == nil {
				t.Fatal("accepted unsafe archive")
			}
		})
	}
}

func TestSymlinksAndDuplicateCaseRejected(t *testing.T) {
	if err := extractArchive(makeArchive(t, []string{"link"}, true), t.TempDir()); err == nil {
		t.Fatal("accepted source symlink")
	}
	if err := extractArchive(makeArchive(t, []string{"file.txt", "FILE.txt"}, false), t.TempDir()); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatal("accepted case-insensitive duplicate entries")
	}
}

func TestRequiredSourceFiles(t *testing.T) {
	if err := extractArchive(makeArchive(t, []string{"README.md"}, false), t.TempDir()); err == nil {
		t.Fatal("accepted archive without application source")
	}
}

func TestBundledSourceExtractionAndReuse(t *testing.T) {
	home := t.TempDir()
	root, err := ensureSource(home)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "mobsf", "BugBounty", "models.py")); err != nil {
		t.Fatal("Bug Bounty source is not bundled:", err)
	}
	if _, err := os.Stat(filepath.Join(root, "LICENSES", "IP2LOCATION LITE DATA.txt")); err != nil {
		t.Fatal("third-party license is not bundled:", err)
	}
	again, err := ensureSource(home)
	if err != nil || again != root {
		t.Fatal("source version changed on repeat startup", err)
	}
}

func TestCredentialsAreRandomAndPreserved(t *testing.T) {
	home := t.TempDir()
	location, err := ensureConfig(home)
	if err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(location)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(first), "MOBSF_ANDROID_MODERN_DYNAMIC=0") {
		t.Fatal("modern runtime was silently enabled")
	}
	if _, err := ensureConfig(home); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(location)
	if !bytes.Equal(first, second) {
		t.Fatal("existing initial credentials were changed")
	}
	other, err := ensureConfig(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	third, _ := os.ReadFile(other)
	if bytes.Equal(first, third) {
		t.Fatal("fresh installations reused a default password")
	}
}

func TestArgumentBoundariesAndDataPreservation(t *testing.T) {
	root := `C:\Users\Researcher Name\MobSF & tools`
	config := filepath.Join(root, "desktop.env")
	args := composeArgs(root, config, "stop")
	if args[4] != root || args[6] != config || args[len(args)-1] != "stop" {
		t.Fatal("Docker argument boundaries were not preserved", args)
	}
	for _, arg := range args {
		if arg == "down" || arg == "-v" || strings.HasPrefix(arg, "MOBSF_ADMIN_PASSWORD=") {
			t.Fatal("destructive or secret command argument", arg)
		}
	}
}

func TestUnknownCommandFailsBeforeDependencies(t *testing.T) {
	if err := run([]string{"delete-everything"}); err == nil {
		t.Fatal("unknown action accepted")
	}
}

func TestEmbeddedSelfTest(t *testing.T) {
	if err := selfTest(); err != nil {
		t.Fatal(err)
	}
}
