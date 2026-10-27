package cfwarp

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomicReplacesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "reg.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A hard link keeps the old inode visible: an in-place write would change
	// it, a rename leaves it alone.
	oldLink := filepath.Join(dir, "old-link")
	if err := os.Link(path, oldLink); err != nil {
		t.Fatal(err)
	}

	if err := writeFileAtomic(path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != "new" {
		t.Errorf("content = %q, want new", got)
	}
	if got, _ := os.ReadFile(oldLink); string(got) != "old" {
		t.Errorf("old inode content = %q: file was written in place", got)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", info.Mode().Perm())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 2 {
		t.Errorf("dir holds %d entries, want no leftover temp file", len(entries))
	}
}

func TestWriteFileAtomicFailureKeepsOldFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "reg.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })

	if err := writeFileAtomic(path, []byte("new")); err == nil {
		t.Fatal("write into a read-only directory succeeded")
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, []byte("old")) {
		t.Errorf("content = %q, want the old file", got)
	}
}
