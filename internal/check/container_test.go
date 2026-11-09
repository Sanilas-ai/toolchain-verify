package check

import (
	"errors"
	"os"
	"testing"
	"time"
)

type memFI struct{}

func (memFI) Name() string       { return "x" }
func (memFI) Size() int64        { return 0 }
func (memFI) Mode() os.FileMode  { return 0 }
func (memFI) ModTime() time.Time { return time.Time{} }
func (memFI) IsDir() bool        { return false }
func (memFI) Sys() any           { return nil }

func TestDetectContainerIgnoresEnvAlone(t *testing.T) {
	// detectContainer never consults getenv — $container alone must not count.
	t.Setenv("container", "docker")
	stat := func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	read := func(string) ([]byte, error) { return nil, os.ErrNotExist }
	if detectContainer(stat, read) {
		t.Fatal("env-only / missing markers must not look like a container")
	}
}

func TestDetectContainerMarkerFile(t *testing.T) {
	stat := func(path string) (os.FileInfo, error) {
		if path == "/.dockerenv" {
			return memFI{}, nil
		}
		return nil, os.ErrNotExist
	}
	read := func(string) ([]byte, error) { return nil, errors.New("no") }
	if !detectContainer(stat, read) {
		t.Fatal("/.dockerenv must count")
	}
}

func TestDetectContainerCgroup(t *testing.T) {
	stat := func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	read := func(path string) ([]byte, error) {
		if path == "/proc/1/cgroup" {
			return []byte("12:memory:/docker/abc\n"), nil
		}
		return nil, os.ErrNotExist
	}
	if !detectContainer(stat, read) {
		t.Fatal("docker cgroup must count")
	}
}

func TestDetectContainerOverlayRoot(t *testing.T) {
	stat := func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	read := func(path string) ([]byte, error) {
		if path == "/proc/1/cgroup" {
			return []byte("0::/\n"), nil // cgroup v2 host-like
		}
		if path == "/proc/self/mountinfo" {
			return []byte("1 0 0:0 / / rw,relatime - overlay overlay rw\n"), nil
		}
		return nil, os.ErrNotExist
	}
	if !detectContainer(stat, read) {
		t.Fatal("overlay on / must count when cgroup is inconclusive")
	}
}

func TestDetectContainerHostMountinfo(t *testing.T) {
	stat := func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	read := func(path string) ([]byte, error) {
		if path == "/proc/1/cgroup" {
			return []byte("0::/\n"), nil
		}
		if path == "/proc/self/mountinfo" {
			return []byte("1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n"), nil
		}
		return nil, os.ErrNotExist
	}
	if detectContainer(stat, read) {
		t.Fatal("ext4 root must not look like a container")
	}
}
