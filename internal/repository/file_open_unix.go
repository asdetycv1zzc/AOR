//go:build !windows

package repository

import (
	"io/fs"
	"os"
	"syscall"
)

func openFileNoFollow(name string) (*os.File, error) {
	descriptor, err := syscall.Open(name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(descriptor), name), nil
}

func openReadFileNoFollow(name string) (*os.File, error) {
	descriptor, err := syscall.Open(name, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(descriptor), name), nil
}

func unsafeOpenedFile(file *os.File) bool {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return true
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return !ok || stat.Nlink != 1
}

func unsafePathInfo(info fs.FileInfo) bool {
	return info == nil || info.Mode()&os.ModeSymlink != 0
}
