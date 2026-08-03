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

func hasMultipleLinks(info fs.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return !ok || stat.Nlink != 1
}
