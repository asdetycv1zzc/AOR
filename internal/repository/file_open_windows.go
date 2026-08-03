//go:build windows

package repository

import (
	"io/fs"
	"os"
	"syscall"
)

func openFileNoFollow(name string) (*os.File, error) {
	return os.OpenFile(name, os.O_WRONLY|os.O_CREATE, 0o600)
}

func openReadFileNoFollow(name string) (*os.File, error) {
	return os.Open(name)
}

func hasMultipleLinks(info fs.FileInfo) bool {
	data, ok := info.Sys().(*syscall.Win32FileAttributeData)
	if !ok {
		return true
	}
	const fileAttributeReparsePoint = 0x400
	return data.FileAttributes&fileAttributeReparsePoint != 0
}
