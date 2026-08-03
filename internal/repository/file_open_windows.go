//go:build windows

package repository

import (
	"io/fs"
	"os"
	"syscall"
)

const (
	fileAttributeReparsePoint = 0x400
	fileFlagOpenReparsePoint  = 0x00200000
)

func openFileNoFollow(name string) (*os.File, error) {
	return openWindowsFile(name, syscall.GENERIC_WRITE, syscall.OPEN_ALWAYS)
}

func openReadFileNoFollow(name string) (*os.File, error) {
	return openWindowsFile(name, syscall.GENERIC_READ, syscall.OPEN_EXISTING)
}

func openWindowsFile(name string, access uint32, disposition uint32) (*os.File, error) {
	path, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	handle, err := syscall.CreateFile(path, access, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, disposition, syscall.FILE_ATTRIBUTE_NORMAL|fileFlagOpenReparsePoint, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), name), nil
}

func unsafeOpenedFile(file *os.File) bool {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || unsafePathInfo(info) {
		return true
	}
	var handleInfo syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(syscall.Handle(file.Fd()), &handleInfo); err != nil {
		return true
	}
	return handleInfo.FileAttributes&fileAttributeReparsePoint != 0 || handleInfo.NumberOfLinks != 1
}

func unsafePathInfo(info fs.FileInfo) bool {
	if info == nil || info.Mode()&os.ModeSymlink != 0 {
		return true
	}
	data, ok := info.Sys().(*syscall.Win32FileAttributeData)
	return !ok || data.FileAttributes&fileAttributeReparsePoint != 0
}
