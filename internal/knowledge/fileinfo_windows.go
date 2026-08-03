//go:build windows

package knowledge

import (
	"io/fs"
	"syscall"
)

func platformUnsafeFileInfo(info fs.FileInfo) bool {
	data, ok := info.Sys().(*syscall.Win32FileAttributeData)
	if !ok {
		return true
	}
	const fileAttributeReparsePoint = 0x400
	return data.FileAttributes&fileAttributeReparsePoint != 0
}
