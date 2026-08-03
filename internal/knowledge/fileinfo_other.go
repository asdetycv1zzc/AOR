//go:build !windows

package knowledge

import "io/fs"

func platformUnsafeFileInfo(fs.FileInfo) bool { return false }
