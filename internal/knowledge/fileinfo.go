package knowledge

import (
	"io/fs"
	"os"
)

func unsafeFileInfo(info fs.FileInfo) bool {
	if info == nil {
		return true
	}
	mode := info.Mode()
	return mode&os.ModeSymlink != 0 || mode&(os.ModeDevice|os.ModeNamedPipe|os.ModeSocket|os.ModeCharDevice|os.ModeIrregular) != 0 || platformUnsafeFileInfo(info)
}
