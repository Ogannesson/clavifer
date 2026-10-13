//go:build darwin

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

func renameWithoutReplace(from, to string) error {
	if err := unix.RenamexNp(from, to, unix.RENAME_EXCL); err != nil {
		return &os.LinkError{Op: "rename", Old: from, New: to, Err: err}
	}
	return nil
}
