package main

import (
	"crypto/rand"
	"errors"
	"os"
	"time"
)

// Logout retains non-secret installation metadata as an ignored archive. The
// platform operation must fail if the destination exists, even on Windows.
func archiveProfile(path string) error {
	for range 3 {
		archive := path + ".logged-out-" + time.Now().UTC().Format("20060102T150405.000000000Z") + "-" + rand.Text()
		err := renameWithoutReplace(path, archive)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return errors.New("local credentials were cleared but profile metadata could not be archived; check local file permissions")
		}
		return nil
	}
	return errors.New("could not choose an unused profile archive path")
}
