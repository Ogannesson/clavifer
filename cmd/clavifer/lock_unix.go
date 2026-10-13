//go:build linux || darwin

package main

import (
	"crypto/sha256"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"time"
)

func tokenLock(key string) (func(), error) {
	dir, err := userConfigDir()
	if err != nil {
		return nil, err
	}
	dir = filepath.Join(dir, "clavifer")
	if err = os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, fmt.Sprintf("refresh-%x.lock", sha256.Sum256([]byte(key)))), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(35 * time.Second)
	for {
		err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, fmt.Errorf("cannot acquire credential refresh lock")
		}
		time.Sleep(100 * time.Millisecond)
	}
	return func() { unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, nil
}
