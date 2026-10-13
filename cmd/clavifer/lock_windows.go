//go:build windows

package main

import (
	"crypto/sha256"
	"fmt"
	"golang.org/x/sys/windows"
	"runtime"
)

func tokenLock(key string) (func(), error) {
	runtime.LockOSThread()
	name, err := windows.UTF16PtrFromString(fmt.Sprintf("Local\\clavifer-%x", sha256.Sum256([]byte(key))))
	if err != nil {
		runtime.UnlockOSThread()
		return nil, err
	}
	handle, err := windows.CreateMutex(nil, false, name)
	if err != nil && err != windows.ERROR_ALREADY_EXISTS {
		runtime.UnlockOSThread()
		return nil, err
	}
	result, err := windows.WaitForSingleObject(handle, 35000)
	if err != nil || (result != windows.WAIT_OBJECT_0 && result != windows.WAIT_ABANDONED) {
		windows.CloseHandle(handle)
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("cannot acquire credential refresh lock")
	}
	return func() { windows.ReleaseMutex(handle); windows.CloseHandle(handle); runtime.UnlockOSThread() }, nil
}
