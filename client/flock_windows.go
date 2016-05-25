// Based on https://github.com/boltdb/bolt/blob/master/bolt_windows.go
// Copyright boltdb authors

package client

import (
	"errors"
	"os"
	"syscall"
	"time"
	"unsafe"
)

// LockFileEx code derived from golang build filemutex_windows.go @ v1.5.1
var (
	modkernel32      = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx   = modkernel32.NewProc("LockFileEx")
	procUnlockFileEx = modkernel32.NewProc("UnlockFileEx")

	// ErrTimeout is returned when we cannot obtain an exclusive lock
	// on the key file.
	ErrTimeout = errors.New("timeout")
)

const (
	lockExt = ".lock"

	// see https://msdn.microsoft.com/en-us/library/windows/desktop/aa365203(v=vs.85).aspx
	flagLockExclusive       = 2
	flagLockFailImmediately = 1

	// see https://msdn.microsoft.com/en-us/library/windows/desktop/ms681382(v=vs.85).aspx
	errLockViolation syscall.Errno = 0x21
)

func lockFileEx(h syscall.Handle, flags, reserved, locklow, lockhigh uint32, ol *syscall.Overlapped) (err error) {
	r, _, err := procLockFileEx.Call(uintptr(h), uintptr(flags), uintptr(reserved), uintptr(locklow), uintptr(lockhigh), uintptr(unsafe.Pointer(ol)))
	if r == 0 {
		return err
	}
	return nil
}

func unlockFileEx(h syscall.Handle, reserved, locklow, lockhigh uint32, ol *syscall.Overlapped) (err error) {
	r, _, err := procUnlockFileEx.Call(uintptr(h), uintptr(reserved), uintptr(locklow), uintptr(lockhigh), uintptr(unsafe.Pointer(ol)), 0)
	if r == 0 {
		return err
	}
	return nil
}

type flock struct {
	lockfile *os.File
}

func newFlock() *flock {
	return &flock{&os.File{}}
}

// lock acquires an advisory lock on a file descriptor.
func (f *flock) lock(k *KeysFile, mode os.FileMode, exclusive bool, timeout time.Duration) error {
	// Create a separate lock file on windows because a process
	// cannot share an exclusive lock on the same file.
	file, err := os.OpenFile(k.fn+lockExt, os.O_CREATE, mode)
	if err != nil {
		return err
	}
	f.lockfile = file
	var t time.Time
	for {
		// If we're beyond our timeout then return an error.
		// This can only occur after we've attempted a lock once.
		if t.IsZero() {
			t = time.Now()
		} else if timeout > 0 && time.Since(t) > timeout {
			return ErrTimeout
		}

		var flag uint32 = flagLockFailImmediately
		if exclusive {
			flag |= flagLockExclusive
		}
		err = lockFileEx(syscall.Handle(f.lockfile.Fd()), flag, 0, 1, 0, &syscall.Overlapped{})
		if err == nil {
			return nil
		} else if err != errLockViolation {
			return err
		}

		// Wait for a bit and try again.
		time.Sleep(50 * time.Millisecond)
	}
}

// unlock releases an advisory lock on a file descriptor.
func (f *flock) unlock(k *KeysFile) error {
	err := unlockFileEx(syscall.Handle(f.lockfile.Fd()), 0, 1, 0, &syscall.Overlapped{})
	f.lockfile.Close()
	os.Remove(k.fn + lockExt)
	return err
}
