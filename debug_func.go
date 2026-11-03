//go:build windows

package main

import (
	"deub/types"
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	STATUS_SUCCESS         uint32 = 0x00000000
	STATUS_NO_MORE_ENTRIES uint32 = 0x8000001A

	THREAD_GET_CONTEXT       uint32 = 0x0008
	THREAD_SET_CONTEXT       uint32 = 0x0010
	THREAD_SUSPEND_RESUME    uint32 = 0x0002
	THREAD_QUERY_INFORMATION uint32 = 0x0040

	invalidThreadCount = 0xFFFFFFFF
)

var (
	kernel32         = windows.NewLazyDLL("Kernel32.dll")
	procDebug        = kernel32.NewProc("DebugActiveProcess")
	waitForDebug     = kernel32.NewProc("WaitForDebugEvent")
	continueDebug    = kernel32.NewProc("ContinueDebugEvent")
	getThreadContext = kernel32.NewProc("GetThreadContext")
	setThreadContext = kernel32.NewProc("SetThreadContext")
	suspendThread    = kernel32.NewProc("SuspendThread")
	resumeThread     = kernel32.NewProc("ResumeThread")

	ntdll           = windows.NewLazyDLL("ntdll.dll")
	ntGetNextThread = ntdll.NewProc("NtGetNextThread")
)

func NtGetNextThread(hProcess, hThread windows.Handle) (windows.Handle, error) {
	var newThread windows.Handle

	desiredAccess := THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
		THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION

	r1, _, _ := ntGetNextThread.Call(
		uintptr(hProcess),
		uintptr(hThread),
		uintptr(desiredAccess),
		0,
		0,
		uintptr(unsafe.Pointer(&newThread)),
	)

	ntstatus := uint32(r1)
	switch ntstatus {
	case STATUS_SUCCESS:
		return newThread, nil
	case STATUS_NO_MORE_ENTRIES:
		return 0, nil
	default:
		return 0, fmt.Errorf("NtGetNextThread failed: NTSTATUS=0x%X", ntstatus)
	}
}

func SuspendThread(hThread windows.Handle) (uint32, error) {
	r1, _, err := suspendThread.Call(uintptr(hThread))
	ret := uint32(r1)
	if ret == invalidThreadCount {
		if err == windows.ERROR_SUCCESS {
			return 0, errors.New("SuspendThread failed")
		}
		return 0, err
	}
	return ret, nil
}

func ResumeThread(hThread windows.Handle) (uint32, error) {
	r1, _, err := resumeThread.Call(uintptr(hThread))
	ret := uint32(r1)
	if ret == invalidThreadCount {
		if err == windows.ERROR_SUCCESS {
			return 0, errors.New("ResumeThread failed")
		}
		return 0, err
	}
	return ret, nil
}

func GetThreadContext(hThread windows.Handle, lpContext *types.AMD64CONTEXT) (bool, error) {
	buf := make([]byte, unsafe.Sizeof(*lpContext)+15)
	ctx := (*types.AMD64CONTEXT)(unsafe.Pointer((uintptr(unsafe.Pointer(&buf[15]))) &^ 15))
	ctx.ContextFlags = lpContext.ContextFlags

	r1, _, err := getThreadContext.Call(uintptr(hThread), uintptr(unsafe.Pointer(ctx)))

	if r1 == 0 {
		if err == windows.ERROR_SUCCESS {
			return false, errors.New("GetThreadContext failed")
		}
		return false, err
	}
	*lpContext = *ctx

	return true, nil
}

func SetThreadContext(hThread windows.Handle, lpContext *types.AMD64CONTEXT) (bool, error) {
	buf := make([]byte, unsafe.Sizeof(*lpContext)+15)
	ctx := (*types.AMD64CONTEXT)(unsafe.Pointer((uintptr(unsafe.Pointer(&buf[15]))) &^ 15))
	*ctx = *lpContext

	r1, _, err := setThreadContext.Call(uintptr(hThread), uintptr(unsafe.Pointer(ctx)))
	if r1 == 0 {
		if err == windows.ERROR_SUCCESS {
			return false, errors.New("SetThreadContext failed")
		}
		return false, err
	}
	return true, nil
}

func ContinueDebugEvent(pid, tid, continueStatus uint32) (bool, error) {
	r1, _, err := continueDebug.Call(uintptr(pid), uintptr(tid), uintptr(continueStatus))
	if r1 == 0 {
		if err == windows.ERROR_SUCCESS {
			return false, errors.New("ContinueDebugEvent failed")
		}
		return false, err
	}
	return true, nil
}

func WaitForDebugEvent(debugLevel *types.DEBUG_EVENT, dwMillis uint32) (bool, error) {
	r1, _, err := waitForDebug.Call(uintptr(unsafe.Pointer(debugLevel)), uintptr(dwMillis))
	if r1 == 0 {
		return false, err
	}
	return true, nil
}

func DebugActiveProcess(pid uint32) error {
	r1, _, err := procDebug.Call(uintptr(pid))
	if r1 == 0 {
		if err == windows.ERROR_SUCCESS {
			return errors.New("DebugActiveProcess failed")
		}
		return err
	}
	return nil
}
