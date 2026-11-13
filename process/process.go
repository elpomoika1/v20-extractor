//go:build windows

package process

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TerminateBrowsers(procs []string) error {
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(snapshot)

	err = windows.Process32First(snapshot, &entry)
	for err == nil {
		name := windows.UTF16ToString(entry.ExeFile[:])
		for _, p := range procs {
			if strings.EqualFold(name, p) {
				hProcess, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, entry.ProcessID)
				if err != nil {
					fmt.Println("hprocess open fail")
					err = windows.Process32Next(snapshot, &entry)
					continue
				}

				err = windows.TerminateProcess(hProcess, 0)
				if err != nil {
					fmt.Printf("terminate fail: %v\n", err)
				}
				windows.CloseHandle(hProcess)
			}
		}
		err = windows.Process32Next(snapshot, &entry)
	}
	return nil
}
