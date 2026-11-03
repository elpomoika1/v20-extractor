//go:build windows

package types

import "golang.org/x/sys/windows"

type DEBUG_EVENT_UNION [160]byte

type DEBUG_EVENT struct {
	DwDebugEventCode uint32
	DwProcessId      uint32
	DwThreadId       uint32
	_                [4]byte
	U                DEBUG_EVENT_UNION
}

type AMD64CONTEXT struct {
	P1Home uint64
	P2Home uint64
	P3Home uint64
	P4Home uint64
	P5Home uint64
	P6Home uint64

	ContextFlags uint32
	MxCsr        uint32

	SegCs  uint16
	SegDs  uint16
	SegEs  uint16
	SegFs  uint16
	SegGs  uint16
	SegSs  uint16
	EFlags uint32

	Dr0 uint64
	Dr1 uint64
	Dr2 uint64
	Dr3 uint64
	Dr6 uint64
	Dr7 uint64

	Rax uint64
	Rcx uint64
	Rdx uint64
	Rbx uint64
	Rsp uint64
	Rbp uint64
	Rsi uint64
	Rdi uint64
	R8  uint64
	R9  uint64
	R10 uint64
	R11 uint64
	R12 uint64
	R13 uint64
	R14 uint64
	R15 uint64

	Rip uint64

	_ [512]byte

	_             [26 * 16]byte
	VectorControl uint64

	DebugControl         uint64
	LastBranchToRip      uint64
	LastBranchFromRip    uint64
	LastExceptionToRip   uint64
	LastExceptionFromRip uint64
}

type EXCEPTION_DEBUG_INFO struct {
	ExeptionRecord EXCEPTION_RECORD
	FirstChance    uint32 // if already have encountered the exception, if != 0 -> for the first time
	_              [4]byte
}

const EXCEPTION_MAXIMUM_PARAMETERS = 15

type EXCEPTION_RECORD struct {
	ExceptionCode        uint32
	ExceptionFlags       uint32
	ExceptionRecord      *EXCEPTION_RECORD
	ExceptionAddress     uintptr
	NumberParameters     uint32
	_                    [4]byte
	ExceptionInformation [EXCEPTION_MAXIMUM_PARAMETERS]uintptr
}

type CREATE_THREAD_DEBUG_INFO struct {
	HThread           windows.Handle
	LpThreadLocalBase uintptr
	LpStartAddress    uintptr
}

type LOAD_DLL_DEBUG_INFO struct {
	HFile                 uintptr
	LpBaseOfDll           uintptr
	DwDebugInfoFileOffset uint32
	NDebugInfoSize        uint32
	LpImageName           uintptr
	FUnicode              uint16
	_                     [6]byte
}
