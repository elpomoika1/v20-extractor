# v20 Master Key Extractor PoC

POC for recovering the Chrome v20 App-Bound Encryption master key using the hardware breakpoint technique

## Disclaimer

This project is provided strictly for educational and security research purposes only. It is intended to help security researchers, malware analysts, and defenders understand how App-Bound Encryption can be bypassed in memory by advanced infostealers, so that detection logic, mitigations, and forensic tooling can be improved.

The author does not condone, support, or take responsibility for any use of this code for unauthorized access, data theft, or any other illegal activity. Running this code against systems you do not own or do not have explicit written permission to test is illegal in most jurisdictions and may violate computer fraud and abuse laws.

By using this repository you agree that you are solely responsible for your actions and that the author bears no liability for any damage, legal consequences, or misuse resulting from the code or information provided here.

If you are a defender or researcher and wish to report a related issue or discuss mitigation, please open an issue in this repository.

## Overview

The program launches a suspended Chrome process, attaches as a debugger, locates the `OSCrypt.AppBoundProvider.Decrypt.ResultCode` string inside `chrome.dll`, scans `.text` for the referencing LEA instruction, and places a hardware execution breakpoint (`DR0`) on that address across all threads. When the instruction is executed, the decrypted v20 master key is read from the `R15` register context.

## Technique

- Process creation with `CREATE_SUSPENDED` and `SW_HIDE`
- Debugger attach via `DebugActiveProcess`
- PE parsing from process memory to locate `.rdata` and `.text`
- Signature scan for `OSCrypt.AppBoundProvider.Decrypt.ResultCode` and its RIP-relative LEA xref
- Hardware breakpoint via debug registers (`DR0`/`DR7`)
- Thread enumeration with `NtGetNextThread`
- Context capture with `GetThreadContext` / `SetThreadContext`

## Future:

- x86 support
- add msedge support

## License -> MIT
