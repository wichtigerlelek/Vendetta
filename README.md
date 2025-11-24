# Vendetta
**Advanced Threadless Phantom DLL Injector**

Vendetta is a proof-of-concept User-Mode injector that utilizes **Transacted Section Hollowing** (based on Forrest Orr's [Phantom DLL](https://github.com/forrest-orr/phantom-dll-hollower-poc) technique) combined with syscalls to achieve stealth-optimized injection.

Unlike standard injectors, Vendetta avoids creating new threads and avoids `MEM_PRIVATE` allocations for the payload. It leverages **Special User APCs** for threadless execution and calls `LdrpInsertDataTableEntry` to manually link the module into the target's PEB, Red-Black Tree, and Hash Table.

## Key Features
* **Transacted Hollowing:** Maps the payload as `MEM_IMAGE` backed by a transaction (Phantom DLL technique), bypassing `MEM_PRIVATE` execution scans.
* **Threadless Execution:** Uses `NtQueueApcThreadEx` with `QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC` to hijack existing threads without triggering kernel callbacks like `PsSetCreateThreadNotifyRoutine`.
* **Stealth Linking:** Locates and calls `ntdll!LdrpInsertDataTableEntry` to register the module in the PEB, `LdrpHashTable`, and `LdrpModuleBaseAddressIndex` (RB-Tree).
* **Silent Load:** Modifies `LDR_DATA_TABLE_ENTRY` flags (`LDRP_DONT_CALL_FOR_THREADS`) to prevent race conditions and duplicate execution on thread creation.

## Usage

```console
# Target by Process ID
vendetta.exe -p <PID> <path to benign dll>
```

```console
# Target by Process Name
vendetta.exe -n <process exe name> <path to benign dll>
```

## Included Test Payloads
The repository includes two pre-compiled x64 payloads for testing purposes. Both execute a standard "Hello World" message box:
1. shellc_hello.bin: Standard Metasploit-generated shellcode.
2. buf.bin: A PE file converted to shellcode using Donut.

## Roadmap
- [x] Phantom DLL Linking: Successfully link transacted sections to the PEB (Lists, Hash Table, & RB-Tree).
- [ ] Handle Hijacking: Implement handle duplication to bypass permission checks.
- [ ] Proxy Injection: Convert the loader to shellcode, inject into discord or other whitelisted processes and writeprocessmemory from proxy
- [ ] Memory-Only Loading: Support loading DLLs directly from memory buffers (avoiding disk I/O entirely).
- [ ] Header Stomping or changing it with ntdll header (optional experiment).
- [ ] Call Stack Spoofing (optional).

## Disclaimer
This project is for educational and research purposes only. I am not responsible for any misuse of this software.
