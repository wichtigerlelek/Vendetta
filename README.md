# Vendetta
**Advanced Threadless Phantom DLL Injector**

Vendetta is a proof-of-concept User-Mode injector that utilizes **Transacted Section Hollowing** (based on Forrest Orr's [Phantom DLL](https://github.com/forrest-orr/phantom-dll-hollower-poc) technique) combined with syscalls to achieve stealth-optimized injection.

Unlike standard injectors, Vendetta avoids creating new threads and avoids `MEM_PRIVATE` allocations for the payload. It uses `NtQueueApcThreadEx` for threadless execution and calls `LdrpInsertDataTableEntry` to manually link the module into the target's PEB, Red-Black Tree, and Hash Table.

## Key Features
* **Transacted Hollowing:** Maps the payload as `MEM_IMAGE` backed by a transaction (Phantom DLL technique), bypassing `MEM_PRIVATE` execution scans.
* **Threadless Execution:** Uses `NtQueueApcThreadEx` with `QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC` to hijack existing threads without triggering kernel callbacks like `PsSetCreateThreadNotifyRoutine`.
* **Legit-Linking:** Locates and calls `ntdll!LdrpInsertDataTableEntry` to register the module in the PEB, `LdrpHashTable`, and `LdrpModuleBaseAddressIndex` to look as legit as possible to memory scanners.

## Usage

```console
____   ____                 .___      __    __
\   \ /   /____   ____    __| _/_____/  |__/  |______
 \   Y   // __ \ /    \  / __ |/ __ \   __\   __\__  \
  \     /\  ___/|   |  \/ /_/ \  ___/|  |  |  |  / __ \_
   \___/  \___  >___|  /\____ |\___  >__|  |__| (____  /
                                                     \/
        .------------------------------------.
        |Advanced Phantom DLL injector v1.0.0|
        |      Author: (wichtigerlelek)      |
        '------------------------------------'
Usage: vendetta.exe [TARGET] [OPTIONS] <PHANTOM_DLL_PATH>

Target (Choose one):
  -pid <id>          Target process by PID
  -proc <name>       Target process by Name (e.g., notepad.exe)

Options:
  -payload <path>    Path to the raw shellcode/PE-shellcode file
  -m <method>        Handle hijacking method: 'open_handle' (default) or 'hijack_handle'

Examples:
  vendetta.exe -pid 1234 -payload shellcode.bin C:\Windows\System32\xpsservices.dll
  vendetta.exe -proc notepad.exe -payload beacon.bin -m hijack_handle C:\Windows\System32\xpsservices.dll
```

## Roadmap
- [x] Phantom DLL PEB linking.
- [x] Handle Hijacking: Implement handle duplication to bypass permission checks.
- [ ] Proxy Injection: Convert the loader to a dll, inject into whitelisted processes with VM_WRITE | VM_READ handle.
- [ ] Memory-Only Loading: Support loading DLLs directly from memory buffers (avoiding disk I/O entirely).
- [ ] Header Stomping or changing it with ntdll header to confuse dumpers (optional experiment).
- [ ] Call Stack Spoofing (optional).

## Disclaimer
This project is for educational and research purposes only. I am not responsible for any misuse of this software.
