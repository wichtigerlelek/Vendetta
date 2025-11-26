# Vendetta
**Threadless Phantom DLL Injector**

Vendetta is a proof-of-concept User-Mode Proxy-Injector that utilizes **Transacted Section Hollowing** (based on Forrest Orr's [Phantom DLL](https://github.com/forrest-orr/phantom-dll-hollower-poc) technique) combined with syscalls to achieve stealth-optimized injection.

Unlike standard injectors, Vendetta does **not need a Handle** to the target, avoids creating new threads and avoids `MEM_PRIVATE` allocations for the payload. It uses `NtQueueApcThreadEx` for threadless execution and calls `LdrpInsertDataTableEntry` to manually link the module into the target's PEB, Red-Black Tree, and Hash Table.

## Usage
### Prerequisites
- Administrator privileges required for VendettaStager.exe
- [DebugView](https://learn.microsoft.com/en-us/sysinternals/downloads/debugview) (optional, for viewing debug output)
- Vendetta only works on x64 because of the Syswhispers but you can modify it for x86 if you need it

1. **Clone the repository**
```bash
git clone https://github.com/wichtigerlelek/Vendetta.git
```

2. **Configure the target process**
   - Navigate to `$(SolutionDir)Shared/config.h`
   - Modify the target process name:
```cpp
const std::wstring TARGET = L"dummy.exe"; // Change to your target process
```

3. **Configure the phantom DLL (Optional)**
   - In the same `config.h` file, you can specify which legitimate DLL to use as the phantom:
```cpp
const std::wstring BENIGN_DLL = LR"(C:\Windows\System32\xpsservices.dll)";
```

4. **Build and run**
   - Build the project
   - Run `VendettaStager.exe` **as Administrator**

5. **Verify execution**
   
   If successful, you should see output similar to:
```
   [13:27:03.2370532]  [INFO] Target: dummy.exe
   [13:27:03.2432829]  [INFO] Vendetta Core: C:\Path\To\VendettaCore.dll
   [13:27:03.2502683]  [INFO] Resizing SystemInformation buffer to 431kb
   [13:27:03.2615058]  [INFO] Resizing SystemInformation buffer to 4524kb
   [13:27:03.2668809]  [INFO] System (4) holds a handle to dummy.exe with Access: 0x1fffff
   [13:27:03.2669883]  [INFO] csrss.exe (1624) holds a handle to dummy.exe with Access: 0x1fffff
   [13:27:03.2670772]  [INFO] svchost.exe (3152) holds a handle to dummy.exe with Access: 0x1478
```

6. **Monitor debug output (Optional)**
   - Open DebugView as Administrator
   - Enable **Capture → Capture Global Win32**
   - View real-time debug output from VendettaCore.dll

7. **Execute injection**
   - Enter the PID of the process you want to use as a proxy
   - The injection process will begin automatically

### Troubleshooting
- Ensure VendettaStager.exe is run with Administrator privileges because it needs `SeDebugPrivilege`
- Verify the target process name matches exactly (case-sensitive)
- Check that the phantom DLL path exists and is accessible

## Information about the Proxy-Injection
* Vendetta now only opens a `PROCESS_QUERY_LIMITED_INFORMATION` Handle to the target which is minimum access and less suspicious than `PROCESS_VM_WRITE | PROCESS_VM_OPERATION`. You can make it work completely handle-less but you need to use **System Informer** or a simlar tool to look up which process currently running has a `PROCESS_VM_WRITE | PROCESS_VM_OPERATION` Handle open to the target, which is usually one or more of the `svchost.exe` processes.

## What it doesn't
* **It does not** evade moneta, pe-sieve, ... because it will always trigger a Disk-Memory-Mismatch since it either deletes the file so that these tools can not find it anymore or it leaves it on disk but than they can compare the .text section on disk to the .text section in the memory. **Can this be changed / improved?** Yes and no. Patching the .reloc section and marking it as RX should fix this but that is very suspicious / unexpected that the .reloc section is exercutable and i think it would only make it worse. Another way to fix this would be to overwrite the .text section on the disk but than it would fail because the disk image is not signed anymore and this would just be a shitty loadlibrary injector.
* **It does not** resolve imports and relocations so it is only working for shellcode not for whole dll files.

## Key Features
* **Transacted Hollowing:** Maps the payload as `MEM_IMAGE` backed by a transaction, bypassing `MEM_PRIVATE` execution scans.
* **Threadless Execution:** Uses `NtQueueApcThreadEx` with `QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC` to hijack existing threads without triggering kernel callbacks like `PsSetCreateThreadNotifyRoutine`.
* **Proxy Injection:** Uses a third process to avoid creating a new handle. Reuses an existing one.
* **Native-Linking:** Locates and calls `ntdll!LdrpInsertDataTableEntry` to register the module in the PEB (`PEB_LDR_DATA`), `LdrpHashTable`, and `LdrpModuleBaseAddressIndex`.

## Roadmap
- [ ] Add Global Event to perfectly synchronize Injection and Unloading of Vendetta Core in the Proxy.
- [ ] Memory-Only Loading: Support loading DLLs directly from memory buffers (avoiding disk I/O entirely).

## Disclaimer
This project is for educational and research purposes only. I am not responsible for any misuse of this software.
