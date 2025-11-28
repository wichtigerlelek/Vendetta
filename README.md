# Vendetta
**Threadless and Handleless Proxy / Phantom DLL Injector**

Vendetta is a proof-of-concept User-Mode Proxy-Injector that hides itself in a trusted process and utilizes **Transacted Section Hollowing** (based on Forrest Orr's [Phantom DLL](https://github.com/forrest-orr/phantom-dll-hollower-poc) technique) combined with syscalls to achieve stealth-optimized injection. It works very well against Usermode Anti-Cheats as the injector is virtually invisible to them because ot the Proxy-Injection nature. 

Proxying is much more stealthy than injecting from the injector itself because if you proxy Discord for example, the AC trusts Discord because it injects its own overlay into games so it needs `PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_VM_OPERATION` access.

Unlike standard injectors, Vendetta does **not need a Handle** to the target, avoids creating new threads, and avoids `MEM_PRIVATE` allocations for the payload. It uses `NtQueueApcThreadEx` for threadless execution and calls `LdrpInsertDataTableEntry` to manually link the module into the target's PEB, Red-Black Tree, and Hash Table.

**PLEASE DO NOT TEST THIS AGAINST A KERNEL ANTICHEAT**

You can only really read memory from a Kernel-protected game if you proxy Discord for example, but it is very risky and there are better approaches for that.

### Virustotal Results
- Stager: https://www.virustotal.com/gui/file/9985e2b63ea740fb1c4b34e2c67bd8a2f685f6f38b5d230f7c84e72e1750eb0a?nocache=1
- Core (No Metasploit Shellcode): https://www.virustotal.com/gui/file/26280b6ec80598ec45d0e0ab20f16d4aa8dba12695f4368dec2d3e50a76f3e86?nocache=1

## Key Features
* **Proxy Injection:** Uses a trusted process as a proxy.
* **Transacted Hollowing:** Maps the payload as `MEM_IMAGE` backed by a transaction, bypassing `MEM_PRIVATE` execution scans.
* **Threadless Execution:** Uses `NtQueueApcThreadEx` with `QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC`, bypassing kernel callbacks like `PsSetCreateThreadNotifyRoutine`.
* **Native-Linking:** Locates and calls `ntdll!LdrpInsertDataTableEntry` to register the module in the PEB (`PEB_LDR_DATA`), `LdrpHashTable`, and `LdrpModuleBaseAddressIndex`.

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

4. **Add Custom shellcode (Optional)**
   - Change the `static unsigned char buf[320]` inside the `dllmain.cpp` to your desired shellcode
   - The included shellcode is a x64 Messagebox generated with Metasploit

5. **Build and run**
   - Build the project
   - Run `VendettaStager.exe` **as Administrator**

6. **Verify execution**
   
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

7. **Monitor debug output (Optional)**
   - Open DebugView as Administrator
   - Enable **Capture → Capture Global Win32**
   
   If the injection was successful, you should see output similar to:
```
00000001	0.00000000	[3148] [15:26:42.0672213] [INFO]  Found target PID: 8080	
00000002	0.00111760	[3148] [15:26:42.0684219] [INFO]  Resizing SystemInformation buffer to 4422kb	
00000003	0.41092640	[3148] [15:26:42.4781609] [INFO]  Found internal handle: 0x1a8 (Access: 1478)	
00000004	0.41115350	[3148] [15:26:42.4784655] [WARN]  Copying C:\Windows\System32\xpsservices.dll to TEMP folder	
00000005	0.41706941	[3148] [15:26:42.4843646] [INFO]  Reading Legitimate DLL: C:\WINDOWS\TEMP\xpsservices.dll	
00000006	0.44701001	[3148] [15:26:42.5142751] [INFO]  Transaction created.	
00000007	0.46979779	[3148] [15:26:42.5370645] [INFO]  Patching .text section in memory...	
00000008	0.46983531	[3148] [15:26:42.5371462] [INFO]  Writing patched PE content to transaction...	
00000009	0.48787650	[3148] [15:26:42.5551632] [INFO]  Section created and mapped to the target process.	
00000010	1.01908624	[3148] [15:26:43.0863445] [INFO]  Transaction rolled back successfully.	
00000011	1.01912534	[3148] [15:26:43.0864348] [INFO]  Mapped Base Address: 0x7ffaf3430000	
00000012	1.01915765	[3148] [15:26:43.0864744] [INFO]  Linking phantom dll to PEB...	
00000013	1.01918662	[3148] [15:26:43.0865050] [INFO]  Looking for LdrpInsertDataTableEntry, pattern: 40 53 48 83 EC ? F6 41 ? ? 48 8B D9 75	
00000014	1.02028728	[3148] [15:26:43.0875914] [INFO]  Pattern found at address: 0x7ffbd70e64b0	
00000015	1.02043033	[3148] [15:26:43.0877436] [INFO]  Memory allocated and LDR entry written.	
00000016	1.04362738	[3148] [15:26:43.1109310] [INFO]  Queueing Apc. Executing 0x7ffbd70e64b0, RCX: 0x239c2320000, RDX: 0x0, R8: 0x0. TID = 14496.	
00000017	1.04367030	[3148] [15:26:43.1109841] [INFO]  Linked successfully via direct LdrpInsertDataTableEntry call.	
00000018	1.06541276	[3148] [15:26:43.1327225] [INFO]  Queueing Apc. Executing 0x7ffaf3431000, RCX: 0x0, RDX: 0x0, R8: 0x0. TID = 14496.	
00000019	1.06555283	[3148] [15:26:43.1328701] [INFO]  Injection succeeded	
00000020	1.06558251	[3148] [15:26:43.1329020] [WARN]  Deleting C:\WINDOWS\TEMP\xpsservices.dll	
```

8. **Execute injection**
   - Enter the PID of the process you want to use as a proxy or use a preset from the config
   - The injection process will begin automatically

### Troubleshooting
- Ensure VendettaStager.exe is run with Administrator privileges because it needs `SeDebugPrivilege`
- Verify the target process name matches exactly (case-sensitive)
- Check that the phantom DLL path exists and is accessible
- If you see the Injection succeeded message but no messagebox pop up, the main thread of the target is most likely sleeping 

## What it doesn't
* **It does not** evade moneta, pe-sieve, ... because it will always trigger a Disk-Memory-Mismatch since it either deletes the file so that these tools can not find it anymore or it leaves it on disk but than they can compare the .text section on disk to the .text section in the memory. **Can this be changed / improved?** Yes and no. Patching the .reloc section and marking it as RX should fix this but that is very suspicious / unexpected that the .reloc section is exercutable and i think it would only make it worse. Another way to fix this would be to overwrite the .text section on the disk but than it would fail because the disk image is not signed anymore and this would just be a shitty loadlibrary injector.
* **It does not** resolve imports and relocations so it is only working for shellcode not for whole dll files.

## Roadmap
- [ ] Add Manual-Mapping
- [ ] Add Global Event to perfectly synchronize Injection and Unloading of Vendetta Core in the Proxy.
- [ ] Memory-Only Loading: Support loading DLLs directly from memory buffers (avoiding disk I/O entirely).

## Disclaimer
This project is for educational and research purposes only. I am not responsible for any misuse of this software.
