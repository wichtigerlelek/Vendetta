# Vendetta
**Advanced Threadless Phantom DLL Injector (Proxy version)**

This is the proxy version of vendetta. It injects itself into a third process to do the shellcode injection from there. It consists of a Stager (Injects the core into a third process) and the Core (Dll with the logic from the master-branch).

## Usage
### Prerequisites
- Administrator privileges required for VendettaStager.exe
- [DebugView](https://learn.microsoft.com/en-us/sysinternals/downloads/debugview) (optional, for viewing debug output)

1. **Clone the repository**
```bash
   git clone -b proxy-injection https://github.com/wichtigerlelek/Vendetta.git
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

## Key Features
* **Proxy Injection:** Uses a third process to avoid creating a new handle. Reuses an existing one.

## Roadmap
- [ ] Memory-Only Loading: Support loading DLLs directly from memory buffers (avoiding disk I/O entirely).

## Disclaimer
This project is for educational and research purposes only. I am not responsible for any misuse of this software.
