# Vendetta
**Advanced Threadless Phantom DLL Injector (Proxy version)**

This is the proxy version of vendetta. It injects itself into a third process to do the shellcode injection from there. It consists of a Stager (Injects the core into a third process) and the Core (Dll with the logic from the master-branch).

## Key Features
* **Proxy Injection:** Uses a third process to avoid creating a new handle. Reuses an existing one.

## Roadmap
- [ ] Proxy Injection: Convert the loader to a dll, inject into whitelisted processes with VM_WRITE | VM_READ handle.
- [ ] Memory-Only Loading: Support loading DLLs directly from memory buffers (avoiding disk I/O entirely).

## Disclaimer
This project is for educational and research purposes only. I am not responsible for any misuse of this software.
