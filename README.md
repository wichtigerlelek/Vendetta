# Vendetta
**Advanced Threadless Phantom DLL Injector**

Vendetta is a proof-of-concept User-Mode injector that utilizes **Transacted Section Hollowing** ("Phantom DLL") combined with syscalls to achieve stealth-optimized injection.

Unlike standard injectors, Vendetta avoids creating new threads and avoids `MEM_PRIVATE` allocations for the payload. It leverages **Special User APCs** for threadless execution and calls `LdrpInsertDataTableEntry` to manually link the module into the target's PEB, Red-Black Tree, and Hash Table.

## Key Features
* **Transacted Hollowing:** Maps the payload as `MEM_IMAGE` backed by a transaction (Phantom DLL technique), bypassing `MEM_PRIVATE` execution scans.
* **Threadless Execution:** Uses `NtQueueApcThreadEx` with `QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC` to hijack existing threads without triggering kernel callbacks like `PsSetCreateThreadNotifyRoutine`.
* **Stealth Linking:** Locates and calls `ntdll!LdrpInsertDataTableEntry` to register the module in the PEB, `LdrpHashTable`, and `LdrpModuleBaseAddressIndex` (RB-Tree).
* **Silent Load:** Modifies `LDR_DATA_TABLE_ENTRY` flags (`LDRP_DONT_CALL_FOR_THREADS`) to prevent race conditions and duplicate execution on thread creation.

## Usage

```console
# Target by Process ID
vendetta.exe -p <PID> <payload_path>

# Target by Process Name
vendetta.exe -n <process_name> <payload_path>
