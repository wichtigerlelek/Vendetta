.code

EXTERN SW3_GetSyscallNumber: PROC

EXTERN SW3_GetSyscallAddress: PROC

Sw3NtCreateProcess PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0FBB81628h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 0FBB81628h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtCreateProcess ENDP

Sw3NtCreateThreadEx PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 080BACC6Eh        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 080BACC6Eh        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtCreateThreadEx ENDP

Sw3NtOpenProcess PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0F7AF0DC7h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 0F7AF0DC7h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtOpenProcess ENDP

Sw3NtOpenProcessToken PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 00B911F30h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 00B911F30h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtOpenProcessToken ENDP

Sw3NtTestAlert PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 022AF09F0h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 022AF09F0h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtTestAlert ENDP

Sw3NtOpenThread PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 06C4D32FEh        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 06C4D32FEh        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtOpenThread ENDP

Sw3NtSuspendProcess PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 021BACEA0h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 021BACEA0h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtSuspendProcess ENDP

Sw3NtSuspendThread PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 000D84271h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 000D84271h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtSuspendThread ENDP

Sw3NtResumeProcess PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0872D86A0h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 0872D86A0h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtResumeProcess ENDP

Sw3NtResumeThread PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 09630090Bh        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 09630090Bh        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtResumeThread ENDP

Sw3NtGetContextThread PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 000A04601h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 000A04601h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtGetContextThread ENDP

Sw3NtSetContextThread PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 024BF2601h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 024BF2601h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtSetContextThread ENDP

Sw3NtClose PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 00C9C2509h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 00C9C2509h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtClose ENDP

Sw3NtReadVirtualMemory PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0859662F8h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 0859662F8h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtReadVirtualMemory ENDP

Sw3NtWriteVirtualMemory PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 003972B37h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 003972B37h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtWriteVirtualMemory ENDP

Sw3NtAllocateVirtualMemory PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 08B148197h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 08B148197h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtAllocateVirtualMemory ENDP

Sw3NtProtectVirtualMemory PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0339AFFCFh        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 0339AFFCFh        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtProtectVirtualMemory ENDP

Sw3NtFreeVirtualMemory PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 081189F8Fh        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 081189F8Fh        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtFreeVirtualMemory ENDP

Sw3NtQuerySystemInformation PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 08CD66EDBh        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 08CD66EDBh        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtQuerySystemInformation ENDP

Sw3NtQueryDirectoryFile PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 07A388A6Eh        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 07A388A6Eh        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtQueryDirectoryFile ENDP

Sw3NtQueryInformationFile PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0ED562B6Bh        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 0ED562B6Bh        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtQueryInformationFile ENDP

Sw3NtQueryInformationProcess PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 08106666Ch        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 08106666Ch        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtQueryInformationProcess ENDP

Sw3NtQueryInformationThread PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 03C0836ADh        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 03C0836ADh        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtQueryInformationThread ENDP

Sw3NtCreateSection PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 07B3A87B0h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 07B3A87B0h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtCreateSection ENDP

Sw3NtOpenSection PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 014B4D5E7h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 014B4D5E7h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtOpenSection ENDP

Sw3NtMapViewOfSection PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0D3B4F125h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 0D3B4F125h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtMapViewOfSection ENDP

Sw3NtUnmapViewOfSection PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 00CA66C77h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 00CA66C77h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtUnmapViewOfSection ENDP

Sw3NtAdjustPrivilegesToken PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 08355094Eh        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 08355094Eh        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtAdjustPrivilegesToken ENDP

Sw3NtDeviceIoControlFile PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 04CDA404Ch        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 04CDA404Ch        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtDeviceIoControlFile ENDP

Sw3NtQueueApcThread PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 008A4D29Ah        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 008A4D29Ah        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtQueueApcThread ENDP

Sw3NtQueueApcThreadEx PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0D23F2741h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 0D23F2741h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtQueueApcThreadEx ENDP

Sw3NtWaitForMultipleObjects PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 06039A472h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 06039A472h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtWaitForMultipleObjects ENDP

Sw3NtCreateTransaction PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 008202B71h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 008202B71h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtCreateTransaction ENDP

Sw3NtCreateFile PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 03EE4B6C2h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 03EE4B6C2h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtCreateFile ENDP

Sw3NtWriteFile PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 07EE8B6BEh        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 07EE8B6BEh        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtWriteFile ENDP

Sw3NtRollbackTransaction PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 030E82E59h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 030E82E59h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtRollbackTransaction ENDP

end