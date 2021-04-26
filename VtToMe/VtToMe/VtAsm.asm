
.CODE
ALIGN 16

VtVmExitRoutine PROTO ; 外部函数

;----------------------------------------------------------------------------------
; 宏定义
SAVESTATE MACRO
	push r15
	mov r15,rsp  ;先保存原始的栈顶(进入接管函数之前的RSP)
	add r15,8
	push r14
	push r13
	push r12
	push r11
	push r10
	push r9
	push r8
	push rdi
	push rsi
	push rbp
	push r15    ;rsp
	push rbx
	push rdx
	push rcx
	push rax
ENDM

LOADSTATE MACRO
	pop rax
	pop rcx
	pop rdx
	pop rbx
	add rsp, 8
	pop rbp
	pop rsi
	pop rdi
	pop r8
	pop r9
	pop r10
	pop r11
	pop r12
	pop r13
	pop r14
	pop r15
ENDM
;----------------------------------------------------------------------------------
__readcs PROC
	xor rax, rax;
	mov rax, cs;
	ret;
__readcs ENDP

__readds PROC
	xor rax, rax;
	mov rax, ds;
	ret;
__readds ENDP

__readss PROC
	xor rax, rax;
	mov rax, ss;
	ret;
__readss ENDP

__reades PROC
	xor rax, rax;
	mov rax, es;
	ret;
__reades ENDP

__readfs PROC
	xor rax, rax;
	mov rax, fs;
	ret;
__readfs ENDP

__readgs PROC
	xor rax, rax;
	mov rax, gs;
	ret;
__readgs ENDP

__sldt PROC
	xor rax, rax;
	sldt rax;
	ret;
__sldt ENDP

__str PROC
	xor rax, rax;
	str rax;
	ret;
__str ENDP

__sgdt PROC
	xor rax, rax;
	mov rax, rcx;
	sgdt [rax];
	ret;
__sgdt ENDP

__invd PROC ; what if we just "mov eax,cr3;mov cr3, eax"
	invd;
	ret;
__invd ENDP

__writeds PROC
	mov ds, cx;
	ret;
__writeds ENDP

__writees PROC
	mov es, cx;
	ret;
__writees ENDP

__writefs PROC
	mov fs, cx;
	ret;
__writefs ENDP

__writecr2 PROC
	mov cr2, rcx;
	ret;
__writecr2 ENDP

;----------------------------------------------------------------------------------

__invept PROC
    invept rcx, OWORD PTR [rdx]
    ret
__invept ENDP

__invvpid PROC
    invvpid rcx, OWORD PTR [rdx]
    ret
__invvpid ENDP

;----------------------------------------------------------------------------------
__GetStackPointer PROC
 mov rax, rsp
 add rax, sizeof(QWORD)
 mov [rcx], rax;
 ret
__GetStackPointer ENDP

__GetNextInstructionPointer PROC
 mov rax, [rsp];
 mov [rcx], rax;
 ret
__GetNextInstructionPointer ENDP
;----------------------------------------------------------------------------------
Asm_VmExitHandler PROC
	cli
	SAVESTATE		;保存现场
	mov   rcx,rsp   ;把栈顶给rcx

	sub   rsp,0100h ; 开辟缓冲空间
	call  VtVmExitRoutine ; 调用 VtVmExitRoutine(__fastcall)
	add   rsp,0100h

	LOADSTATE		;恢复现场
	sti

__do_resume:
	vmresume;   返回到VM non-root(返回到Guest环境里继续执行)
	ret
Asm_VmExitHandler ENDP

;----------------------------------------------------------------------------------
Asm_UpdateRspAndRip PROC
	mov rsp,rcx
	jmp rdx
	ret
Asm_UpdateRspAndRip ENDP

Asm_VmxCall PROC
	push rax
	push rcx
	push rdx
	push rbx
	push rsi
	push rdi
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15 ;pushaq

	pushfq

	mov rax,rcx
	vmcall ; 调用 VMCALL
	
	popfq
	
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rdi
	pop rsi
	pop rbx
	pop rdx
	pop rcx
	pop rax ;popaq
	
	ret
Asm_VmxCall ENDP

END