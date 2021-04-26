USERMD_STACK_GS = 10h
KERNEL_STACK_GS = 1A8h

MAX_SYSCALL_INDEX = 1000h

EXTERN g_ssdt_table:DQ
EXTERN g_param_table:DB
EXTERN g_hook_enabled:DB

EXTERN KiSystemCall64Pointer:DQ
EXTERN KiSystemServiceCopyEndPointer:DQ

.CODE

; ************************复写 Windows7 syscall**************************
Win7_SysCallEntryPointer PROC
	swapgs									; 置换 GS 由TEB64变为 KPCR
	mov			gs:[USERMD_STACK_GS], rsp	; save user stack pointer

	cmp			rax, MAX_SYSCALL_INDEX		; 是否为影子表(shadow)函数
	jge			KiSystemCall64				; 是，跳回原函数流程

	lea			rsp, offset g_hook_enabled	; 
	cmp			byte ptr [rsp + rax], 0h	; 是否为Hook的函数
	jne			KiSystemCall64_Emulate		; 跳向我们的 syscall 流程
Win7_SysCallEntryPointer ENDP
; **************************************************

; ************************复写 Windows7 syscall**************************
KiSystemCall64 PROC
	mov rsp, gs:[USERMD_STACK_GS]	; 复原环境
	swapgs							; Switch to usermode GS
	jmp [KiSystemCall64Pointer]		; 跳回原函数流程
KiSystemCall64 ENDP
; **************************************************

; ************************复写 Windows7 syscall**************************
KiSystemCall64_Emulate PROC
	mov			rsp, gs:[KERNEL_STACK_GS]   ; set kernel stack pointer
	push		2Bh                         ; push dummy SS selector
    push		qword ptr gs:[10h]          ; push user stack pointer
    push		r11                         ; push previous EFLAGS
    push		33h                         ; push dummy 64-bit CS selector
    push		rcx                         ; push return address
    mov			rcx, r10                    ; set first argument value

	sub			rsp, 8h						; 
	push        rbp                         ; save standard register
    sub         rsp, 158h                   ; allocate fixed frame
    lea         rbp, [rsp+80h]              ; set frame pointer
    mov         [rbp+0C0h], rbx             ; save nonvolatile registers
    mov         [rbp+0C8h], rdi             ;
    mov         [rbp+0D0h], rsi             ;
    mov         byte ptr [rbp-55h], 2h      ; set service active
    mov         rbx, gs:[188h]              ; get current thread address
    prefetchw	byte ptr [rbx+1D8h]         ; prefetch with write intent
    stmxcsr     dword ptr [rbp-54h]         ; save current MXCSR
    ldmxcsr     dword ptr gs:[180h]         ; set default MXCSR
    cmp         byte ptr [rbx+3], 0         ; test if debug enabled
    mov         word ptr [rbp+80h], 0       ; assume debug not enabled
	jz			KiSS50						; if z, debug not enabled
	mov         [rbp-50h], rax              ; save service argument registers
    mov         [rbp-48h], rcx              ;
    mov         [rbp-40h], rdx              ;
    mov         [rbp-38h], r8               ;
    mov         [rbp-30h], r9               ;

	int			3							; 调用 INT3 的 KiSaveDebugRegisterState(思路有点骚)
	align       10h							; 注意16字节对齐

KiSS50:
	mov		[rbx+1E0h], rcx					; CurrentThread.FirstArgument = 函数第一个参数
	mov		[rbx+1F8h], eax					;
KiSystemCall64_Emulate ENDP
; **************************************************

; ************************复写 Windows7 syscall**************************
KiSystemServiceStart PROC
	mov     [rbx+1D8h], rsp					; CurrentThread.TrapFrame = Rsp(当前_KTRAP_FRAME 结构)
	mov     edi, eax						; Rdi = 系统服务号
	shr     edi, 7							; Rdi = 系统服务号 >> 7
	and     edi, 20h						; Rdi = (系统服务号 >> 7) & 0x20 = 服务表的索引
	and     eax, 0FFFh						; EAX = 系统服务号
KiSystemServiceStart ENDP
; **************************************************

; ************************复写 Windows7 syscall**************************
KiSystemServiceRepeat PROC
	; RAX = [IN ] syscall index
    ; RAX = [OUT] number of parameters
    ; R10 = [OUT] func address
    ; R11 = [I/O] trashed

	lea		r11, offset g_ssdt_table			; 切换 ssdt 表
	mov		r10, qword ptr [r11 + rax * 8h]		; 获取Hook函数地址

	lea		r11, offset g_param_table			;
	movzx	rax, byte ptr [r11 + rax]			; RAX = paramter count

	jmp		[KiSystemServiceCopyEndPointer]		; 跳回原函数流程 (不能 Hook 五个参数以上的函数)
KiSystemServiceRepeat ENDP
; **************************************************

END