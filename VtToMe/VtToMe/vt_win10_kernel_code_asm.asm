
USERMD_STACK_GS = 10h
KERNEL_STACK_GS = 1A8h
KERNEL_CR3 = 9000h

MAX_SYSCALL_INDEX = 1000h

EXTERN KiSystemCall64Pointer:DQ
EXTERN KiSystemServiceCopyEndPointer:DQ

EXTERN g_hook_enabled:DB
EXTERN g_param_table:DB
EXTERN g_ssdt_table:DQ

.DATA
ServiceNum dq ? ; 系统服务号

.CODE

; *********************************************************
;
;	复写Win10系统调用流程, 需要注意的是微软的"幽灵"补丁
;
; *********************************************************
Win10_SysCallEntryPointer PROC
	;cli
	
	;mov			gs:[USERMD_STACK_GS], rsp
	;mov			rsp, gs:[KERNEL_CR3]		; 切换为内核Cr3
	;mov			cr3, rsp

	swapgs
	mov			gs:[USERMD_STACK_GS], rsp

	;
	;	判断系统服务号是否为 影子表(shadow)函数
	;
	cmp			rax, MAX_SYSCALL_INDEX		; 是否为影子表(shadow)函数
	jge			Win10_KiSystemCall64		; 是，跳回原函数流程

	lea			rsp, offset g_hook_enabled	;
	cmp			byte ptr [rsp + rax], 0h	; 是否为Hook的函数
	jne			Win10_KiSystemCall64_Emulate		; 是的话, 跳向我们的 syscall 流程
Win10_SysCallEntryPointer ENDP

; *********************************************************
;
;	原函数流程
;
; *********************************************************
Win10_KiSystemCall64 PROC
	mov rsp, gs:[USERMD_STACK_GS]	; 复原环境
	swapgs							; Switch to usermode GS
	jmp [KiSystemCall64Pointer]		; 跳回原函数流程
Win10_KiSystemCall64 ENDP

; *********************************************************
;
;	我们的SysCall函数流程
;
; *********************************************************
Win10_KiSystemCall64_Emulate PROC
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
    mov         [rbp+0D0h], rsi				;

Win10_KiSystemServiceUser:
	mov			byte ptr [rbp-55h], 2
	mov			rbx, gs:[188h]
	prefetchw	byte ptr [rbx+90h]				    
	stmxcsr		dword ptr [rbp-54h]				    
	ldmxcsr		dword ptr gs:[180h]				    
	cmp			byte ptr [rbx+3], 0				    
	mov			word ptr [rbp+80h], 0
	jz			Win10_ClearDebugPart		; if CurrentThread.Header.DebugActive is 0, jmp
; -----------------------------------------------------------
	; GG 这里暂时不实现有调试情况下的相关处理
	INT 3
	align       10h

Win10_ClearDebugPart:
	;sti
	mov			[rbx+88h], rcx
	mov			[rbx+80h], eax
	xchg		ax, ax

Win10_KiSystemServiceStart:
	mov     [rbx+90h], rsp					; CurrentThread.TrapFrame = Rsp(当前_KTRAP_FRAME 结构)
	mov     edi, eax						; Rdi = 系统服务号
	shr     edi, 7							; Rdi = 系统服务号 >> 7
	and     edi, 20h						; Rdi = (系统服务号 >> 7) & 0x20 = 服务表的索引
	and     eax, 0FFFh						; EAX = 系统服务号

Win10_KiSystemServiceRepeat:
	; RAX = [IN ] syscall index
    ; RAX = [OUT] number of parameters
    ; R10 = [OUT] func address
    ; R11 = [I/O] trashed

	lea		r11, offset g_ssdt_table			; 切换 ssdt 表
	mov		r10, qword ptr [r11 + rax * 8h]		; 获取Hook函数地址

	lea		r11, offset g_param_table			;
	movzx	rax, byte ptr [r11 + rax]			; RAX = paramter count

	jmp		[KiSystemServiceCopyEndPointer]		; 跳回原函数流程 (不能 Hook 五个参数以上的函数)
Win10_KiSystemCall64_Emulate ENDP

END