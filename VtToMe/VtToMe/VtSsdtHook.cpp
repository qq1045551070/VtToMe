#include "VtSsdtHook.h"
#include "Tools.h"
#include "NeedKernelFunc.h"
#include "VtAsm.h"
#include "vt_win7_kernel_code_asm.h"
#include "vt_win10_kernel_code_asm.h"
#include "VtBase.h"
#include "VtEvent.h"
#include <intrin.h>

typedef struct _NT_KPROCESS
{
	DISPATCHER_HEADER Header;
	LIST_ENTRY	ProfileListHead;
	ULONG64		DirectoryTableBase;		// 保存进程 R0 Cr3
	LIST_ENTRY	ThreadListHead;
	UINT32		ProcessLock;
	UINT32		ProcessTimerDelay;
	ULONG64		DeepFreezeStartTime;
	CHAR		Know[0x340];
	ULONG64		UserDirectoryTableBase; // 保存进程 R3 Cr3
}NT_KPROCESS, *PNT_KPROCESS;

// 是否为 SysRet 指令
#define IS_SYSRET_INSTRUCTION(Code) \
(*((PUINT8)(Code) + 0) == 0x48 && \
*((PUINT8)(Code) + 1) == 0x0F && \
*((PUINT8)(Code) + 2) == 0x07)

// 是否为 SysCall 指令
#define IS_SYSCALL_INSTRUCTION(Code) \
(*((PUINT8)(Code) + 0) == 0x0F && \
*((PUINT8)(Code) + 1) == 0x05)

EXTERN_C CHAR  g_hook_enabled[MAX_SYSCALL_INDEX] = { 0 };	// 是否Hook该下表函数
EXTERN_C CHAR  g_param_table[MAX_SYSCALL_INDEX]  = { 0 };	// 函数参数表
EXTERN_C PVOID g_ssdt_table[MAX_SYSCALL_INDEX]	= { 0 };	// ssdt 表(直接存储函数地址)

EXTERN_C PVOID KiSystemCall64Pointer = NULL;
EXTERN_C PVOID KiSystemServiceCopyEndPointer = NULL;

ULONG_PTR g_r3_Cr3 = 0;
ULONG_PTR g_r0_Cr3 = 0;

VtSsdtHook::VtSsdtHook()
{}

VtSsdtHook::~VtSsdtHook()
{}

// 初始化函数
bool VtSsdtHook::VtInitSsdtHook()
{
	__debugbreak();
	if (NULL == KiSystemCall64Pointer) {
		// 获取 KiSystemCall64 地址
		KiSystemCall64Pointer = (PVOID)__readmsr(MSR_LSTAR); // System Call Rip
	}

	if (GetWindowsVersion() == WIN7) {
		// 如果是 Win7 直接采用 Hook Msr lstar 方式
		if (NULL == KiSystemServiceCopyEndPointer) {
			// 获取 KiSystemServiceCopyEnd
			char opcode[] = "\xf7\x05********\x0F\x85****\x41\xFF\xD2";
			KiSystemServiceCopyEndPointer = MmFindByCode(opcode, 19);
		}
	}
	else if (GetWindowsVersion() == WIN10) {
		// 如果是 Win10 采用 Efer Hook
		if (NULL == KiSystemServiceCopyEndPointer) {
			// 获取 KiSystemServiceCopyEnd
			char opcode[] = "\xf7\x05********\x0F\x85****\xf7\x05********\x0F\x85****\x49\x8B\xC2\xFF\xD0";
			KiSystemServiceCopyEndPointer = MmFindByCode(opcode, 0x25);
		}
	}
	

	if (!KiSystemCall64Pointer || !KiSystemServiceCopyEndPointer) 
		return false;
	return true;
}

// Hook 指定下标 SSDT 函数
bool VtSsdtHook::VtHookSsdtByIndex(ULONG32 ssdt_index, PVOID hook_address, CHAR param_number)
{
	UNREFERENCED_PARAMETER(ssdt_index);

	LARGE_INTEGER timeOut;
	timeOut.QuadPart = -1 * 1000 * 1000; // 0.1秒延迟加载, 以防 VT 未启动
	KeDelayExecutionThread(KernelMode, FALSE, &timeOut);

	g_hook_enabled[ssdt_index] = TRUE;			// Hook 标志打亮
	g_param_table[ssdt_index]  = param_number;	// 确定函数参数
	g_ssdt_table[ssdt_index]   = hook_address;	// 修改其函数地址

	return true;
}

// Hook Msr Lstar 寄存器
bool VtSsdtHook::VtHookMsrLstar()
{
	RemovWP();
	// HOOK LSTAR
	__writemsr(MSR_LSTAR, (ULONG_PTR)Win7SysCallEntryPointer); // 修改 SysCall Rip 流程
	
	UnRemovWP();
	return true;
}

// Un Hook Msr Lstar 寄存器
bool VtSsdtHook::VtUnHookMsrLstar()
{
	RemovWP();

	// HOOK LSTAR
	__writemsr(MSR_LSTAR, (ULONG_PTR)KiSystemCall64Pointer); // 修复 SysCall Rip 流程

	UnRemovWP();
	return true;
}

// Efer Hook
bool VtSsdtHook::VtEferHook()
{
	/*
		进行EFER HOOK所需要的步骤(参考 https://revers.engineering/syscall-hooking-via-extended-feature-enable-register-efer/)
		1. Enable VMX
		2. 设置 VM-entry 中的 load_ia32_efer 字段
		3. 设置 VM-exit 中的 save_ia32_efer 字段
		4. 设置 MSR-bitmap 让其在, 写入和读取EFER MSR时退出
		5. 设置 Exception-bitmap 拦截 #UD 异常
		6. 设置 VM-exit 中的 load_ia32_efer 字段
		7. 清除 sce 位
		8. 处理 SysCall 与 SysRet 指令导致的 #UD 异常
	*/
	
	Ia32VmxEfer ia32_efer = { 0 };
	ia32_efer.all = __readmsr(MSR_IA32_EFER);
	ia32_efer.Bits.sce = false;
	// 清除 sce 位
	VtBase::VmCsWrite(GUEST_EFER, ia32_efer.all);

	return true;
}

// #UD 异常处理
bool VtSsdtHook::UdExceptionVtExitHandler(ULONG_PTR * Registers)
{
	// 获取基本信息
	BOOLEAN retbool = FALSE;
	ULONG_PTR guestRip = VtBase::VmCsRead(GUEST_RIP);
	ULONG_PTR guest_cr3 = VtBase::VmCsRead(GUEST_CR3);
	//ULONG_PTR guest_liner_address = VtBase::VmCsRead(GUEST_LINEAR_ADDRESS);
	//ULONG_PTR guest_phy_address = VtBase::VmCsRead(GUEST_PHYSICAL_ADDRESS);
	ULONG_PTR exitInstructionLength = VtBase::VmCsRead(VM_EXIT_INSTRUCTION_LEN); // 退出的指令长度

	NT_KPROCESS * CurrentProcess = reinterpret_cast<PNT_KPROCESS>(PsGetCurrentProcess());
	ULONG_PTR current_process_kernel_cr3 = CurrentProcess->DirectoryTableBase;
	
	UNREFERENCED_PARAMETER(guest_cr3);
	
	__writecr3(current_process_kernel_cr3); // 切换为内核 Guest Cr3

	PULONG_PTR pte = GetPteAddress((PVOID)guestRip);

	if (!MmIsAddressValid((PVOID)guestRip) || !(*pte & 0x1)) { // 判断 Rip 地址内容是否可读
		// 不存在注入 #PF 异常
		
		__writecr2(guestRip); // 设置缺页地址

		PageFaultErrorCode fault_code = { 0 };
		VtEvent::VtInjectInterruption(
			InterruptionType::kHardwareException, 
			InterruptionVector::EXCEPTION_VECTOR_PAGE_FAULT,
			TRUE, fault_code.all);

		return TRUE;
	}
	
	PVOID user_liner_address = GetKernelModeLinerAddress(current_process_kernel_cr3, guestRip);

	if (exitInstructionLength == 0x2) { // 判断指令长度
		if (IS_SYSCALL_INSTRUCTION(user_liner_address)) {
			/*
				如果是 SysCall 指令
			*/
			VtSysCallEmulate(Registers);

			retbool = TRUE;
		}
	}
	
	if (exitInstructionLength == 0x3) {
		if (IS_SYSRET_INSTRUCTION(user_liner_address)) {
			/*
				如果是 SysRet 指令
			*/
			VtSysRetEmulate(Registers);

			retbool = TRUE;
		}
	}

	FreeKernelModeLinerAddress(user_liner_address);

	return retbool;
}

// 模拟 SysCall 流程
bool VtSsdtHook::VtSysCallEmulate(ULONG_PTR * Registers)
{
	// 获取基本信息
	PNT_KPROCESS current_process = (PNT_KPROCESS)PsGetCurrentProcess();
	ULONG_PTR MsrValue = 0;
	BOOLEAN boolret = TRUE;
	ULONG_PTR guestRip = VtBase::VmCsRead(GUEST_RIP);
	//ULONG_PTR guestRsp = VtBase::VmCsRead(GUEST_RSP);
	ULONG_PTR GuestRflags = VtBase::VmCsRead(GUEST_RFLAGS);
	//ULONG_PTR guest_r3_cr3 = VtBase::VmCsRead(GUEST_CR3);
	ULONG_PTR exitInstructionLength = VtBase::VmCsRead(VM_EXIT_INSTRUCTION_LEN); // 退出的指令长度

	// 参考白皮书 SYSCALL—Fast System Call

	/*
		a.	SysCall loading Rip From the IA32_LSTA MSR
		b.	SysCall 加载 IA32_LSTA MSR 的值到 Rip 中
	*/
	//MsrValue = __readmsr(MSR_LSTAR);
	// 走我们的流程
	MsrValue = (ULONG_PTR)Win10_SysCallEntryPointer;
	boolret &= VtBase::VmCsWrite(GUEST_RIP, MsrValue);

	/*
		a.	After Saving the Adress of the instruction following SysCall into Rcx
		b.	SysCall 会将下一行指令地址保存到 Rcx 中
	*/
	auto next_instruction = exitInstructionLength + guestRip;
	Registers[R_RCX] = next_instruction;

	/*
		a. Save RFLAGS into R11 and then mask RFLAGS using MSR_FMASK.
		b. 保存 RFLAGS 到 R11 寄存器中, 并且使用 MSR_FMASK 清除 RFLAGS 对应的每一位
	*/
	MsrValue = __readmsr(MSR_IA32_FMASK);
	Registers[R_R11] = GuestRflags;
	GuestRflags &= ~(MsrValue | X86_FLAGS_RF);
	VtBase::VmCsWrite(GUEST_RFLAGS, GuestRflags);

	/*
		a. SYSCALL loads the CS and SS selectors with values derived from bits 47:32 of the IA32_STAR MSR.
		b. SysCall 加载 CS、SS 段寄存器的值来自于 IA32_STAR MSR 寄存器的 32:47 位
	*/
	MsrValue = __readmsr(MSR_IA32_STAR);
	ULONG_PTR Cs = (UINT16)((MsrValue >> 32) & ~3);
	boolret &= VtBase::VmCsWrite(GUEST_CS_SELECTOR, Cs);
	boolret &= VtBase::VmCsWrite(GUEST_CS_LIMIT, (UINT32)~0);
	boolret &= VtBase::VmCsWrite(GUEST_CS_AR_BYTES, 0xA09B);
	boolret &= VtBase::VmCsWrite(GUEST_CS_BASE, 0);

	ULONG_PTR Ss = Cs + 0x8;
	boolret &= VtBase::VmCsWrite(GUEST_SS_SELECTOR, Ss);
	boolret &= VtBase::VmCsWrite(GUEST_SS_LIMIT, (UINT32)~0);
	boolret &= VtBase::VmCsWrite(GUEST_SS_AR_BYTES, 0xC093);
	boolret &= VtBase::VmCsWrite(GUEST_SS_BASE, 0);

	VtBase::VmCsWrite(GUEST_CR3, current_process->DirectoryTableBase);

	return boolret;
}

// 模拟 SysRet 流程
bool VtSsdtHook::VtSysRetEmulate(ULONG_PTR * Registers)
{
	// 获取基本信息
	//PNT_KPROCESS current_process = (PNT_KPROCESS)PsGetCurrentProcess();
	ULONG_PTR MsrValue = 0;
	BOOLEAN boolret = TRUE;
	ULONG_PTR GuestRflags = 
		(Registers[R_R11] & ~(X86_FLAGS_RF | X86_FLAGS_VM | X86_FLAGS_RESERVED_BITS)) | X86_FLAGS_FIXED;
	ULONG_PTR exitInstructionLength = VtBase::VmCsRead(VM_EXIT_INSTRUCTION_LEN); // 退出的指令长度

	UNREFERENCED_PARAMETER(exitInstructionLength);

	// 参考白皮书 SYSRET—Return From Fast System Call
	/*
		a. It does so by loading RIP from RCX and loading RFLAGS from R11
		b. 它将 RCX 值加载到 RIP , 将 R11 的值加载到 RFLAGS 来做到这一点
	*/
	boolret &= VtBase::VmCsWrite(GUEST_RIP, Registers[R_RCX]);
	boolret &= VtBase::VmCsWrite(GUEST_RFLAGS, GuestRflags);

	/*
		a. SYSRET loads the CS and SS selectors with values derived from bits 63:48 of the IA32_STAR MSR.
		b. SysRet 加载 CS、SS 段寄存器的值来自于 IA32_STAR MSR 寄存器的 48:63 位
	*/
	MsrValue = __readmsr(MSR_IA32_STAR);
	ULONG_PTR Cs = (UINT16)(((MsrValue >> 48) + 16) | 3);
	boolret &= VtBase::VmCsWrite(GUEST_CS_SELECTOR, Cs);
	boolret &= VtBase::VmCsWrite(GUEST_CS_LIMIT, (UINT32)~0);
	boolret &= VtBase::VmCsWrite(GUEST_CS_AR_BYTES, 0xA0FB);
	boolret &= VtBase::VmCsWrite(GUEST_CS_BASE, 0);

	ULONG_PTR Ss = (UINT16)(((MsrValue >> 48) + 8) | 3);
	boolret &= VtBase::VmCsWrite(GUEST_SS_SELECTOR, Ss);
	boolret &= VtBase::VmCsWrite(GUEST_SS_LIMIT, (UINT32)~0);
	boolret &= VtBase::VmCsWrite(GUEST_SS_AR_BYTES, 0xC0F3);
	boolret &= VtBase::VmCsWrite(GUEST_SS_BASE, 0);

	return boolret;
}

// 启动SsdtHook
bool VtSsdtHook::VtStartHookSsdt()
{
	if (GetWindowsVersion() == WIN7) {
		VtSsdtHook::VtHookMsrLstar();	// Msr Hook
	}
	else if (GetWindowsVersion() == WIN10) {
		Asm_VmxCall(CallSsdtHook);		// Efer Hook
	}
	else {
		return false;
	}

	return true;
}

// 停止SsdtHook
bool VtSsdtHook::VtStopHookSsdt()
{
	if (GetWindowsVersion() == WIN7) {
		// Win7 修复 Msr
		VtSsdtHook::VtUnHookMsrLstar();
	}
	else if (GetWindowsVersion() == WIN10) {
		Ia32VmxEfer ia32_efer = { 0 };
		ia32_efer.all = __readmsr(MSR_IA32_EFER);
		ia32_efer.Bits.sce = true;
		// sce 位置为1
		VtBase::VmCsWrite(GUEST_EFER, ia32_efer.all);
	}
	else {
		return false;
	}

	return true;
}
