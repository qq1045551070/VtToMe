#include "VtVmExit.h"
#include "VtBase.h"
#include "VtEpt.h"
#include "VtEptHook.h"
#include "VtEvent.h"
#include "Tools.h"
#include "VtSsdtHook.h"

extern VtEpt * g_Ept;
EXTERN_C PVOID KiSystemCall64Pointer;

void ShowGuestRegister(ULONG_PTR* Registers)
{
	ULONG_PTR Rip = 0, Rsp = 0;
	ULONG_PTR Cr0 = 0, Cr3 = 0, Cr4 = 0;
	ULONG_PTR Cs = 0, Ss = 0, Ds = 0, Es = 0, Fs = 0, Gs = 0, Tr = 0, Ldtr = 0;
	ULONG_PTR GsBase = 0, DebugCtl = 0, Dr7 = 0, RFlags = 0;
	ULONG_PTR IdtBase = 0, GdtBase = 0, IdtLimit = 0, GdtLimit = 0;

	DbgPrint("Debug:RAX = 0x%016llX RCX = 0x%016llX RDX = 0x%016llX RBX = 0x%016llX\n",
		Registers[R_RAX], Registers[R_RCX], Registers[R_RDX], Registers[R_RBX]);
	DbgPrint("Debug:RSP = 0x%016llX RBP = 0x%016llX RSI = 0x%016llX RDI = 0x%016llX\n",
		Registers[R_RSP], Registers[R_RBP], Registers[R_RSI], Registers[R_RDI]);
	DbgPrint("Debug:R8 = 0x%016llX R9 = 0x%016llX R10 = 0x%016llX R11 = 0x%016llX\n",
		Registers[R_R8], Registers[R_R9], Registers[R_R10], Registers[R_R11]);
	DbgPrint("Debug:R12 = 0x%016llX R13 = 0x%016llX R14 = 0x%016llX R15 = 0x%016llX\n",
		Registers[R_R12], Registers[R_R13], Registers[R_R14], Registers[R_R15]);
	DbgPrint("\r\n");

	__vmx_vmread(GUEST_RSP, &Rsp);
	__vmx_vmread(GUEST_RIP, &Rip);
	DbgPrint("Debug:RSP = 0x%016llX RIP = 0x%016llX\n", Rsp, Rip);

	__vmx_vmread(GUEST_CR0, &Cr0);
	__vmx_vmread(GUEST_CR3, &Cr3);
	__vmx_vmread(GUEST_CR4, &Cr4);
	DbgPrint("Debug:CR0 = 0x%016llX CR3 = 0x%016llX CR4 = 0x%016llX\n", Cr0, Cr3, Cr4);

	__vmx_vmread(GUEST_CS_SELECTOR, &Cs);
	__vmx_vmread(GUEST_SS_SELECTOR, &Ss);
	__vmx_vmread(GUEST_DS_SELECTOR, &Ds);
	__vmx_vmread(GUEST_ES_SELECTOR, &Es);
	__vmx_vmread(GUEST_FS_SELECTOR, &Fs);
	__vmx_vmread(GUEST_GS_SELECTOR, &Gs);
	__vmx_vmread(GUEST_TR_SELECTOR, &Tr);
	__vmx_vmread(GUEST_LDTR_SELECTOR, &Ldtr);
	DbgPrint("Debug:CS = 0x%016llX SS = 0x%016llX DS = 0x%016llX ES = 0x%016llX FS = 0x%016llX GS = 0x%016llX TR = 0x%016llX LDTR = 0x%016llX\n",
		Cs, Ss, Ds, Es, Fs, Gs, Tr, Ldtr);

	__vmx_vmread(GUEST_GS_BASE, &GsBase);
	__vmx_vmread(GUEST_IA32_DEBUGCTL, &DebugCtl);
	__vmx_vmread(GUEST_DR7, &Dr7);
	__vmx_vmread(GUEST_RFLAGS, &RFlags);
	DbgPrint("Debug:GsBase = 0x%016llX DebugCtl = 0x%016llX Dr7 = 0x%016llX RFlags = 0x%016llX\n",
		GsBase, DebugCtl, Dr7, RFlags);

	__vmx_vmread(GUEST_IDTR_BASE, &IdtBase);
	__vmx_vmread(GUEST_IDTR_LIMIT, &IdtLimit);
	DbgPrint("Debug:IdtBase = 0x%016llX IdtLimit = 0x%016llX\n", IdtBase, IdtLimit);

	__vmx_vmread(GUEST_GDTR_BASE, &GdtBase);
	__vmx_vmread(GUEST_GDTR_LIMIT, &GdtLimit);
	DbgPrint("Debug:GdtBase = 0x%016llX GdtLimit = 0x%016llX\n", GdtBase, GdtLimit);

	return VOID();
}

// 用于统一处理 VM-EXIT
EXTERN_C FASTCALL
VOID VtVmExitRoutine(ULONG_PTR * Registers)
{
	KIRQL irql = KeGetCurrentIrql();
	if (irql < DISPATCH_LEVEL) {
		KeRaiseIrqlToDpcLevel(); // 提升 IRQL 等级为 DPC_LEVEL
	}
	
	VmExitInformation exitReason = { 0 };
	FlagRegister guestRflag = { 0 };

	exitReason.all = (ULONG32)VtBase::VmCsRead(VM_EXIT_REASON); // 获取 VM-exit 原因

	switch (exitReason.Bits.reason)
	{
	case ExitExceptionOrNmi:	// 拦截 Nmi 中断(不可屏蔽)
		NmiExceptionVtExitHandler(Registers);
		break;
	case ExitExternalInterrupt: // 拦截外部中断(可屏蔽)
		ExternalInterruptVtExitHandler(Registers);
		break;
	case ExitCpuid:			// 拦截 cpuid
		CpuidVmExitHandler(Registers);
		break;
	case ExitVmcall:		// 拦截 vmcall
		VmcallVmExitHandler(Registers);
		break;
	case ExitCrAccess:		// 拦截访问 CrX 寄存器
		CrAccessVtExitHandler(Registers);
		break;
	case ExitMsrRead:		// 拦截msr寄存器访问,必须设置,不然任何访msr的操作都会导致vmexit
		MsrReadVtExitHandler(Registers);
		break;
	case ExitMsrWrite:		// 拦截msr寄存器 写入
		MsrWriteVtExitHandler(Registers);
		break;
	case ExitGdtrOrIdtrAccess:	// 拦截 LGDT、LIDT、SGDT or SIDT 指令
		GdtrOrIdtrAccessVtExitHandler(Registers);
		break;
	case ExitLdtrOrTrAccess:	// 拦截 LLDT, LTR, SLDT, or STR 指令
		LdtrOrTrAccessVtExitHandler(Registers);
	case ExitEptViolation:	// EPT Violation 导致的 VM-EXIT
		g_Ept->EptViolationVtExitHandler(Registers);
		break;
	case ExitEptMisconfig:	// Ept 配置错误
		kprint(("ExitEptMisconfig!\r\n"));
		DbgBreakPoint();
		break;
	case ExitTripleFault:	// 3重异常,对它的处理直接蓝屏;
		kprint(("ExitTripleFault 0x%p!\r\n", VtBase::VmCsRead(GUEST_RIP)));
		DbgBreakPoint();
		break;
	case ExitXsetbv:		// Win10 必须处理高速缓存
		_xsetbv((ULONG32)Registers[R_RCX], MAKEQWORD(Registers[R_RAX], Registers[R_RDX]));
		break;
	case ExitInvd:
		__wbinvd();
		break;
	case ExitVmclear:		// 拒绝 VT 嵌套
	case ExitVmptrld:
	case ExitVmptrst:
	case ExitVmread:
	case ExitVmwrite:
	case ExitVmresume:
	case ExitVmoff:
	case ExitVmon:
	case ExitVmlaunch:
	case ExitVmfunc:
	case ExitInvept:
	case ExitInvvpid:
	{
		// 设置 rflags 的 cf 位, 置为1(表面失败)
		guestRflag.all = VtBase::VmCsRead(GUEST_RFLAGS);
		guestRflag.Bits.cf = 1;
		VtBase::VmCsWrite(GUEST_RFLAGS, guestRflag.all);
		// 走默认流程
		DefaultVmExitHandler(Registers);
	}
		break;
	default:		// 默认例程
		DefaultVmExitHandler(Registers);
		kprint(("[+]default: 未知的 VM_EIXT 原因:0x%X\n", exitReason));
		break;
	}

	if (irql < DISPATCH_LEVEL) {
		KeLowerIrql(irql);
	}
	
	return VOID();
}

// 用于处理 CPUID VM-EXIT
EXTERN_C
VOID CpuidVmExitHandler(ULONG_PTR * Registers)
{
	int CpuInfo[4] = { 0 };

	if (Registers[R_RAX] == 0x88888888)
	{
		//KdBreakPoint();

		Registers[R_RAX] = 0x88888888;
		Registers[R_RBX] = 0x88888888;
		Registers[R_RCX] = 0x88888888;
		Registers[R_RDX] = 0x88888888;
	}
	else
	{
		// 默认正常流程
		__cpuidex(CpuInfo, (int)Registers[R_RAX], (int)Registers[R_RCX]);
		Registers[R_RAX] = (ULONG_PTR)CpuInfo[0];
		Registers[R_RBX] = (ULONG_PTR)CpuInfo[1];
		Registers[R_RCX] = (ULONG_PTR)CpuInfo[2];
		Registers[R_RDX] = (ULONG_PTR)CpuInfo[3];
	}

	// 走默认流程
	DefaultVmExitHandler(Registers);

	return VOID();
}

// 用于处理 CrX VM-EXIT
EXTERN_C
VOID CrAccessVtExitHandler(ULONG_PTR * Registers)
{
	CrxVmExitQualification CrxQualification = { 0 };
	CrxQualification.all = VtBase::VmCsRead(EXIT_QUALIFICATION); // 获取字段信息

	if (CrxQualification.Bits.lmsw_operand_type == 0)
	{
		switch (CrxQualification.Bits.crn)
		{
		case 3: // 访问 Cr3
		{
			if (CrxQualification.Bits.access_type == MovCrAccessType::KMobeFromCr)   // MOV reg,cr3
			{
				Registers[CrxQualification.Bits.gp_register] = VtBase::VmCsRead(GUEST_CR3);
			}
			else if(CrxQualification.Bits.access_type == kMoveToCr) // MOV crx, reg 
			{
				VtBase::VmCsWrite(GUEST_CR3, Registers[CrxQualification.Bits.gp_register]);
			}
		}
		break;
		default:
			kprint(("CrAccessVtExitHandler: 访问Cr[%d]!\r\n", CrxQualification.Bits.crn));
			break;
		}
	}

	// 走默认流程
	DefaultVmExitHandler(Registers);

	return VOID();
}

// 用于处理 VMCALL VM-EXIT
EXTERN_C
VOID VmcallVmExitHandler(ULONG_PTR * Registers)
{
	ULONG_PTR JmpEIP = 0;
	ULONG_PTR GuestRIP = 0, GuestRSP = 0;
	ULONG_PTR ExitInstructionLength = 0;

	GuestRIP = VtBase::VmCsRead(GUEST_RIP);
	GuestRSP = VtBase::VmCsRead(GUEST_RSP);
	ExitInstructionLength = VtBase::VmCsRead(VM_EXIT_INSTRUCTION_LEN);

	switch (Registers[R_RAX])
	{
	case CallSsdtHook:
	{
		VtSsdtHook::VtEferHook();
	}
		break;
	case CallEptHook:	// 提供 hook 的方式
	{
		//KdBreakPoint();
		PVOID retaddr = VtEptHook::VtEptHookMemory(Registers[R_RDX], Registers[R_R8], 1);
		*(PVOID *)Registers[R_R9] = retaddr; // 返回原函数流程
	}
		break;
	case CallDelEptHook: // 提供 hook 卸载的方式
		break;
	case CallExitVt: // 退出当前虚拟化
	{
		DbgPrint("Debug:【Over VMCALL被调用】\n");

		__vmx_off(); // 退出当前虚拟化

		JmpEIP = GuestRIP + ExitInstructionLength; // 越过产生 VM-EXIT 的指令
		// 修改 Rsp\Rip 返回到 Guest 中
		Asm_UpdateRspAndRip(GuestRSP, JmpEIP);
	}
	break;
	default:
		break;
	}

	// 走默认流程
	DefaultVmExitHandler(Registers);

	return VOID();
}

// 处理读取 MSR VM-EXIT
EXTERN_C
VOID MsrReadVtExitHandler(ULONG_PTR * Registers)
{
	ULONGLONG MsrValue = __readmsr((ULONG)Registers[R_RCX]);
	
	switch (Registers[R_RCX])
	{
	case MSR_LSTAR: // 读取 MSR RIP
	{
		KdBreakPoint();
		if (KiSystemCall64Pointer) {
			MsrValue = (ULONG_PTR)KiSystemCall64Pointer; // SSDT HOOK
		}
	}
	default:
	{
		// 默认正常流程
		Registers[R_RAX] = LODWORD(MsrValue);
		Registers[R_RDX] = HIDWORD(MsrValue);
	}
	break;
	}

	// 走默认流程
	DefaultVmExitHandler(Registers);

	return VOID();
}

// 处理写入 MSR VM-EXIT
EXTERN_C
VOID MsrWriteVtExitHandler(ULONG_PTR * Registers)
{
	ULONGLONG MsrValue = MAKEQWORD(Registers[R_RAX], Registers[R_RDX]);

	switch (Registers[R_RCX])
	{
	case IA32_SYSENTER_EIP: // 写入 MSR 0x176
	case IA32_SYSENTER_ESP: // 写入 MSR 0x175
	case IA32_SYSENTER_CS:	// 写入 MSR 0x174
	default:
	{
		// 默认正常流程
		__writemsr((ULONG)Registers[R_RCX], MsrValue);
	}
	break;
	}

	// 走默认流程
	DefaultVmExitHandler(Registers);

	return VOID();
}

// 用于处理 Nmi 中断 (不可屏蔽中断)
EXTERN_C
VOID NmiExceptionVtExitHandler(ULONG_PTR * Registers)
{
	UNREFERENCED_PARAMETER(Registers);

	VmxVmExit_Interrupt_info exception = { 0 }; // 定义直接向量事件
	InterruptionType interruption_type = InterruptionType::kExternalInterrupt; // 默认初始化
	InterruptionVector vector = InterruptionVector::EXCEPTION_VECTOR_DIVIDE_ERROR;
	ULONG32 error_code_valid = 0;

	/*
		"直接向量事件" 是指直接引发 VM-exit 的向量事件。包括以下三种：
		(1). 硬件异常：由于异常的向量号在 exception bitmap 对应的位为1而直接导致 VM-exit.
		(2). 软件异常(#BP与#OF)：由于异常的向量号在 exception bitmap 对应的位为1而直接导致 VM-exit.
		(3). 外部中断：发生外部中断请求时, 由于"exception-interrupt exiting"为1而直接导致 VM-exit.
		(4). NMI：发生NMI请求时, 由于"NMI exiting"为1而直接导致 VM-exit.
	*/

	// 处理中断时, 获取 VM-Exit Interruption-Information 字段
	exception.all = static_cast<ULONG32>(VtBase::VmCsRead(VM_EXIT_INTR_INFO));

	interruption_type = static_cast<InterruptionType>(exception.Bits.interruption_type); // 获取中断类型
	vector = static_cast<InterruptionVector>(exception.Bits.vector); // 获取中断向量号
	error_code_valid = exception.Bits.error_code_valid; // 是否有错误码

	if (interruption_type == InterruptionType::kHardwareException)
	{
		// 如果是硬件异常, 处理其关于内存的异常
		if (vector == InterruptionVector::EXCEPTION_VECTOR_PAGE_FAULT)
		{
			// 如果为 #PF 异常
			// exit qualification 字段存储的是 #PF 异常的线性地址值 (参考【处理器虚拟化技术】(第3.10.1.6节))
			auto fault_address = VtBase::VmCsRead(EXIT_QUALIFICATION);

			// VM-exit interruption error code 字段指向的是 Page-Fault Error Code (参考【处理器虚拟化技术】(第3.10.2节))
			PageFaultErrorCode fault_code = { 0 };
			fault_code.all = static_cast<ULONG32>(VtBase::VmCsRead(VM_EXIT_INTR_ERROR_CODE));

			// 默认不修改，重新注入回去
			VtEvent::VtInjectInterruption(interruption_type, vector, true, fault_code.all);

			//kprint(("[+] #PF 异常!\r\n"));

			// 注意同步 cr2 寄存器
			__writecr2(fault_address);

			VtBase::VmCsWrite(VM_ENTRY_INTR_INFO, exception.all);

			if (error_code_valid) {
				VtBase::VmCsWrite(VM_ENTRY_EXCEPTION_ERROR_CODE, VtBase::VmCsRead(VM_EXIT_INTR_ERROR_CODE));
			}

		}
		else if (vector == InterruptionVector::EXCEPTION_VECTOR_GENERAL_PROTECTION){
			// 如果为 #GP 异常

			auto error_code = VtBase::VmCsRead(VM_EXIT_INTR_ERROR_CODE);

			// 默认不修改，重新注入回去
			VtEvent::VtInjectInterruption(interruption_type, vector, true, (ULONG32)error_code);

			//kprint(("[+] #GP 异常!\r\n"));
		}
		else if (vector == InterruptionVector::EXCEPTION_VECTOR_INVALID_OPCODE) {
			// 如果是 #UD 异常

			/*
				判断是否为 SysCall/SysRet 指令
			*/
			if (!VtSsdtHook::UdExceptionVtExitHandler(Registers)) {

				/*
					如果不是默认注入 #UD
				*/
				VtEvent::VtInjectInterruption(interruption_type, vector, false, 0);
			}
		}
	}
	else if (interruption_type == InterruptionType::kSoftwareException) {
		// 如果是 软件异常
		if (vector == InterruptionVector::EXCEPTION_VECTOR_BREAKPOINT)
		{
			// #BP
			// int3 触发的软件异常, 注意此指令有长度
			// 默认不修改，重新注入回去
			VtEvent::VtInjectInterruption(interruption_type, vector, false, 0);
			auto exit_inst_length = VtBase::VmCsRead(VM_EXIT_INSTRUCTION_LEN); // 获取导致 VM-exit 的指令长度
			VtBase::VmCsWrite(VM_ENTRY_INSTRUCTION_LEN, exit_inst_length);

			//kprint(("[+] #BP 异常!\r\n"));
		}
	}
	else {
		//kprint(("[+] interruption_type:[%d]; vector:[%d] 异常!\r\n", interruption_type, vector));
		VtBase::VmCsWrite(VM_ENTRY_INTR_INFO, exception.all);

		if (error_code_valid) {
			VtBase::VmCsWrite(VM_ENTRY_EXCEPTION_ERROR_CODE, VtBase::VmCsRead(VM_EXIT_INTR_ERROR_CODE));
		}
	}
}

// 用于处理 外部中断
EXTERN_C
VOID ExternalInterruptVtExitHandler(ULONG_PTR * Registers)
{
	DefaultVmExitHandler(Registers);
}

// 处理对 GDT/IDT 访问导致的 VM-exit
EXTERN_C
VOID GdtrOrIdtrAccessVtExitHandler(ULONG_PTR * Registers)
{
	UNREFERENCED_PARAMETER(Registers);
	
	/*
		sgdt [eax + 4 * ebx + 0xC]
		eax : base_register
		ebx : index_register
		4	: scalling
		0xC	: displacement
	*/

	// 获取其偏移量 (参考【处理器虚拟化技术】(第3.10.1.4节))
	ULONG_PTR displacement = VtBase::VmCsRead(EXIT_QUALIFICATION);
	// 获取指令相关信息
	GdtrOrIdtrInstInformation instruction_info = { 0 };
	instruction_info.all = static_cast<ULONG32>(VtBase::VmCsRead(VMX_INSTRUCTION_INFO));

	ULONG_PTR scalling = static_cast<ULONG_PTR>(instruction_info.Bits.scalling);
	ULONG_PTR address_size = static_cast<ULONG_PTR>(instruction_info.Bits.address_size);
	ULONG_PTR operand_size = static_cast<ULONG_PTR>(instruction_info.Bits.operand_size);
	ULONG_PTR segment_register = static_cast<ULONG_PTR>(instruction_info.Bits.segment_register);
	ULONG_PTR index_register = static_cast<ULONG_PTR>(instruction_info.Bits.index_register);
	ULONG_PTR index_register_invalid = static_cast<ULONG_PTR>(instruction_info.Bits.index_register_invalid);
	ULONG_PTR base_register = static_cast<ULONG_PTR>(instruction_info.Bits.base_register);
	ULONG_PTR base_register_invalid = static_cast<ULONG_PTR>(instruction_info.Bits.base_register_invalid);
	ULONG_PTR instruction_identity = static_cast<ULONG_PTR>(instruction_info.Bits.instruction_identity);

	UNREFERENCED_PARAMETER(address_size);
	UNREFERENCED_PARAMETER(operand_size);

	ULONG_PTR base_address = 0;
	ULONG_PTR index_address = 0;
	ULONG_PTR total_address = 0;

	if (segment_register > 5) {
		//kprint(("超过段选择子界限!\r\n"));
		return VOID();
	}

	if (!index_register_invalid && (index_register < 16)) {
		// 如果有操作数寄存器, 判断是否有操作数
		if (scalling) index_address = 0;
		else {
			// 有操作数
			index_address = Registers[index_register] << scalling;
		}
	}

	if (!base_register_invalid && (base_register < 16)) {
		// 如果有基址寄存器
		base_address = Registers[base_register];
	}

	// 计算内存总大小 (注意此地址有可能是 ring3 模式下的)
	total_address = VtBase::VmCsRead(GUEST_ES_BASE + segment_register * 2) + base_address + index_address + displacement;
	// 方案一：将其地址物理页重新映射一份到 ring0
	
	// 判断访问的指令类型 （0-SGDT、1-SIDT、2-LGDT、3-LIDT）
	switch (instruction_identity)
	{
	case 0:		// SGDT
	case 1:		// SIDT
	{
		ULONG_PTR cr3 = 0;
		PCHAR address = NULL;
		cr3 = VtBase::VmCsRead(GUEST_CR3);
		address = reinterpret_cast<PCHAR>(GetKernelModeLinerAddress(cr3, total_address));
		*(PULONG)(address + 2) = 0x12345678;
		*(PSHORT)(address) = 0x3ff;
		FreeKernelModeLinerAddress(address);
	}
	break;
	case 2:		// LGDT
		break;
	default:	// LIDT
		break;
	}

	// 走默认流程
	DefaultVmExitHandler(Registers);
	return VOID();
}

// 处理对 LDT/TR 访问导致的 VM-exit
EXTERN_C
VOID LdtrOrTrAccessVtExitHandler(ULONG_PTR * Registers)
{
	UNREFERENCED_PARAMETER(Registers);
	//KdBreakPoint();
	/*

	*/

	// 获取其偏移量 (参考【处理器虚拟化技术】(第3.10.1.4节))
	ULONG_PTR displacement = VtBase::VmCsRead(EXIT_QUALIFICATION);
	// 获取指令相关信息
	LdtrOrTrInstInformation instruction_info = { 0 };
	instruction_info.all = static_cast<ULONG32>(VtBase::VmCsRead(VMX_INSTRUCTION_INFO));

	ULONG_PTR scalling = static_cast<ULONG_PTR>(instruction_info.Bits.scalling);
	ULONG_PTR register1 = static_cast<ULONG_PTR>(instruction_info.Bits.register1);
	ULONG_PTR address_size = static_cast<ULONG_PTR>(instruction_info.Bits.address_size);
	ULONG_PTR register_access = static_cast<ULONG_PTR>(instruction_info.Bits.register_access);
	ULONG_PTR segment_register = static_cast<ULONG_PTR>(instruction_info.Bits.segment_register);
	ULONG_PTR index_register = static_cast<ULONG_PTR>(instruction_info.Bits.index_register);
	ULONG_PTR index_register_invalid = static_cast<ULONG_PTR>(instruction_info.Bits.index_register_invalid);
	ULONG_PTR base_register = static_cast<ULONG_PTR>(instruction_info.Bits.base_register);
	ULONG_PTR base_register_invalid = static_cast<ULONG_PTR>(instruction_info.Bits.base_register_invalid);
	ULONG_PTR instruction_identity = static_cast<ULONG_PTR>(instruction_info.Bits.instruction_identity);

	UNREFERENCED_PARAMETER(address_size);
	UNREFERENCED_PARAMETER(register1);
	
	// 先判断访问形式
	if (register_access) {
		// 如果是寄存器的访问形式
		// 判断访问指令类型
		switch (instruction_identity) //（0-SLDT、1-STR、2-LLDT、3-LTR）
		{
		case 0: // SLDT
		{
			Registers[index_register] = VtBase::VmCsRead(GUEST_LDTR_SELECTOR);
		}
		break;
		case 1:	// STR
		{
			Registers[index_register] = VtBase::VmCsRead(GUEST_TR_SELECTOR);
		}
		break;
		case 2: // LLDT
		{
			VtBase::VmCsWrite(GUEST_LDTR_SELECTOR, Registers[index_register]);
		}
		break;
		case 3: // LTR
		{
			VtBase::VmCsWrite(GUEST_TR_SELECTOR, Registers[index_register]);
		}
		break;
		}
	}
	else {
		// 如果是内存的访问形式
		if (segment_register > 5) {
			//kprint(("超过段选择子界限!\r\n"));
			return VOID();
		}

		ULONG_PTR base_address = 0;
		ULONG_PTR index_address = 0;
		ULONG_PTR total_address = 0;

		if (!index_register_invalid && (index_register < 16)) {
			// 如果有操作数寄存器, 判断是否有操作数
			if (scalling) index_address = 0;
			else {
				// 有操作数
				index_address = Registers[index_register] << scalling;
			}
		}

		if (!base_register_invalid && (base_register < 16)) {
			// 如果有基址寄存器
			base_address = Registers[base_register];
		}

		// 计算内存总大小 (注意此地址有可能是 ring3 模式下的)
		total_address = VtBase::VmCsRead(GUEST_ES_BASE + segment_register * 2) + base_address + index_address + displacement;

		switch (instruction_identity) //（0-SLDT、1-STR、2-LLDT、3-LTR）
		{
		case 0: // SLDT
			break;
		case 1:	// STR
			break;
		case 2: // LLDT
			break;
		case 3: // LTR
			break;
		}
	}

	// 走默认流程
	DefaultVmExitHandler(Registers);

	return VOID();
}

// 用于处理默认 VM-EXIT
EXTERN_C
VOID DefaultVmExitHandler(ULONG_PTR * Registers)
{
	//ULONG_PTR exitReason = VtBase::VmCsRead(VM_EXIT_REASON); // 获取 VM-exit 原因
	ULONG_PTR guestRip = VtBase::VmCsRead(GUEST_RIP);
	ULONG_PTR guestRsp = VtBase::VmCsRead(GUEST_RSP);
	ULONG_PTR exitInstructionLength = VtBase::VmCsRead(VM_EXIT_INSTRUCTION_LEN); // 退出的指令长度

	UNREFERENCED_PARAMETER(Registers);

	VtBase::VmCsWrite(GUEST_RIP, guestRip + exitInstructionLength);
	VtBase::VmCsWrite(GUEST_RSP, guestRsp);

	return VOID();
}
