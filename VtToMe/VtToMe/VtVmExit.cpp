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

// ???????????? VM-EXIT
EXTERN_C FASTCALL
VOID VtVmExitRoutine(ULONG_PTR * Registers)
{
	KIRQL irql = KeGetCurrentIrql();
	if (irql < DISPATCH_LEVEL) {
		KeRaiseIrqlToDpcLevel(); // ???? IRQL ?????? DPC_LEVEL
	}
	
	VmExitInformation exitReason = { 0 };
	FlagRegister guestRflag = { 0 };

	exitReason.all = (ULONG32)VtBase::VmCsRead(VM_EXIT_REASON); // ???? VM-exit ????

	switch (exitReason.Bits.reason)
	{
	case ExitExceptionOrNmi:	// ???? Nmi ????(????????)
		NmiExceptionVtExitHandler(Registers);
		break;
	case ExitExternalInterrupt: // ????????????(??????)
		ExternalInterruptVtExitHandler(Registers);
		break;
	case ExitCpuid:			// ???? cpuid
		CpuidVmExitHandler(Registers);
		break;
	case ExitVmcall:		// ???? vmcall
		VmcallVmExitHandler(Registers);
		break;
	case ExitCrAccess:		// ???????? CrX ??????
		CrAccessVtExitHandler(Registers);
		break;
	case ExitMsrRead:		// ????msr??????????,????????,??????????msr??????????????vmexit
		MsrReadVtExitHandler(Registers);
		break;
	case ExitMsrWrite:		// ????msr?????? ????
		MsrWriteVtExitHandler(Registers);
		break;
	case ExitGdtrOrIdtrAccess:	// ???? LGDT??LIDT??SGDT or SIDT ????
		GdtrOrIdtrAccessVtExitHandler(Registers);
		break;
	case ExitLdtrOrTrAccess:	// ???? LLDT, LTR, SLDT, or STR ????
		LdtrOrTrAccessVtExitHandler(Registers);
	case ExitEptViolation:	// EPT Violation ?????? VM-EXIT
		g_Ept->EptViolationVtExitHandler(Registers);
		break;
	case ExitEptMisconfig:	// Ept ????????
		kprint(("ExitEptMisconfig!\r\n"));
		DbgBreakPoint();
		break;
	case ExitTripleFault:	// 3??????,??????????????????;
		kprint(("ExitTripleFault 0x%p!\r\n", VtBase::VmCsRead(GUEST_RIP)));
		DbgBreakPoint();
		break;
	case ExitXsetbv:		// Win10 ????????????????
		_xsetbv((ULONG32)Registers[R_RCX], MAKEQWORD(Registers[R_RAX], Registers[R_RDX]));
		break;
	case ExitInvd:
		__wbinvd();
		break;
	case ExitVmclear:		// ???? VT ????
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
		// ???? rflags ?? cf ??, ????1(????????)
		guestRflag.all = VtBase::VmCsRead(GUEST_RFLAGS);
		guestRflag.Bits.cf = 1;
		VtBase::VmCsWrite(GUEST_RFLAGS, guestRflag.all);
		// ??????????
		DefaultVmExitHandler(Registers);
	}
		break;
	default:		// ????????
		DefaultVmExitHandler(Registers);
		kprint(("[+]default: ?????? VM_EIXT ????:0x%X\n", exitReason));
		break;
	}

	if (irql < DISPATCH_LEVEL) {
		KeLowerIrql(irql);
	}
	
	return VOID();
}

// ???????? CPUID VM-EXIT
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
		// ????????????
		__cpuidex(CpuInfo, (int)Registers[R_RAX], (int)Registers[R_RCX]);
		Registers[R_RAX] = (ULONG_PTR)CpuInfo[0];
		Registers[R_RBX] = (ULONG_PTR)CpuInfo[1];
		Registers[R_RCX] = (ULONG_PTR)CpuInfo[2];
		Registers[R_RDX] = (ULONG_PTR)CpuInfo[3];
	}

	// ??????????
	DefaultVmExitHandler(Registers);

	return VOID();
}

// ???????? CrX VM-EXIT
EXTERN_C
VOID CrAccessVtExitHandler(ULONG_PTR * Registers)
{
	CrxVmExitQualification CrxQualification = { 0 };
	CrxQualification.all = VtBase::VmCsRead(EXIT_QUALIFICATION); // ????????????

	if (CrxQualification.Bits.lmsw_operand_type == 0)
	{
		switch (CrxQualification.Bits.crn)
		{
		case 3: // ???? Cr3
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
			kprint(("CrAccessVtExitHandler: ????Cr[%d]!\r\n", CrxQualification.Bits.crn));
			break;
		}
	}

	// ??????????
	DefaultVmExitHandler(Registers);

	return VOID();
}

// ???????? VMCALL VM-EXIT
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
	case CallEptHook:	// ???? hook ??????
	{
		//KdBreakPoint();
		PVOID retaddr = VtEptHook::VtEptHookMemory(Registers[R_RDX], Registers[R_R8], 1);
		*(PVOID *)Registers[R_R9] = retaddr; // ??????????????
	}
		break;
	case CallDelEptHook: // ???? hook ??????????
		break;
	case CallExitVt: // ??????????????
	{
		DbgPrint("Debug:??Over VMCALL????????\n");

		__vmx_off(); // ??????????????

		JmpEIP = GuestRIP + ExitInstructionLength; // ???????? VM-EXIT ??????
		// ???? Rsp\Rip ?????? Guest ??
		Asm_UpdateRspAndRip(GuestRSP, JmpEIP);
	}
	break;
	default:
		break;
	}

	// ??????????
	DefaultVmExitHandler(Registers);

	return VOID();
}

// ???????? MSR VM-EXIT
EXTERN_C
VOID MsrReadVtExitHandler(ULONG_PTR * Registers)
{
	ULONGLONG MsrValue = __readmsr((ULONG)Registers[R_RCX]);
	
	switch (Registers[R_RCX])
	{
	case MSR_LSTAR: // ???? MSR RIP
	{
		KdBreakPoint();
		if (KiSystemCall64Pointer) {
			MsrValue = (ULONG_PTR)KiSystemCall64Pointer; // SSDT HOOK
		}
	}
	default:
	{
		// ????????????
		Registers[R_RAX] = LODWORD(MsrValue);
		Registers[R_RDX] = HIDWORD(MsrValue);
	}
	break;
	}

	// ??????????
	DefaultVmExitHandler(Registers);

	return VOID();
}

// ???????? MSR VM-EXIT
EXTERN_C
VOID MsrWriteVtExitHandler(ULONG_PTR * Registers)
{
	ULONGLONG MsrValue = MAKEQWORD(Registers[R_RAX], Registers[R_RDX]);

	switch (Registers[R_RCX])
	{
	case IA32_SYSENTER_EIP: // ???? MSR 0x176
	case IA32_SYSENTER_ESP: // ???? MSR 0x175
	case IA32_SYSENTER_CS:	// ???? MSR 0x174
	default:
	{
		// ????????????
		__writemsr((ULONG)Registers[R_RCX], MsrValue);
	}
	break;
	}

	// ??????????
	DefaultVmExitHandler(Registers);

	return VOID();
}

// ???????? Nmi ???? (????????????)
EXTERN_C
VOID NmiExceptionVtExitHandler(ULONG_PTR * Registers)
{
	UNREFERENCED_PARAMETER(Registers);

	VmxVmExit_Interrupt_info exception = { 0 }; // ????????????????
	InterruptionType interruption_type = InterruptionType::kExternalInterrupt; // ??????????
	InterruptionVector vector = InterruptionVector::EXCEPTION_VECTOR_DIVIDE_ERROR;
	ULONG32 error_code_valid = 0;

	/*
		"????????????" ???????????? VM-exit ??????????????????????????
		(1). ???????????????????????????? exception bitmap ??????????1?????????? VM-exit.
		(2). ????????(#BP??#OF)???????????????????? exception bitmap ??????????1?????????? VM-exit.
		(3). ????????????????????????????, ????"exception-interrupt exiting"??1?????????? VM-exit.
		(4). NMI??????NMI??????, ????"NMI exiting"??1?????????? VM-exit.
	*/

	// ??????????, ???? VM-Exit Interruption-Information ????
	exception.all = static_cast<ULONG32>(VtBase::VmCsRead(VM_EXIT_INTR_INFO));

	interruption_type = static_cast<InterruptionType>(exception.Bits.interruption_type); // ????????????
	vector = static_cast<InterruptionVector>(exception.Bits.vector); // ??????????????
	error_code_valid = exception.Bits.error_code_valid; // ????????????

	if (interruption_type == InterruptionType::kHardwareException)
	{
		// ??????????????, ????????????????????
		if (vector == InterruptionVector::EXCEPTION_VECTOR_PAGE_FAULT)
		{
			// ?????? #PF ????
			// exit qualification ???????????? #PF ???????????????? (????????????????????????(??3.10.1.6??))
			auto fault_address = VtBase::VmCsRead(EXIT_QUALIFICATION);

			// VM-exit interruption error code ???????????? Page-Fault Error Code (????????????????????????(??3.10.2??))
			PageFaultErrorCode fault_code = { 0 };
			fault_code.all = static_cast<ULONG32>(VtBase::VmCsRead(VM_EXIT_INTR_ERROR_CODE));

			// ????????????????????????
			VtEvent::VtInjectInterruption(interruption_type, vector, true, fault_code.all);

			//kprint(("[+] #PF ????!\r\n"));

			// ???????? cr2 ??????
			__writecr2(fault_address);

			VtBase::VmCsWrite(VM_ENTRY_INTR_INFO, exception.all);

			if (error_code_valid) {
				VtBase::VmCsWrite(VM_ENTRY_EXCEPTION_ERROR_CODE, VtBase::VmCsRead(VM_EXIT_INTR_ERROR_CODE));
			}

		}
		else if (vector == InterruptionVector::EXCEPTION_VECTOR_GENERAL_PROTECTION){
			// ?????? #GP ????

			auto error_code = VtBase::VmCsRead(VM_EXIT_INTR_ERROR_CODE);

			// ????????????????????????
			VtEvent::VtInjectInterruption(interruption_type, vector, true, (ULONG32)error_code);

			//kprint(("[+] #GP ????!\r\n"));
		}
		else if (vector == InterruptionVector::EXCEPTION_VECTOR_INVALID_OPCODE) {
			// ?????? #UD ????

			/*
				?????????? SysCall/SysRet ????
			*/
			if (!VtSsdtHook::UdExceptionVtExitHandler(Registers)) {

				/*
					???????????????? #UD
				*/
				VtEvent::VtInjectInterruption(interruption_type, vector, false, 0);
			}
		}
	}
	else if (interruption_type == InterruptionType::kSoftwareException) {
		// ?????? ????????
		if (vector == InterruptionVector::EXCEPTION_VECTOR_BREAKPOINT)
		{
			// #BP
			// int3 ??????????????, ????????????????
			// ????????????????????????
			VtEvent::VtInjectInterruption(interruption_type, vector, false, 0);
			auto exit_inst_length = VtBase::VmCsRead(VM_EXIT_INSTRUCTION_LEN); // ???????? VM-exit ??????????
			VtBase::VmCsWrite(VM_ENTRY_INSTRUCTION_LEN, exit_inst_length);

			//kprint(("[+] #BP ????!\r\n"));
		}
	}
	else {
		//kprint(("[+] interruption_type:[%d]; vector:[%d] ????!\r\n", interruption_type, vector));
		VtBase::VmCsWrite(VM_ENTRY_INTR_INFO, exception.all);

		if (error_code_valid) {
			VtBase::VmCsWrite(VM_ENTRY_EXCEPTION_ERROR_CODE, VtBase::VmCsRead(VM_EXIT_INTR_ERROR_CODE));
		}
	}
}

// ???????? ????????
EXTERN_C
VOID ExternalInterruptVtExitHandler(ULONG_PTR * Registers)
{
	DefaultVmExitHandler(Registers);
}

// ?????? GDT/IDT ?????????? VM-exit
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

	// ???????????? (????????????????????????(??3.10.1.4??))
	ULONG_PTR displacement = VtBase::VmCsRead(EXIT_QUALIFICATION);
	// ????????????????
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
		//kprint(("????????????????!\r\n"));
		return VOID();
	}

	if (!index_register_invalid && (index_register < 16)) {
		// ??????????????????, ????????????????
		if (scalling) index_address = 0;
		else {
			// ????????
			index_address = Registers[index_register] << scalling;
		}
	}

	if (!base_register_invalid && (base_register < 16)) {
		// ????????????????
		base_address = Registers[base_register];
	}

	// ?????????????? (?????????????????? ring3 ????????)
	total_address = VtBase::VmCsRead(GUEST_ES_BASE + segment_register * 2) + base_address + index_address + displacement;
	// ???????????????????????????????????? ring0
	
	// ?????????????????? ??0-SGDT??1-SIDT??2-LGDT??3-LIDT??
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

	// ??????????
	DefaultVmExitHandler(Registers);
	return VOID();
}

// ?????? LDT/TR ?????????? VM-exit
EXTERN_C
VOID LdtrOrTrAccessVtExitHandler(ULONG_PTR * Registers)
{
	UNREFERENCED_PARAMETER(Registers);
	//KdBreakPoint();
	/*

	*/

	// ???????????? (????????????????????????(??3.10.1.4??))
	ULONG_PTR displacement = VtBase::VmCsRead(EXIT_QUALIFICATION);
	// ????????????????
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
	
	// ??????????????
	if (register_access) {
		// ??????????????????????
		// ????????????????
		switch (instruction_identity) //??0-SLDT??1-STR??2-LLDT??3-LTR??
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
		// ????????????????????
		if (segment_register > 5) {
			//kprint(("????????????????!\r\n"));
			return VOID();
		}

		ULONG_PTR base_address = 0;
		ULONG_PTR index_address = 0;
		ULONG_PTR total_address = 0;

		if (!index_register_invalid && (index_register < 16)) {
			// ??????????????????, ????????????????
			if (scalling) index_address = 0;
			else {
				// ????????
				index_address = Registers[index_register] << scalling;
			}
		}

		if (!base_register_invalid && (base_register < 16)) {
			// ????????????????
			base_address = Registers[base_register];
		}

		// ?????????????? (?????????????????? ring3 ????????)
		total_address = VtBase::VmCsRead(GUEST_ES_BASE + segment_register * 2) + base_address + index_address + displacement;

		switch (instruction_identity) //??0-SLDT??1-STR??2-LLDT??3-LTR??
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

	// ??????????
	DefaultVmExitHandler(Registers);

	return VOID();
}

// ???????????? VM-EXIT
EXTERN_C
VOID DefaultVmExitHandler(ULONG_PTR * Registers)
{
	//ULONG_PTR exitReason = VtBase::VmCsRead(VM_EXIT_REASON); // ???? VM-exit ????
	ULONG_PTR guestRip = VtBase::VmCsRead(GUEST_RIP);
	ULONG_PTR guestRsp = VtBase::VmCsRead(GUEST_RSP);
	ULONG_PTR exitInstructionLength = VtBase::VmCsRead(VM_EXIT_INSTRUCTION_LEN); // ??????????????

	UNREFERENCED_PARAMETER(Registers);

	VtBase::VmCsWrite(GUEST_RIP, guestRip + exitInstructionLength);
	VtBase::VmCsWrite(GUEST_RSP, guestRsp);

	return VOID();
}
