#include "VtBase.h"
#include "VtEpt.h"

extern  VtEpt *g_Ept;

VtBase::VtBase()
{
	GuestRip = GuestRsp = 0;
	m_CpuNumber = 0;
	m_VmxOn = FALSE; // 当前 CPU 核的虚拟化是否打开
	m_VmOnRegionAddress = 0;     // VMON 区域
	m_VmCsRegionAddress = 0;     // VMCS 区域
	m_VmBitMapRegionAddress = 0; // VM BITMAP 区域
	m_VmOnRegionPhyAddress = 0;    // 对应的物理地址
	m_VmCsRegionPhyAddress = 0;
	m_VmMsrBitMapRegionPhyAddress = 0;
	m_VmStackRootRegionPointer = 0;// VMM 所需要的堆栈内存
	m_HostState = {0};  // HOST  环境
	m_GuestState = {0}; // GUEST 环境
	VtIsUseEpt = FALSE; // 是否使用 EPT
}

VtBase::~VtBase()
{}

// VMCS 区域的读入
// @info: 要写入的字段
// @Value: 要写入的值
// @return 返回 ULONG_PTR 的 VMCS 信息, 不成功为 FALSE
BOOLEAN VtBase::VmCsWrite(ULONG_PTR info, ULONG_PTR Value)
{
	ULONG_PTR uinfo = info;

	if (__vmx_vmwrite(uinfo, Value) != 0)
	{
		__debugbreak();
		kprint(("VmcsField: [0x%016x] 调用vmwrite失败!\n", info));
		return FALSE;
	}

	return TRUE;
}

// VMCS 区域的读取
// @info: 要读取的字段
// @return 返回 ULONG_PTR 的 VMCS 信息, 不成功为 -1
ULONG_PTR VtBase::VmCsRead(ULONG_PTR info)
{
	ULONG_PTR value = 0xFFFFFFFFFFFFFFFF;
	ULONG_PTR uinfo = info;

	if (__vmx_vmread(uinfo, &value) != 0)
	{
		__debugbreak();
		kprint(("Vmx [0x%016x] 调用vmread失败!\n", info));
		return value;
	}

	return value;
}

// 执行 VMON 指令
// @return 执行成功返回 TRUE
BOOLEAN VtBase::ExecuteVmxOn()
{
	ULONG_PTR m_VmxBasic = __readmsr(IA32_VMX_BASIC_MSR_CODE); // 获取 VMID
	// 1. 填充版本号 VMID
	*(PULONG32)m_VmOnRegionAddress = (ULONG32)m_VmxBasic;
	*(PULONG32)m_VmCsRegionAddress = (ULONG32)m_VmxBasic;

	// 2. 设置CR4
	Cr4 cr4 = { 0 };
	cr4.all = __readcr4();
	cr4.Bits.vmxe = TRUE; // CR4.VMXE 置为 1, 解锁 VMX 指令
	__writecr4(cr4.all);

	// 3. 对每个 CPU 开启 VMXON 指令限制
	Ia32FeatureControlMsr msr = { 0 };
	msr.all = __readmsr(IA32_FEATURE_CONTROL_CODE);
	if (!msr.Bits.lock)
	{
		msr.Bits.lock = TRUE;		  // 启用 VMON
		msr.Bits.enable_vmxon = TRUE; // 启用 VMON
		__writemsr(IA32_FEATURE_CONTROL_CODE, msr.all);
	}

	// 4. 执行 VMON 指令
	// VMXON 该指令会检查:
	// 1). VMXON 指针是否超过物理地址宽度, 并且是否 4K 对齐
	// 2). VMXON 区域的头 DWORD 值是否符合 VMCS ID
	// 3). 最后会将该物理地址作为指针，指向 VMXON 区域
	// 4). 最终可通过 eflags.cf 是否为 0 来判断执行成功
	__vmx_on(&m_VmOnRegionPhyAddress);

	FlagRegister eflags = { 0 };
	*(ULONG_PTR*)(&eflags) = __readeflags();
	if (eflags.Bits.cf != 0)
	{
		kprint(("Cpu:[%d] vmxon 启动失败!\n", m_CpuNumber));
		return FALSE;
	}

	kprint(("[+]Cpu:[%d] vmxon 启动成功!\n", m_CpuNumber));
	m_VmxOn = TRUE; // 打亮 VT 虚拟化标志

	// 5. 执行 VMCLEAR 指令来初始化 VMCS 控制块的特定信息
	// 传入 VMCS 区域的物理地址
	VtDbgErrorPrint(__vmx_vmclear(&m_VmCsRegionPhyAddress), "vmclear");
	// 6. 执行 VMPTRLD 指令激活 VMCS 区域
	VtDbgErrorPrint(__vmx_vmptrld(&m_VmCsRegionPhyAddress), "vmptrld");

	kprint(("[+]Debug:[%d] VMCS 装载成功\n", m_CpuNumber));
	return TRUE;
}

// 检测是否能启用 VT
// @return 可以启用返回 TRUE，否则 FALSE
BOOLEAN VtBase::VtCheckIsSupported()
{
	// 检测当前 CPUD 是否支持 VT 技术
	// EAX = 1; CPUID.1:ECX.VMX[bit 5] 是否为 1
	unsigned __int32 Regs[4] = { 0 }; // EAX，EBX，ECX和EDX
	__cpuidex(reinterpret_cast<int *>(Regs), 1, 1);
	pCpudFeatureInfoByEcx pRcx = reinterpret_cast<pCpudFeatureInfoByEcx>(&Regs[2]);
	
	if (pRcx->Bits.vmx == FALSE)
	{
		return FALSE; // 不支持虚拟化
	}

	// 检测 VMXON 指令能否执行
	// VMXON 指令能否执行也是受 IA32_FEATURE_CONTROL_MSR 寄存器的控制
	// IA32_FEATURE_CONTROL_MSR[bit 0] 为 0, 则 VMXON 不能调用
	// IA32_FEATURE_CONTROL_MSR[bit 2] 为 0, 则 VMXON 不能在 SMX 操作系统外调用
	ULONG_PTR uMsr = __readmsr(IA32_FEATURE_CONTROL_CODE);
	pIa32FeatureControlMsr pMsr = reinterpret_cast<pIa32FeatureControlMsr>(&uMsr);

	if ((pMsr->Bits.lock == FALSE) && (pMsr->Bits.enable_vmxon == FALSE))
	{
		return FALSE;
	}

	return TRUE;
}

// 检测虚拟化开关是否打开
// @return 虚拟化开关打开返回 TRUE，否则 FALSE
BOOLEAN VtBase::VtCheckIsEnable()
{
	// 开启虚拟机时，会将 CR4.VMXE[bit 13] 置为 1
	ULONG_PTR uCr4 = __readcr4();
	pCr4 Cr4Pointer = reinterpret_cast<pCr4>(&uCr4);

	if (Cr4Pointer->Bits.vmxe == TRUE)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

// 申请 VMON\VMCS 内存地址
// @return 申请成功返回 TRUE，否则 FALSE
BOOLEAN VtBase::VtVmmMemAllocate()
{
	// VMM 内存的申请
	m_VmOnRegionAddress = (ULONG_PTR *)kmalloc(PAGE_SIZE);
	m_VmCsRegionAddress = (ULONG_PTR *)kmalloc(PAGE_SIZE);
	m_VmBitMapRegionAddress = (ULONG_PTR *)kmalloc(PAGE_SIZE);
	m_VmStackRootRegionPointer = (ULONG_PTR)kmalloc(PAGE_SIZE * 10);

	if (!m_VmOnRegionAddress || !m_VmCsRegionAddress || !m_VmBitMapRegionAddress || !m_VmStackRootRegionPointer)
	{
		VtVmmMemFree();
		return FALSE;
	}

	m_VmOnRegionPhyAddress = MmGetPhysicalAddress(m_VmOnRegionAddress).QuadPart;
	m_VmCsRegionPhyAddress = MmGetPhysicalAddress(m_VmCsRegionAddress).QuadPart;
	m_VmMsrBitMapRegionPhyAddress = MmGetPhysicalAddress(m_VmBitMapRegionAddress).QuadPart;

	if (!m_VmOnRegionPhyAddress || !m_VmCsRegionPhyAddress || !m_VmMsrBitMapRegionPhyAddress)
	{
		VtVmmMemFree();
		return FALSE;
	}

	kprint(("Cpu:[%d] Vt 内存初始化成功!\r\n", m_CpuNumber));

	return TRUE;
}

// 释放 VMM 内存
VOID VtBase::VtVmmMemFree()
{
	if (m_VmOnRegionAddress)
	{
		kFree(m_VmOnRegionAddress);
		m_VmOnRegionAddress = NULL;
	}

	if (m_VmCsRegionAddress)
	{
		kFree(m_VmCsRegionAddress);
		m_VmCsRegionAddress = NULL;
	}

	if (m_VmBitMapRegionAddress)
	{
		kFree(m_VmBitMapRegionAddress);
		m_VmBitMapRegionAddress = NULL;
	}

	if (m_VmStackRootRegionPointer)
	{
		kFree((PVOID)m_VmStackRootRegionPointer);
		m_VmStackRootRegionPointer = NULL;
	}
}

// 设置 VMCS 区域
BOOLEAN VtBase::SetupVmcs()
{
	if (m_VmxOn)
	{
		kprint(("[+]Cpu:[%d] 虚拟化【正在运行】!\n", m_CpuNumber));
		return FALSE;
	}

	BOOLEAN retbool = TRUE;
	
	kprint(("Cpu:[%d] 设置VMCS区域\r\n", m_CpuNumber));

	// 2. 初始化 Guest 和 Host 环境
	KdBreakPoint();
	// (1). 配置 Guest 状态
	m_GuestState.cs = __readcs();
	m_GuestState.ds = __readds();
	m_GuestState.ss = __readss();
	m_GuestState.es = __reades();
	m_GuestState.fs = __readfs();
	m_GuestState.gs = __readgs();

	m_GuestState.ldtr = __sldt();
	m_GuestState.tr = __str();
	m_GuestState.rflags = __readeflags();

	m_GuestState.rsp = GuestRsp; // 设置 GUEST 的 RSP、RIP
	m_GuestState.rip = GuestRip; 

	__sgdt(&(m_GuestState.gdt));
	__sidt(&(m_GuestState.idt));

	m_GuestState.cr3 = __readcr3();
	m_GuestState.cr0 = ((__readcr0() & __readmsr(IA32_VMX_CR0_FIXED1)) | __readmsr(IA32_VMX_CR0_FIXED0));
	m_GuestState.cr4 = ((__readcr4() & __readmsr(IA32_VMX_CR4_FIXED1)) | __readmsr(IA32_VMX_CR4_FIXED0));

	m_GuestState.dr7 = __readdr(7);
	m_GuestState.msr_debugctl = __readmsr(IA32_DEBUGCTL);
	m_GuestState.msr_sysenter_cs = __readmsr(IA32_SYSENTER_CS);
	m_GuestState.msr_sysenter_eip = __readmsr(IA32_SYSENTER_EIP);
	m_GuestState.msr_sysenter_esp = __readmsr(IA32_SYSENTER_ESP);

	__writecr0(m_GuestState.cr0);
	__writecr4(m_GuestState.cr4);

	m_GuestState.msr_efer = __readmsr(MSR_IA32_EFER); // 填充 Guest EFER

	// (2). 初始化 Host 状态
	m_HostState.cr0 = __readcr0();
	m_HostState.cr3 = __readcr3();
	m_HostState.cr4 = __readcr4();

	m_HostState.cs = __readcs() & 0xF8;
	m_HostState.ds = __readds() & 0xF8;
	m_HostState.ss = __readss() & 0xF8;
	m_HostState.es = __reades() & 0xF8;
	m_HostState.fs = __readfs() & 0xF8;
	m_HostState.gs = __readgs() & 0xF8;
	m_HostState.tr = __str();

	m_HostState.rsp = ROUNDUP((m_VmStackRootRegionPointer + 0x2000), PAGE_SIZE); // 设置 HOST 的 RSP、RIP
	m_HostState.rip = reinterpret_cast<ULONG_PTR>(Asm_VmExitHandler);

	m_HostState.msr_sysenter_cs = __readmsr(IA32_SYSENTER_CS);
	m_HostState.msr_sysenter_eip = __readmsr(IA32_SYSENTER_EIP);
	m_HostState.msr_sysenter_esp = __readmsr(IA32_SYSENTER_ESP);

	m_HostState.msr_efer = __readmsr(MSR_IA32_EFER); // 填充 Host EFER

	__sgdt(&(m_HostState.gdt));
	__sidt(&(m_HostState.idt));

	// 3. Setup Vmx
	// 简化设置 VMCS 区域
	retbool = InitVmcs();
	if (!retbool) return retbool;

	// 4. 填写 VMCS 中的 GUEST 状态
	// (1). CS\SS\DS\ES\FS\GS\TR 寄存器
	ULONG_PTR uBase, uLimit, uAccess;
	GetSelectorInfoBySelector(m_GuestState.cs, &uBase, &uLimit, &uAccess);
	retbool &= VmCsWrite(GUEST_CS_SELECTOR, m_GuestState.cs);
	retbool &= VmCsWrite(GUEST_CS_LIMIT, uLimit);
	retbool &= VmCsWrite(GUEST_CS_AR_BYTES, uAccess);
	retbool &= VmCsWrite(GUEST_CS_BASE, uBase);

	GetSelectorInfoBySelector(m_GuestState.ss, &uBase, &uLimit, &uAccess);
	retbool &= VmCsWrite(GUEST_SS_SELECTOR, m_GuestState.ss);
	retbool &= VmCsWrite(GUEST_SS_LIMIT, uLimit);
	retbool &= VmCsWrite(GUEST_SS_AR_BYTES, uAccess);
	retbool &= VmCsWrite(GUEST_SS_BASE, uBase);

	GetSelectorInfoBySelector(m_GuestState.ds, &uBase, &uLimit, &uAccess);
	retbool &= VmCsWrite(GUEST_DS_SELECTOR, m_GuestState.ds);
	retbool &= VmCsWrite(GUEST_DS_LIMIT, uLimit);
	retbool &= VmCsWrite(GUEST_DS_AR_BYTES, uAccess);
	retbool &= VmCsWrite(GUEST_DS_BASE, uBase);

	GetSelectorInfoBySelector(m_GuestState.es, &uBase, &uLimit, &uAccess);
	retbool &= VmCsWrite(GUEST_ES_SELECTOR, m_GuestState.es);
	retbool &= VmCsWrite(GUEST_ES_LIMIT, uLimit);
	retbool &= VmCsWrite(GUEST_ES_AR_BYTES, uAccess);
	retbool &= VmCsWrite(GUEST_ES_BASE, uBase);
	retbool &= VmCsWrite(HOST_ES_SELECTOR, m_HostState.es);

	GetSelectorInfoBySelector(m_GuestState.fs, &uBase, &uLimit, &uAccess);
	retbool &= VmCsWrite(GUEST_FS_SELECTOR, m_GuestState.fs);
	retbool &= VmCsWrite(GUEST_FS_LIMIT, uLimit);
	retbool &= VmCsWrite(GUEST_FS_AR_BYTES, uAccess);
	retbool &= VmCsWrite(GUEST_FS_BASE, uBase);
	m_HostState.fsbase = uBase;


	GetSelectorInfoBySelector(m_GuestState.gs, &uBase, &uLimit, &uAccess);
	retbool &= VmCsWrite(GUEST_GS_SELECTOR, m_GuestState.gs);
	uBase = __readmsr(MSR_GS_BASE);
	retbool &= VmCsWrite(GUEST_GS_LIMIT, uLimit);
	retbool &= VmCsWrite(GUEST_GS_AR_BYTES, uAccess);
	retbool &= VmCsWrite(GUEST_GS_BASE, uBase);
	m_HostState.gsbase = uBase;

	GetSelectorInfoBySelector(m_GuestState.tr, &uBase, &uLimit, &uAccess);
	retbool &= VmCsWrite(GUEST_TR_SELECTOR, m_GuestState.tr);
	retbool &= VmCsWrite(GUEST_TR_LIMIT, uLimit);
	retbool &= VmCsWrite(GUEST_TR_AR_BYTES, uAccess);
	retbool &= VmCsWrite(GUEST_TR_BASE, uBase);
	m_HostState.trbase = uBase;

	GetSelectorInfoBySelector(m_GuestState.ldtr, &uBase, &uLimit, &uAccess);
	retbool &= VmCsWrite(GUEST_LDTR_SELECTOR, m_GuestState.ldtr);
	retbool &= VmCsWrite(GUEST_LDTR_LIMIT, uLimit);
	retbool &= VmCsWrite(GUEST_LDTR_AR_BYTES, uAccess);
	retbool &= VmCsWrite(GUEST_LDTR_BASE, uBase);

	// (2). GDTR\IDTR 信息
	retbool &= VmCsWrite(GUEST_GDTR_BASE, m_GuestState.gdt.uBase);
	retbool &= VmCsWrite(GUEST_GDTR_LIMIT, m_GuestState.gdt.uLimit);

	retbool &= VmCsWrite(GUEST_IDTR_BASE, m_GuestState.idt.uBase);
	retbool &= VmCsWrite(GUEST_IDTR_LIMIT, m_GuestState.idt.uLimit);

	// (3). 控制寄存器 CR0\CR3\CR4
	retbool &= VmCsWrite(GUEST_CR0, m_GuestState.cr0);
	retbool &= VmCsWrite(GUEST_CR3, m_GuestState.cr3);
	retbool &= VmCsWrite(CR0_READ_SHADOW, m_GuestState.cr0);

	retbool &= VmCsWrite(GUEST_CR4, m_GuestState.cr4);
	retbool &= VmCsWrite(CR4_READ_SHADOW, m_GuestState.cr4);

	// (4). RSP\RIP 和 RFLAGS、DR7
	retbool &= VmCsWrite(GUEST_IA32_DEBUGCTL, m_GuestState.msr_debugctl);
	retbool &= VmCsWrite(GUEST_DR7, m_GuestState.dr7);
	retbool &= VmCsWrite(GUEST_RSP, m_GuestState.rsp);
	retbool &= VmCsWrite(GUEST_RIP, m_GuestState.rip);
	retbool &= VmCsWrite(GUEST_RFLAGS, m_GuestState.rflags);

	retbool &= VmCsWrite(GUEST_EFER, m_GuestState.msr_efer);

	if (!retbool) return FALSE; // 一个不成功返回FALSE

	// 5. 初始化宿主机(HOST)状态
	retbool &= VmCsWrite(HOST_CS_SELECTOR, m_HostState.cs);
	retbool &= VmCsWrite(HOST_SS_SELECTOR, m_HostState.ss);
	retbool &= VmCsWrite(HOST_DS_SELECTOR, m_HostState.ds);

	retbool &= VmCsWrite(HOST_FS_BASE, m_HostState.fsbase);
	retbool &= VmCsWrite(HOST_FS_SELECTOR, m_HostState.fs);

	retbool &= VmCsWrite(HOST_GS_BASE, m_HostState.gsbase);
	retbool &= VmCsWrite(HOST_GS_SELECTOR, m_HostState.gs);

	retbool &= VmCsWrite(HOST_TR_BASE, m_HostState.trbase);
	retbool &= VmCsWrite(HOST_TR_SELECTOR, m_HostState.tr);

	retbool &= VmCsWrite(HOST_GDTR_BASE, m_HostState.gdt.uBase);
	retbool &= VmCsWrite(HOST_IDTR_BASE, m_HostState.idt.uBase);

	retbool &= VmCsWrite(HOST_CR0, m_HostState.cr0);
	retbool &= VmCsWrite(HOST_CR4, m_HostState.cr4);
	retbool &= VmCsWrite(HOST_CR3, m_HostState.cr3);

	retbool &= VmCsWrite(HOST_RIP, m_HostState.rip);
	retbool &= VmCsWrite(HOST_RSP, m_HostState.rsp);

	retbool &= VmCsWrite(HOST_EFER, m_HostState.msr_efer);

	kprint(("[+]Cpu:[%d] 设置 VMCS 区域完毕\n", m_CpuNumber));

	return retbool;
}

// 简化并设置 VMCS MSR 区域
BOOLEAN VtBase::InitVmcs()
{
	// 3. Setup Vmx
	// 执行 vmxon/vmclear/vmptrld 初始化并激活 VMCS 区域

	BOOLEAN isEnable = TRUE;
	isEnable &= ExecuteVmxOn();
	if (!isEnable)
	{
		kprint(("Cpu:[%d] VMXON失败!\n", m_CpuNumber));
		return FALSE;
	}
	
	// 1. 配置基于pin的vm执行控制信息域 【Pin-Based VM-Execution Controls】
	Ia32VmxBasicMsr ia32basicMsr = { 0 };
	ia32basicMsr.all = __readmsr(MSR_IA32_VMX_BASIC);

	VmxPinBasedControls vm_pinctl_requested = { 0 }; // 用于设置 Pin-Based VM-Execution Controls
	//vm_pinctl_requested.Bits.nmi_exiting = TRUE; // 拦截 Nmi 中断
	// 参见白皮书 (A-2 Vol. 3D)、【处理器虚拟化技术】(第2.5节)
	// 如果IA32_VMX_BASIC MSR中的位55被读取为1，则使用 MSR_IA32_VMX_TRUE_PINBASED_CTLS 
	VmxPinBasedControls vm_pinctl = {
		VmxAdjustControlValue((ia32basicMsr.Bits.vmx_capability_hint) ? MSR_IA32_VMX_TRUE_PINBASED_CTLS : MSR_IA32_VMX_PINBASED_CTLS,
								vm_pinctl_requested.all)};		    // 最终 Pin-Based VM-Execution Controls 的值
	isEnable &= VmCsWrite(PIN_BASED_VM_EXEC_CONTROL, vm_pinctl.all); // 设置 Pin-Based VM-Execution Controls
	
	// 2. 配置基于处理器的主vm执行控制信息域 【Primary Processor-Based VM-Execution Controls】
	VmxProcessorBasedControls vm_procctl_requested = { 0 }; // 用于设置 Primary Processor-Based VM-Execution Controls
	//vm_procctl_requested.Bits.cr3_load_exiting = TRUE;	// 拦截写入Cr3
	//vm_procctl_requested.Bits.cr3_store_exiting = TRUE;	// 拦截读取Cr3
	vm_procctl_requested.Bits.use_msr_bitmaps = TRUE;		// 启用MSR bitmap, 拦截msr寄存器访问,必须设置,不然任何访msr的操作都会导致vmexit
	vm_procctl_requested.Bits.activate_secondary_control = TRUE; // 启用扩展字段
	VmxProcessorBasedControls vm_procctl = {
		VmxAdjustControlValue((ia32basicMsr.Bits.vmx_capability_hint) ? MSR_IA32_VMX_TRUE_PROCBASED_CTLS : MSR_IA32_VMX_PROCBASED_CTLS,
								vm_procctl_requested.all)}; // 最终 Primary Processor-Based VM-Execution Controls 的值
	isEnable &= VmCsWrite(CPU_BASED_VM_EXEC_CONTROL, vm_procctl.all);

	// 3. 配置基于处理器的辅助vm执行控制信息域的扩展字段 【Secondary Processor-Based VM-Execution Controls】
	VmxSecondaryProcessorBasedControls vm_procctl2_requested = { 0 };
	//vm_procctl2_requested.Bits.descriptor_table_exiting = TRUE;	// 拦截 LGDT, LIDT, LLDT, LTR, SGDT, SIDT, SLDT, STR.
	vm_procctl2_requested.Bits.enable_rdtscp = TRUE;		 // for Win10
	vm_procctl2_requested.Bits.enable_invpcid = TRUE;		 // for Win10
	vm_procctl2_requested.Bits.enable_xsaves_xstors = TRUE;	 // for Win10

	// 这里看是否需要启动 EPT
	if (VtIsUseEpt) {
		vm_procctl2_requested.Bits.enable_ept = TRUE;  // 开启 EPT
		vm_procctl2_requested.Bits.enable_vpid = TRUE; // 开启 VPID
												// (VPID用于区分TLB项属于者, 关于VPID参考【系统虚拟化:原理与实现】(第139页)、白皮书(Vol. 3C 28-1))
	}
	VmxSecondaryProcessorBasedControls vm_procctl2 = { VmxAdjustControlValue(
		MSR_IA32_VMX_PROCBASED_CTLS2, vm_procctl2_requested.all) };
	isEnable &= VmCsWrite(SECONDARY_VM_EXEC_CONTROL, vm_procctl2.all);

	// 4. 配置vm-entry控制域
	VmxVmEntryControls vm_entryctl_requested = { 0 };
	vm_entryctl_requested.Bits.load_ia32_efer = TRUE;   // 启用 EFER 寄存器
	vm_entryctl_requested.Bits.ia32e_mode_guest = TRUE; // 64系统必须填, 参考【处理器虚拟化技术】(第212页)
	VmxVmEntryControls vm_entryctl = { VmxAdjustControlValue(
		(ia32basicMsr.Bits.vmx_capability_hint) ? MSR_IA32_VMX_TRUE_ENTRY_CTLS : MSR_IA32_VMX_ENTRY_CTLS,
		vm_entryctl_requested.all) };
	isEnable &= VmCsWrite(VM_ENTRY_CONTROLS, vm_entryctl.all);

	// 5. 配置vm-exit控制信息域
	VmxVmExitControls vm_exitctl_requested = { 0 };
	vm_exitctl_requested.Bits.load_ia32_efer = TRUE;
	vm_exitctl_requested.Bits.save_ia32_efer = TRUE;
	vm_exitctl_requested.Bits.acknowledge_interrupt_on_exit = TRUE;
	vm_exitctl_requested.Bits.host_address_space_size = TRUE; // 64系统必须填, 参考【处理器虚拟化技术】(第219页)
	VmxVmExitControls vm_exitctl = { VmxAdjustControlValue(
		(ia32basicMsr.Bits.vmx_capability_hint) ? MSR_IA32_VMX_TRUE_EXIT_CTLS : MSR_IA32_VMX_EXIT_CTLS,
		vm_exitctl_requested.all) };
	isEnable &= VmCsWrite(VM_EXIT_CONTROLS, vm_exitctl.all);

	/*
		填写 MsrBitMap (参考白皮书 24-14 Vol. 3C)
	*/

	// MSR - Read - BitMap
	PUCHAR msr_bit_map_read_low = (PUCHAR)m_VmBitMapRegionAddress;	// 0x00000000 - 0x00001FFF
	PUCHAR msr_bit_map_read_higt = msr_bit_map_read_low + 1024;		// 0xC0000000 - 0xC0001FFF
	RTL_BITMAP msr_bit_map_read_low_rtl = { 0 };
	RTL_BITMAP msr_bit_map_read_higt_rtl = { 0 };
	// 初始化msr read bitmap数据区
	RtlInitializeBitMap(&msr_bit_map_read_low_rtl, (PULONG)msr_bit_map_read_low, 1024 * 8);
	RtlInitializeBitMap(&msr_bit_map_read_higt_rtl, (PULONG)msr_bit_map_read_higt, 1024 * 8);
	// 设置msr read bitmap数据区
	RtlSetBit(&msr_bit_map_read_higt_rtl, MSR_LSTAR - 0xC0000000);     // MSR_LSTAR 支持 syscall sysret
	RtlSetBit(&msr_bit_map_read_higt_rtl, MSR_IA32_EFER - 0xC0000000);	// 设置 EFER 的写入, 产生 VM-exit

	// MSR - Write - BitMap
	PUCHAR msr_bit_map_write_low = (PUCHAR)m_VmBitMapRegionAddress + 1024 * 2;	// 0x00000000 - 0x00001FFF
	PUCHAR msr_bit_map_write_higt = msr_bit_map_write_low + 1024;				// 0xC0000000 - 0xC0001FFF
	RTL_BITMAP msr_bit_map_write_low_rtl = { 0 };
	RTL_BITMAP msr_bit_map_write_higt_rtl = { 0 };
	// 初始化msr write bitmap数据区
	RtlInitializeBitMap(&msr_bit_map_write_low_rtl, (PULONG)msr_bit_map_write_low, 1024 * 8);
	RtlInitializeBitMap(&msr_bit_map_write_higt_rtl, (PULONG)msr_bit_map_write_higt, 1024 * 8);
	// 设置msr read bitmap数据区
	RtlSetBit(&msr_bit_map_read_higt_rtl, MSR_IA32_EFER - 0xC0000000);	// 设置 EFER 的写入, 产生 VM-exit

	 // VMX MSRs
	for (ULONG i = MSR_IA32_VMX_BASIC; i <= MSR_IA32_VMX_VMFUNC; i++)
		RtlSetBit(&msr_bit_map_read_low_rtl, i);
	isEnable &= VmCsWrite(MSR_BITMAP, m_VmMsrBitMapRegionPhyAddress);    // 位图
	
	/*
		填写 ExceptionBitMap
	*/
	ULONG_PTR exception_bitmap = 0;
	exception_bitmap |= (1 << InterruptionVector::EXCEPTION_VECTOR_INVALID_OPCODE); // 设置拦截 #UD 异常(产生 VM-exit)
	isEnable &= VmCsWrite(EXCEPTION_BITMAP, exception_bitmap);

	// VMCS link pointer 字段初始化
	ULONG_PTR link_pointer = 0xFFFFFFFFFFFFFFFFL;
	isEnable &= VmCsWrite(VMCS_LINK_POINTER, link_pointer);
	
	// Ept 初始化和填充EPTP
	if (VtIsUseEpt)
	{
		isEnable &= VmCsWrite(EPT_POINTER, g_Ept->m_Eptp.all);	// 填写 EptPointer	
		ULONG processor = KeGetCurrentProcessorNumberEx(NULL);
		isEnable &= VmCsWrite(VIRTUAL_PROCESSOR_ID, processor + 1); // VIRTUAL_PROCESSOR_ID的值为CurrentProcessorNumber+0x1
	}

	return isEnable;
}

// 启用 VT
// @return
BOOLEAN VtBase::VtEnable()
{
	kprint(("[+]Cpu:[%d] 支持虚拟化!\n", m_CpuNumber));
	
	// 申请 VMON\VMCS 内存地址
	if (!VtVmmMemAllocate())
	{
		kprint(("Cpu:[%d] 申请 VMON、VMCS 内存地址ERROR!\n", m_CpuNumber));
		return FALSE;
	}

	if (!m_VmxOn)
	{
		// 没有启动 VT, 先设置 GUEST 的 RSP\RIP
		kprint(("Cpu:[%d] 没有启动 VT, 先设置 GUEST 的 RSP、RIP!\n", m_CpuNumber));
		__GetStackPointer(&GuestRsp);
		__GetNextInstructionPointer(&GuestRip);
	}
	
	// 设置 VMCS 区域
	if (!SetupVmcs())
	{
		if (!m_VmxOn) // 如果不是因为 VT 已经启动导致的错误
		{
			kprint(("Cpu:[%d] 设置 VMCS 区域ERROR!\r\n", m_CpuNumber));
		}
		return FALSE;
	}

	// 初始化 VMCS 完毕
	kprint(("[+]Cpu:[%d] 准备启动虚拟化ing...\r\n", m_CpuNumber));
	
	__vmx_vmlaunch(); // 如果这句话执行成功,就不会返回

	if (m_VmxOn)	 // 到此处表明 VT 启动失败
	{
		size_t uError = 0;
		uError = VtBase::VmCsRead(VM_INSTRUCTION_ERROR); // 参考白皮书 (Vol. 3C 30-29)
		kprint(("ERROR:[%d] vmlaunch 指令调用失败!\r\n", uError));

		__vmx_off(); // 关闭 CPU 的 VMX 模式
		m_VmxOn = FALSE;
	}
	kprint(("Cpu:[%d] VT 虚拟化失败!\r\n", m_CpuNumber));

	__writeds(0x28 | 0x3); // RTL置为1
	__writees(0x28 | 0x3);
	__writefs(0x50 | 0x3);

	return TRUE;
}

// 关闭 VT
// @return
BOOLEAN VtBase::VtClose()
{
	if (m_VmxOn)
	{
		// 通过 VMCALL 退出 VT
		Asm_VmxCall(CallExitVt);
		m_VmxOn = FALSE;

		// 释放 VMM 内存
		VtVmmMemFree();

		VtIsUseEpt = FALSE;

		kprint(("Cpu:[%d] VT 已卸载!\r\n", m_CpuNumber));
	}

	// 设置CR4
	Cr4 cr4 = { 0 };
	cr4.all = __readcr4();
	cr4.Bits.vmxe = FALSE; // CR4.VMXE 置为 0
	__writecr4(cr4.all);

	return TRUE;
}

