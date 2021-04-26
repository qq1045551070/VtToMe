#include "VtEpt.h"
#include "VtBase.h"
#include "VtEptHook.h"
#include "LDE64x64.h"
#include "Tools.h"
#include <intrin.h>

// PDPTE 1GB PDE 2MB、PTE 4KB
// PDPTT 512GB、PDT 1GB、PT 2MB
// 8 GB 内存只需要 1个PML4T、1个PDPT、8个PDT、512 * 8个PDE(一个PDE对应4KB的PT内存)
#define  TOTAL_MEM  32 // 32GB内存管理

// 分配的总内存的首地址, 有意思的是采用一个总内存的形式分配给不同的 VMM(Guest)
PCHAR EptMem = NULL;

VtEpt::VtEpt()
{
	m_Eptp = { 0 };
	LDE_init(); // 初始化汇编引擎
}

VtEpt::~VtEpt()
{
	
}

// 开启	EPT
BOOLEAN VtEpt::VtStartEpt()
{
	if (EptMem)
	{
		// 全局 Ept 已经运行
		kprint(("全局 Ept 已经运行!\r\n"));
		return TRUE;
	}

	// 这里要注意所有的 VMM 使用的时一块 EPT 内存
	if (!VtInitEpt())
	{
		kprint(("全局 Ept 初始化失败!\r\n"));
		return FALSE;
	}

	kprint(("[+]全局 Ept 运行成功!\r\n"));

	return TRUE;
}

// 关闭   EPT
VOID VtEpt::VtCloseEpt()
{
	if (EptMem && MmIsAddressValid(EptMem))
	{
		// 卸载所有的Ept Hook
		VtEptHook::VtEptDeleteAllHook(); //Win10 有 BUG 暂时关闭
		
		kprint(("[+]所有的 EPT HOOK 已卸载!\r\n"));

		// 卸载 ept 内存
		ExFreePoolWithTag(EptMem, 'eptm');
		EptMem = NULL;

		kprint(("[+]全局 EPT 已卸载!\r\n"));
	}
}

// 初始化 EPT
BOOLEAN VtEpt::VtInitEpt()
{
	ULONG_PTR Pageindex = 0; // 用于记录总分配物理页的数量
	pEptPml4Entry Pml4t = NULL;
	pEptPdptEntry Pdpt = NULL;

	/*
		申请内存(判断系统)...
	*/
	//KdBreakPoint();
	// 每个PML4E，PDPTE，PDE，PTE都是占8个字节
	// 每个PML4T，PDPT，PDT，PT分配一页内存占4k
	// 分配总的内存，其中2代表PML4T和PDPT需要的两页内存，TOTAL_MEM 是PDT，TOTAL_MEM * 512是PT
	// 注意分配大内存不要使用 MmAllocateContiguousMemory
	EptMem = (PCHAR)ExAllocatePoolWithTag(NonPagedPool, (2 + TOTAL_MEM + TOTAL_MEM * 512) * PAGE_SIZE, 'eptm');
	
	if (NULL == EptMem)
	{
		kprint(("EptMem 为 NULL!\r\n"));
		return FALSE;
	}

	/*
		分配内存...
	*/

	// 最后两页给PML4T和PDPT，这里类似一个每项大小为4KB的数组，第一项为(EptMem + 0 * PAGE_SIZE)
	// 最后一项为(EptMem + (1 + TOTAL_MEM + TOTAL_MEM * 512) * PAGE_SIZE)
	Pml4t = (pEptPml4Entry)(EptMem + (TOTAL_MEM + TOTAL_MEM * 512) * PAGE_SIZE);
	Pdpt = (pEptPdptEntry)(EptMem + (1 + TOTAL_MEM + TOTAL_MEM * 512) * PAGE_SIZE);

	/*
		总布局是这样的：
		EptMem = {[PDT+512个PT],[PDT+512个PT],[PDT+512个PT]...共16个[PDT+512个PT]，PML4T，PDPT}
	*/

	// 设置 Eptp 信息
	VtSetEptPointer(Pml4t);

	// 设置 PML4E 信息
	Pml4t[0].all = MmGetPhysicalAddress(Pdpt).QuadPart & 0xFFFFFFFFFFFFFFF8; // 去除属性
	Pml4t[0].Bits.read_access = TRUE;
	Pml4t[0].Bits.write_access = TRUE;
	Pml4t[0].Bits.execute_access = TRUE;
	// 循环配置 PDPT/PDT/PT
	for (ULONG_PTR PDPT_Index = 0; PDPT_Index < TOTAL_MEM; PDPT_Index++)
	{
		// 分配一页给 PDT
		pEptPdEntry Pdt = (pEptPdEntry)(EptMem + PAGE_SIZE * Pageindex++);
		// 配置 PDPT 信息
		Pdpt[PDPT_Index].all = MmGetPhysicalAddress(Pdt).QuadPart & 0xFFFFFFFFFFFFFFF8;
		Pdpt[PDPT_Index].Bits.read_access = TRUE;
		Pdpt[PDPT_Index].Bits.write_access = TRUE;
		Pdpt[PDPT_Index].Bits.execute_access = TRUE;

		for (ULONG_PTR PDT_Index = 0; PDT_Index < 512; PDT_Index++)
		{
			// 分配一页给PT
			pEptPtEntry Pt = (pEptPtEntry)(EptMem + PAGE_SIZE * Pageindex++);
			// 配置 PDT 信息
			Pdt[PDT_Index].all = MmGetPhysicalAddress(Pt).QuadPart & 0xFFFFFFFFFFFFFFF8;
			Pdt[PDT_Index].Bits.read_access = TRUE;
			Pdt[PDT_Index].Bits.write_access = TRUE;
			Pdt[PDT_Index].Bits.execute_access = TRUE;

			for (ULONG_PTR PT_Index = 0; PT_Index < 512; PT_Index++)
			{
				// 配置 PT 的GPA信息 (参考 【处理器虚拟化技术】(第6.1.5节[419页]))
				Pt[PT_Index].all = (PDPT_Index * (1 << 30) + PDT_Index * (1 << 21) + PT_Index * (1 << 12)); // 配置 GPA
				Pt[PT_Index].Bits.read_access = TRUE;
				Pt[PT_Index].Bits.write_access = TRUE;
				Pt[PT_Index].Bits.execute_access = TRUE;
				Pt[PT_Index].Bits.memory_type = m_Eptp.Bits.memory_type;
			}
		}
	}

	kprint(("[+]全局 Ept 初始化成功!\r\n"));

	return TRUE;
}

// 获取 EPT 相关信息
// @Pml4Address: PML4 的线性地址
VOID VtEpt::VtSetEptPointer(PVOID Pml4Address)
{
	// IA32手册24.6.11

	Ia32VmxEptVpidCapMsr ia32Eptinfo = { 0 };
	ia32Eptinfo.all = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);

	if (ia32Eptinfo.Bits.support_page_walk_length4)
	{
		m_Eptp.Bits.page_walk_length = 3; // 设置为 4 级页表
		kprint(("[+]支持4级分页\r\n"));
	}

	if (ia32Eptinfo.Bits.support_uncacheble_memory_type)
	{
		m_Eptp.Bits.memory_type = 0; // UC(无缓存类型的内存)
		kprint(("[+]支持Ept 使用UC内存\r\n"));
	}

	if (ia32Eptinfo.Bits.support_write_back_memory_type)
	{
		m_Eptp.Bits.memory_type = 6; // WB(可回写类型的内存, 支持则优先设置)
		kprint(("[+]支持Ept 使用WB内存\r\n"));
	}

	if (ia32Eptinfo.Bits.support_accessed_and_dirty_flag) // Ept dirty 标志位是否有效
	{
		m_Eptp.Bits.enable_accessed_and_dirty_flags = TRUE;
	}
	else
	{
		m_Eptp.Bits.enable_accessed_and_dirty_flags = FALSE;
	}

	m_Eptp.Bits.pml4_address = MmGetPhysicalAddress(Pml4Address).QuadPart / PAGE_SIZE; // 清空低 3 字节(属性)

	kprint(("[+]EptPointer 配置完毕!\r\n"));
	return VOID();
}

// 通过物理地址获取 PTE 指针
// @PhyAddress 物理地址
// @return Ept Pte指针
pEptPtEntry VtEpt::VtGetPteByPhyAddress(ULONG_PTR PhyAddress)
{
	// 根据9 9 9 9 12 分页获取GPA对应的各个表的 EPT 下标 (参考 【处理器虚拟化技术】(第419页))
	ULONG_PTR PDPT_Index = (PhyAddress >> (9 + 9 + 12)) & 0x1FF;
	ULONG_PTR PDT_Index = (PhyAddress >> (9 + 12)) & 0x1FF;
	ULONG_PTR PT_Index = (PhyAddress >> 12) & 0x1FF;

	/*
		总布局是这样的：
		EptMem = {[PDT+512个PT],[PDT+512个PT],[PDT+512个PT]...共16个[PDT+512个PT]，PML4T，PDPT}
	*/

	// 假设EptMem是一个每个元素是一页大小的数组，offset就是它的下标
	// 求得每一等份，每一等份是一个 PDT + 512 个PT，排除后两页
	ULONG_PTR offset = 513;
	// 得到目标等份，第一页是PDT，不要
	offset = offset * PDPT_Index + 1;
	// 得到对应的PT
	offset = offset + PDT_Index;

	ULONG_PTR* Pte = (ULONG_PTR*)(EptMem + offset * PAGE_SIZE) + PT_Index; // 获取对应的PTE，并返回

	return reinterpret_cast<pEptPtEntry>(Pte);
}

// 处理 Ept VM-exit 产生的回调
VOID VtEpt::EptViolationVtExitHandler(ULONG_PTR * Registers)
{
	UNREFERENCED_PARAMETER(Registers);
	//KdBreakPoint();
	ULONG_PTR guestRip, guestRsp, guestPhyaddress;
	guestRip = guestRsp = guestPhyaddress = 0;

	guestRip = VtBase::VmCsRead(GUEST_RIP);
	guestRsp = VtBase::VmCsRead(GUEST_RSP);
	guestPhyaddress = VtBase::VmCsRead(GUEST_PHYSICAL_ADDRESS);

	// 通过触发 EptViolation 的地址，查找是不是跟我们HOOK有关
	pVtEptHookEntry hookItem = VtEptHook::VtGetEptHookItemByPhyAddress(guestPhyaddress);

	if (hookItem)
	{
		// 如果在 Hook 链表中， 进来
		// 获取 EPT PDT
		pEptPtEntry pte = VtGetPteByPhyAddress(guestPhyaddress);

		if (pte->Bits.execute_access)
		{
			// 如果是页面无法读写触发得异常
			pte->Bits.execute_access = 0;
			pte->Bits.write_access = 1;
			pte->Bits.read_access = 1;
			pte->Bits.physial_address = hookItem->real_phy_address >> 12;
		}
		else
		{
			// 如果是页面无法执行触发得异常
			pte->Bits.execute_access = 1;
			pte->Bits.write_access = 0;
			pte->Bits.read_access = 0;
			pte->Bits.physial_address = hookItem->fake_phy_address >> 12;
		}
	}
	else
	{
		kprint(("未知 EPT ERROR!\r\n"));
		KdBreakPoint();
	}


	VtBase::VmCsWrite(GUEST_RIP, guestRip);
	VtBase::VmCsWrite(GUEST_RSP, guestRsp);

	// 刷新 EPT
	// INVEPT 指令根据提供的 EPTP.PML4T 地址，刷新 Guest PhySical Mapping 以及 Combined Mapping 相关的 Cache 信息
	// Type 为 2 时(所有环境), 刷新 EPTP.PML4T 地址下的所有 Cache 信息
	__invept(2, &m_Eptp.all);

	return VOID();
}
