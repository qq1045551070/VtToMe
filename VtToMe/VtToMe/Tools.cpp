#include "Tools.h"
#include <intrin.h>

typedef struct _KernelMdouleInfo
{
	ULONG_PTR Base; // 基址
	ULONG_PTR Size; // 大小
}KernelMdouleInfo, *PKernelMdouleInfo;

KernelMdouleInfo VtKernelInfo;
KIRQL irQl;

/* 关于获取内核页表数据 */
ULONG64 g_NT_BASE;
ULONG64 g_PTE_BASE = 0xFFFFF90000000000;
ULONG64 g_PDE_BASE = 0xFFFFF97C80000000;
ULONG64 g_PPE_BASE = 0xFFFFF97CBE400000;
ULONG64 g_PXE_BASE = 0xFFFFF97CBE5F2000;

// 修改Cr0寄存器, 去除写保护（内存保护机制）
KIRQL RemovWP()
{
	//DbgPrint("RemovWP\n");
	// (PASSIVE_LEVEL)提升 IRQL 等级为DISPATCH_LEVEL，并返回旧的 IRQL
	// 需要一个高的IRQL才能修改
	irQl = KeRaiseIrqlToDpcLevel();
	ULONG_PTR cr0 = __readcr0(); // 内联函数：读取Cr0寄存器的值, 相当于: mov eax,  cr0;

	// 将第16位（WP位）清0，消除写保护
	cr0 &= ~0x10000; // ~ 按位取反
	_disable(); // 清除中断标记, 相当于 cli 指令，修改 IF标志位
	__writecr0(cr0); // 将cr0变量数据重新写入Cr0寄存器中，相当于: mov cr0, eax
	//DbgPrint("退出RemovWP\n");
	return irQl;
}

// 复原Cr0寄存器
KIRQL UnRemovWP()
{
	//DbgPrint("UndoWP\n");
	ULONG_PTR cr0 = __readcr0();
	cr0 |= 0x10000; // WP复原为1
	_disable(); // 清除中断标记, 相当于 cli 指令，清空 IF标志位
	__writecr0(cr0); // 将cr0变量数据重新写入Cr0寄存器中，相当于: mov cr0, eax

	// 恢复IRQL等级
	KeLowerIrql(irQl);
	//DbgPrint("退出UndoWP\n");
	return irQl;
}

// 获取操作系统版本
ULONG GetWindowsVersion()
{
	RTL_OSVERSIONINFOW lpVersionInformation = { sizeof(RTL_OSVERSIONINFOW) };
	if (NT_SUCCESS(RtlGetVersion(&lpVersionInformation)))
	{
		ULONG dwMajorVersion = lpVersionInformation.dwMajorVersion;
		ULONG dwMinorVersion = lpVersionInformation.dwMinorVersion;
		if (dwMajorVersion == 5 && dwMinorVersion == 1)
		{
			return WINXP;
		}
		else if (dwMajorVersion == 6 && dwMinorVersion == 1)
		{
			return WIN7;
		}
		else if (dwMajorVersion == 6 && dwMinorVersion == 2)
		{
			return WIN8;
		}
		else if (dwMajorVersion == 10 && dwMinorVersion == 0)
		{
			return WIN10;
		}
	}
	return FALSE;
}

// 获取物理地址对应的Pte
// 将 ring3 的内存映射到 ring0 并返回一个内核 LinerAddress
VOID * GetKernelModeLinerAddress(ULONG_PTR cr3, ULONG_PTR user_mode_address)
{
	PHYSICAL_ADDRESS cr3_phy = { 0 };
	cr3_phy.QuadPart = cr3;
	ULONG_PTR current_cr3 = 0;
	PVOID cr3_liner_address = NULL;

	PHYSICAL_ADDRESS user_phy = { 0 };
	PVOID kernel_mode_liner_address = NULL;

	// 判断cr3是否真确	
	cr3_liner_address = MmGetVirtualForPhysical(cr3_phy);
	if (!MmIsAddressValid(cr3_liner_address)) {
		kprint(("cr3 参数不对!\r\n"));
		return NULL;
	}
	// 判断是否为 rin3 的地址 以及 地址是否可读取
	else if (user_mode_address >= 0xFFFFF80000000000) {
		// 如果为内核地址, 不需要映射
		kprint(("user_mode_address 为内核地址!\r\n"));
		return (void *)user_mode_address;
	}
	// 如果地址不可读
	else if (!MmIsAddressValid((void *)user_mode_address)) {
		kprint(("user_mode_address 参数不对!\r\n"));
		return NULL;
	}
	
	current_cr3 = __readcr3();
	// 关闭写保护，切换Cr3
	RemovWP();
	__writecr3(cr3_phy.QuadPart);

	// 映射 user mode 内存	
	user_phy = MmGetPhysicalAddress((void*)user_mode_address);
	//PVOID kernel_mode_liner_address = MmGetVirtualForPhysical(user_phy); //(直接分解PTE的形式获取对应的虚拟地址)
	kernel_mode_liner_address = MmMapIoSpace(user_phy, 10, MmNonCached); // 映射rin3内存到rin0

	// 恢复
	__writecr3(current_cr3);
	UnRemovWP();

	if (kernel_mode_liner_address) {
		return kernel_mode_liner_address;
	}
	else
		return NULL;
}

// 将 ring3 的内存映射到 ring0 并返回一个内核 LinerAddress
VOID FreeKernelModeLinerAddress(VOID * p, size_t size)
{
	if ((ULONG_PTR)p < 0xFFFFF80000000000) {
		if (p && size) {
			MmUnmapIoSpace(p, size);
		}
	}
}

// 获取内核模块基址、大小 
// (通过驱动链表, MmFindByCode 函数需要此函数先执行)
NTSTATUS GetKernelMoudleBaseAndSize(
	IN PDRIVER_OBJECT DriverObject,
	OUT PULONG_PTR szBase,
	OUT PULONG_PTR szSize)
{
	NTSTATUS dwStatus = STATUS_UNSUCCESSFUL;
	UNICODE_STRING dwKernelMoudleName;
	RtlInitUnicodeString(&dwKernelMoudleName, L"ntoskrnl.exe");

	// 获取驱动链表, 遍历模块
	PLDR_DATA_TABLE_ENTRY dwEentry = (PLDR_DATA_TABLE_ENTRY)(DriverObject->DriverSection);
	PLIST_ENTRY  dwFirstentry = NULL;
	PLIST_ENTRY  dwpCurrententry = NULL;
	PLDR_DATA_TABLE_ENTRY pCurrentModule = NULL;

	if (dwEentry)
	{
		dwFirstentry = dwEentry->InLoadOrderLinks.Flink;
		dwpCurrententry = dwFirstentry->Flink;

		while (dwFirstentry != dwpCurrententry)
		{
			// 获取LDR_DATA_TABLE_ENTRY结构
			pCurrentModule = CONTAINING_RECORD(dwpCurrententry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			if (pCurrentModule->BaseDllName.Buffer != 0)
			{
				if (RtlCompareUnicodeString(&dwKernelMoudleName, &(pCurrentModule->BaseDllName), FALSE) == 0)
				{
					*szBase = (__int64)pCurrentModule->DllBase;
					*szSize = (__int64)pCurrentModule->SizeOfImage;

					dwStatus = STATUS_SUCCESS;
					return dwStatus;
				}
			}
			// 下一个
			dwpCurrententry = dwpCurrententry->Flink;
		}
	}
	return dwStatus;
}

// 内存特征查找地址
// szCode: 特征码
// szSize: 特征码大小 (注意字符串的\00结尾，容易被坑)
PVOID MmFindByCode(char * szCode, size_t szSize)
{
	if (szCode && szSize)
	{
		PCHAR dwKernelBase = (PCHAR)VtKernelInfo.Base;

		for (unsigned __int64 i = 0; i < VtKernelInfo.Size; i++)
		{
			// 判断内核地址是否可读
			if (!MmIsAddressValid(&dwKernelBase[i]))
			{
				continue; // 不可读, 开始下一轮
			}

			for (unsigned __int64 j = 0x0; j < szSize; j++)
			{
				// 判断内核地址是否可读
				if (!MmIsAddressValid(&dwKernelBase[i + j]))
				{
					continue; // 不可读, 开始下一轮
				}

				// 支持模糊搜索
				if (szCode[j] == '*')
				{
					// 继续循环
					continue;
				}

				if (dwKernelBase[i + j] != szCode[j])
				{
					// 有一个内存比较不相等，跳出当前循环
					break;
				}

				if (j + 1 == szSize)
				{
					// 返回地址
					return (PVOID)(&dwKernelBase[i]);
				}
			}
		}
	}

	return NULL;
}

// 获取 PXE
PULONG64 GetPxeAddress(PVOID addr)
{
	// 1个 PXE 对应 512 GB
	return (PULONG64)(((((ULONG64)addr & 0xFFFFFFFFFFFF) >> 39) << 3) + g_PXE_BASE);
}

// 获取 PDPTE
PULONG64 GetPpeAddress(PVOID addr)
{
	// 1个 PDPTE 对应 1 GB
	return (PULONG64)(((((ULONG64)addr & 0xFFFFFFFFFFFF) >> 30) << 3) + g_PPE_BASE);
}

// 获取 PDE
PULONG64 GetPdeAddress(PVOID addr)
{
	// 1个 PDE 对应 2 MB
	return (PULONG64)(((((ULONG64)addr & 0xFFFFFFFFFFFF) >> 21) << 3) + g_PDE_BASE);
}

// 获取 PTE
PULONG64 GetPteAddress(PVOID addr)
{
	// 1个 PTE 对应 4KB
	return (PULONG64)(((((ULONG64)addr & 0xFFFFFFFFFFFF) >> 12) << 3) + g_PTE_BASE);
}

// 初始化工具类
NTSTATUS VtInitTools(PDRIVER_OBJECT DriverObject)
{
	NTSTATUS dwStatus = STATUS_SUCCESS;

	// 获取内核模块信息
	dwStatus = GetKernelMoudleBaseAndSize(DriverObject, &VtKernelInfo.Base, &VtKernelInfo.Size);
	if (!NT_SUCCESS(dwStatus))
	{
		KdPrint(("GetKernelMoudleBaseAndSize Error: [%X]", dwStatus));
		return dwStatus;
	}
	
	// 针对 Win10 随机目录页表
	g_NT_BASE = VtKernelInfo.Base;
	/*g_PTE_BASE = *(PULONG64)(g_NT_BASE + 0x3D68 + 0x2);
	g_PDE_BASE = (ULONG64)GetPteAddress((PVOID)g_PTE_BASE);
	g_PPE_BASE = (ULONG64)GetPteAddress((PVOID)g_PDE_BASE);
	g_PXE_BASE = (ULONG64)GetPteAddress((PVOID)g_PPE_BASE);*/

	return dwStatus;
}