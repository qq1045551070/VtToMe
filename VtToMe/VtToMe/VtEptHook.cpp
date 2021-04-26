#include "VtEptHook.h"
#include "LDE64x64.h"
#include "VtBase.h"
#include "Tools.h"
#include "VtEpt.h"
#include "VtAsm.h"

// 引用
extern  VtEpt *g_Ept;
extern	VtBase * g_Vmxs[128];

VtEptHookEntry m_EptHookRootPointer; // hook list 指针
ULONG hooklist_len = 0; // hook list 长度

VtEptHook::VtEptHook()
{
}

VtEptHook::~VtEptHook()
{
}

// 提供 Ept Hook 方式
// 替换物理页的方式Hook
void * VtEptHook::VtEptHookMemory(
	IN ULONG_PTR HookGuestLinerAddress,	 // 要hook的目标线性地址
	IN ULONG_PTR JmpLinerAddress,		 // 要跳转的线性地址
	IN ULONG HookMode)					 // X86 or X64
{
	UNREFERENCED_PARAMETER(HookMode);

	// 判断 EPT 是否启动 以及 当前核是否启动 EPT
	ULONG cpu_number = KeGetCurrentProcessorNumber();
	if (!g_Ept && !g_Vmxs[cpu_number]->VtIsUseEpt)
	{
		//kprint(("EPT 未启动!!!\r\n"));
		return NULL;
	}

	// 生成 VtEptHookEntry 结构体
	VtEptHookEntry * hook_item = (VtEptHookEntry *)kmalloc(sizeof(VtEptHookEntry));
	if (!hook_item)
	{
		//kprint(("hook_item 生成失败!\r\n"));
		return NULL;
	}

	// 填充 VtEptHookEntry 结构体的基本字段
	hook_item->hook_guest_liner_address = HookGuestLinerAddress;
	hook_item->jmp_liner_address = JmpLinerAddress;
	hook_item->guest_cr3 = VtBase::VmCsRead(GUEST_CR3);
	hook_item->itemid = hooklist_len++;
	hook_item->ishook = TRUE;
	// 挂到 HOOK 链
	if (m_EptHookRootPointer.hooklist.Flink == NULL)
	{
		InitializeListHead(&m_EptHookRootPointer.hooklist); // 初始化链表
	}
	InsertTailList(&m_EptHookRootPointer.hooklist, &hook_item->hooklist); // 插入链表

	// 关闭写保护、切换 Cr3
	RemovWP();
	__writecr3(hook_item->guest_cr3);

	// 构建 jmp shell code
	VtJmpShellCodeInformationEntry jmp_information = { 0 };
	if (!VtGetJmpShellCode(HookGuestLinerAddress, JmpLinerAddress, &jmp_information))
	{
		kprint(("VtGetJmpShellCode error!\r\n"));
		return NULL;
	}

	// 填充 VtEptHookEntry 结构体的物理地址信息字段
	hook_item->fake_phy_address = MmGetPhysicalAddress((PVOID)jmp_information.FakePageLinerAddress).QuadPart & 0xFFFFFFFFFFFFF000;
	hook_item->real_phy_address = MmGetPhysicalAddress((PVOID)HookGuestLinerAddress).QuadPart & 0xFFFFFFFFFFFFF000;
	hook_item->guest_fake_pte_pointer = reinterpret_cast<ULONG_PTR>(g_Ept->VtGetPteByPhyAddress(hook_item->fake_phy_address));
	hook_item->guest_fake_pte_pointer = reinterpret_cast<ULONG_PTR>(g_Ept->VtGetPteByPhyAddress(hook_item->real_phy_address));

	// 还原写保护、切回 Cr3
	__writecr3(hook_item->guest_cr3);  // 恢复 Cr3
	UnRemovWP();

	// 设置hook的页面为只执行
	pEptPtEntry hookItem = (pEptPtEntry)hook_item->guest_fake_pte_pointer;
	hookItem->Bits.execute_access = 1;
	hookItem->Bits.read_access = 0;
	hookItem->Bits.write_access = 0;
	hookItem->Bits.physial_address = hook_item->fake_phy_address >> 12;

	// 刷新 EPT
	// INVEPT 指令根据提供的 EPTP.PML4T 地址，刷新 Guest PhySical Mapping 以及 Combined Mapping 相关的 Cache 信息
	// Type 为 2 时(所有环境无效), 刷新 EPTP.PML4T 地址下的所有 Cache 信息
	__invept(2, &g_Ept->m_Eptp.all);

	return (void *)jmp_information.OriginalFunHeadCode; // 返回原函数流程
}

// 提供 Ept Delete All Hook 方式
void VtEptHook::VtEptDeleteAllHook()
{
	if (!hooklist_len) return void();
	//__debugbreak();
	for (PLIST_ENTRY pListEntry = m_EptHookRootPointer.hooklist.Flink;
		pListEntry != &m_EptHookRootPointer.hooklist;
		pListEntry = pListEntry->Flink)
	{
		pVtEptHookEntry pEntry = CONTAINING_RECORD(pListEntry, VtEptHookEntry, hooklist);
		pEptPtEntry pte = g_Ept->VtGetPteByPhyAddress(pEntry->real_phy_address);

		// 修正pte
		pte->Bits.physial_address = pEntry->real_phy_address >> 12;
		pte->Bits.execute_access = 1;
		pte->Bits.write_access = 1;
		pte->Bits.read_access = 1;

		// 释放内存
		kFree(pEntry);
		hooklist_len--;

		if (!hooklist_len)
		{
			// ????????????????? 针对 BUG ?????????????????
			break;
		}
	}

	return void();
}

// 提供查找指定HookItem方式
VtEptHookEntry * VtEptHook::VtGetEptHookItemByPhyAddress(IN ULONG_PTR phy_address)
{
	if (!phy_address || 
		(m_EptHookRootPointer.hooklist.Flink == NULL) || 
		IsListEmpty(&m_EptHookRootPointer.hooklist))
	{
		kprint(("空的 hook list error!\r\n"));
		return NULL;
	}

	// 去除后三位属性
	phy_address &= 0xFFFFFFFFFFFFF000;

	// 根据物理地址，循环遍历 hook list
	for (PLIST_ENTRY pListEntry = m_EptHookRootPointer.hooklist.Flink;
		pListEntry != &m_EptHookRootPointer.hooklist;
		pListEntry = pListEntry->Flink)
	{
		pVtEptHookEntry pEntry = CONTAINING_RECORD(pListEntry, VtEptHookEntry, hooklist);
		if ((phy_address == pEntry->fake_phy_address ||
			phy_address == pEntry->real_phy_address) &&
			phy_address)
		{
			return pEntry; // 找到目标，返回
		}
	}

	return NULL;
}

// 提供构建跳转ShellCode的方式
bool VtEptHook::VtGetJmpShellCode(
	IN ULONG_PTR HookGuestLinerAddress,				// 要hook的目标线性地址
	IN ULONG_PTR JmpLinerAddress,					// 要跳转的线性地址
	OUT VtJmpShellCodeInformationEntry * jmp_info)	// jmp shell code 信息结构体
{
	/*
		跳到代理函数用
		push 代理地址
		ret
		的方式来HOOK

		跳到代理函数千万不能用jmp qword ptr [***]的方式，
		这样会读取该指令之后的地址(该指令之后的地址存储代理函数地址)
		导致不停触发EptViolation
	*/
	PCHAR OriginalFunHeadCode = NULL;
	ULONG_PTR FakeLinerAddr = HookGuestLinerAddress;
	ULONG_PTR JmpLinerAddr = JmpLinerAddress;
	UCHAR JmpFakeAddr[] = "\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\x50\xC3"; // return 过去代码
	UCHAR JmpOriginalFun[] = "\xFF\x25\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"; // JMP 回来代码

	// 查看是否已经被 hook
	pVtEptHookEntry hook_item =
		VtGetEptHookItemByPhyAddress(MmGetPhysicalAddress((PVOID)HookGuestLinerAddress).QuadPart);

	if (hook_item != NULL)
	{
		// 已经被 hook 过
		if (hook_item->ishook == TRUE)
		{
			// hook 还未取消
			kprint(("该位置已被 hook，且还在运行中!\r\n"));
			return false;
		}
	}

	// 否则进行 hook 的 new or cover
	/*
		构建跳转的 ShellCode
	*/
	RtlMoveMemory(JmpFakeAddr + 2, &JmpLinerAddr, 8);

	// 配置跳回去的代码
	ULONG_PTR WriteLen = GetWriteCodeLen((PVOID)FakeLinerAddr, 12);
	ULONG_PTR JmpOriginalAddr = FakeLinerAddr + WriteLen;
	RtlMoveMemory(JmpOriginalFun + 6, &JmpOriginalAddr, 8);
	
	// 复制原函数页面
	ULONG_PTR MyFakePage = (ULONG_PTR)kmalloc(PAGE_SIZE);
	RtlMoveMemory((PVOID)MyFakePage, (PVOID)(FakeLinerAddr & 0xFFFFFFFFFFFFF000), PAGE_SIZE);

	// 配置 保存原函数被修改的代码 和 跳回原函数
	OriginalFunHeadCode = (PCHAR)kmalloc(WriteLen + 14);
	RtlFillMemory(OriginalFunHeadCode, WriteLen + 14, 0x90);
	RtlMoveMemory(OriginalFunHeadCode, (PVOID)FakeLinerAddr, WriteLen);
	RtlMoveMemory((PCHAR)(OriginalFunHeadCode)+WriteLen, JmpOriginalFun, 14);

	// 配置用于执行的假页面
	ULONG_PTR offset = FakeLinerAddr - (FakeLinerAddr & 0xFFFFFFFFFFFFF000); // 获取相对 PTE BASE 的偏移
	RtlFillMemory((PVOID)(MyFakePage + offset), WriteLen, 0x90);
	RtlMoveMemory((PVOID)(MyFakePage + offset), &JmpFakeAddr, 12);

	// 填写 jmp shell code information
	jmp_info->FakePageLinerAddress = MyFakePage;
	jmp_info->OriginalFunHeadCode = (ULONG_PTR)OriginalFunHeadCode;

	return true;
}

// 对外提供的 Ept Hook 简化接口
bool VtEptHook::VtSimplifyEptHook(
	IN void * hook_liner_address,	 // 要hook的目标线性地址
	IN void * jmp_liner_address,	 // 要跳转的线性地址
	OUT void ** ret_address)			 // X86 or X64(暂不使用)
{
	if (!MmIsAddressValid(ret_address) && !hook_liner_address && !jmp_liner_address)
	{
		kprint(("参数错误!\r\n"));
		return false;
	}
	
	LARGE_INTEGER timeOut;
	timeOut.QuadPart = -1 * 1000 * 1000; // 0.1秒延迟加载, 以防 VT 未启动
	KeDelayExecutionThread(KernelMode, FALSE, &timeOut);

	// Ept Hook 测试
	Asm_VmxCall(CallEptHook, hook_liner_address, jmp_liner_address, ret_address);

	if (!ret_address) {
		kprint(("VtSimplifyEptHook 调用失败!\r\n"));
		return false;
	}

	return true;
}

