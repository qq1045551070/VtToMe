#pragma once
#ifndef VTEPTHOOK
#define VTEPTHOOK

// 该类提供基于 EPT 的 HOOK 方法

#include "VtHeader.h"

// 定义 Ept hook Entry
typedef struct _VtEptHookEntry
{
	ULONG itemid;						// Id
	ULONG_PTR hook_guest_liner_address; // Hook 的 Guest 的线性地址
	ULONG_PTR jmp_liner_address;		// 要跳向的线性地址
	ULONG_PTR guest_cr3;				// VM 的 Cr3
	ULONG_PTR guest_fake_pte_pointer;	// Guest 的线性地址，现在的 pte 数据 pointer
	ULONG_PTR guest_real_pte_pointer;	// Guest 的线性地址，原来的 pte 数据 pointer
	ULONG_PTR fake_phy_address;			// 假的物理页的物理地址
	ULONG_PTR real_phy_address;			// 原来的物理页的物理地址
	LIST_ENTRY hooklist;				// EPT HOOK 链表
	BOOLEAN ishook;						// 该hook是否还在运行中
}VtEptHookEntry, *pVtEptHookEntry;

// 定义存储 shellcode 信息的结构体
typedef struct _VtJmpShellCodeInformationEntry
{
	ULONG_PTR FakePageLinerAddress; // 假页面的 liner address
	ULONG_PTR OriginalFunHeadCode;	// 原函数流程的 liner address
}VtJmpShellCodeInformationEntry, pVtJmpShellCodeInformationEntry;

class VtEptHook : public VtHeader
{
public:
	VtEptHook();
	~VtEptHook();

private:

public:
	// 提供 Ept Hook 方式
	static void * VtEptHookMemory(IN ULONG_PTR HookGuestLinerAddress, IN ULONG_PTR JmpLinerAddress, IN ULONG HookMode);
	// 提供 Ept Delete All Hook 方式
	static void VtEptDeleteAllHook();
	// 提供查找指定HookItem方式
	static VtEptHookEntry * VtGetEptHookItemByPhyAddress(IN ULONG_PTR phy_address);
	// 提供构建跳转ShellCode的方式
	static bool VtGetJmpShellCode(IN ULONG_PTR HookGuestLinerAddress, IN ULONG_PTR JmpLinerAddress, OUT VtJmpShellCodeInformationEntry * jmp_info);

public:
	// 对外提供的Ept Hook简化接口
	static bool VtSimplifyEptHook(
		IN void * HookGuestLinerAddress = NULL,
		IN void * JmpLinerAddress = NULL,
		OUT void ** HookMode = NULL);
};

#endif

