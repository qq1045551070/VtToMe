#pragma once
#ifndef VTBASE
#define VTBASE

#include "VtHeader.h"
#include "VtAsm.h"
#include <intrin.h>

// 该类主要用于管理 VT VMM 区域的信息

#define SELECTOR_TABLE_INDEX    0x04

class VtBase : public VtHeader
{
public:
	VtBase();
	~VtBase();

public:
	// 获取此处的 Rip\Rsp, 作为 GUEST 的环境
	ULONG_PTR GuestRip, GuestRsp;

public:
	ULONG32 m_CpuNumber; // 当前CPU编号

	volatile BOOLEAN m_VmxOn; // 当前 CPU 核的虚拟化是否打开

	ULONG_PTR * m_VmOnRegionAddress;     // VMON 区域
	ULONG_PTR * m_VmCsRegionAddress;     // VMCS 区域
	ULONG_PTR * m_VmBitMapRegionAddress; // VM BITMAP 区域

	ULONGLONG m_VmOnRegionPhyAddress;    // 对应的物理地址
	ULONGLONG m_VmCsRegionPhyAddress;
	ULONGLONG m_VmMsrBitMapRegionPhyAddress;

	ULONG_PTR m_VmStackRootRegionPointer;// VMM 所需要的堆栈内存

	HOST_STATE  m_HostState;  // HOST  环境
	GUEST_STATE m_GuestState; // GUEST 环境

	BOOLEAN VtIsUseEpt; // 是否使用 EPT

public:
	// VMCS 区域的读写
	static BOOLEAN VmCsWrite(ULONG_PTR info, ULONG_PTR Value);
	static ULONG_PTR VmCsRead(ULONG_PTR info);

	// 用于设置指定Bits
	ULONG VmxAdjustControlValue(ULONG Msr, ULONG Ctl)
	{
		// 参考自【处理器虚拟化技术】(2.5.6.3)
		LARGE_INTEGER MsrValue = { 0 };
		MsrValue.QuadPart = __readmsr(Msr);
		Ctl &= MsrValue.HighPart;     //前32位为0的位置表示那些必须设置位0
		Ctl |= MsrValue.LowPart;      //后32位为1的位置表示那些必须设置位1
		return Ctl;
	}

	// 获取对应的段寄存器信息
	static VOID GetSelectorInfoBySelector(ULONG_PTR selector, ULONG_PTR * base, ULONG_PTR * limit, ULONG_PTR * attribute)
	{
		GDT gdtr;
		PKGDTENTRY64 gdtEntry;

		//初始化为0
		*base = *limit = *attribute = 0;

		if (selector == 0 || (selector & SELECTOR_TABLE_INDEX) != 0) {
			*attribute = 0x10000;	// unusable
			return;
		}

		__sgdt(&gdtr);
		gdtEntry = (PKGDTENTRY64)(gdtr.uBase + (selector & ~(0x3)));

		*limit = __segmentlimit((ULONG32)selector);
		*base = ((gdtEntry->u1.Bytes.BaseHigh << 24) | (gdtEntry->u1.Bytes.BaseMiddle << 16) | (gdtEntry->u1.BaseLow)) & 0xFFFFFFFF;
		*base |= ((gdtEntry->u1.Bits.Type & 0x10) == 0) ? ((uintptr_t)gdtEntry->u1.BaseUpper << 32) : 0;
		*attribute = (gdtEntry->u1.Bytes.Flags1) | (gdtEntry->u1.Bytes.Flags2 << 8);
		*attribute |= (gdtEntry->u1.Bits.Present) ? 0 : 0x10000;

		return VOID();
	}

public:
	// 执行 VMON 指令
	BOOLEAN ExecuteVmxOn();

public:
	// 检测是否能启用 VT
	BOOLEAN VtCheckIsSupported();
	// 检测虚拟化开关是否打开
	BOOLEAN VtCheckIsEnable();

	// 申请 VMON\VMCS 内存地址
	BOOLEAN VtVmmMemAllocate();
	// 释放所有 VMM 内存
	VOID VtVmmMemFree();

	// 设置 VMCS 区域
	BOOLEAN SetupVmcs();
	// 简化设置 VMCS MSR 区域
	BOOLEAN InitVmcs();
public:
	// 启用 VT
	BOOLEAN VtEnable();

	// 关闭 VT
	BOOLEAN VtClose();
};


#endif
