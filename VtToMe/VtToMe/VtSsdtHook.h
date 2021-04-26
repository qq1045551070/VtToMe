#pragma once
#ifndef VTSSDTHOOK
#define VTSSDTHOOK

#include "VtHeader.h"

// 使用 VT 进行 SSDT Hook
// Win7 可使用 MSR HOOK，Win10 使用 EFER HOOK

#define MAX_SYSCALL_INDEX 0x1000 // 逆向分析此表大小为 0x1000

class VtSsdtHook : public VtHeader
{
public:
	VtSsdtHook();
	~VtSsdtHook();

public:
	// 初始化函数
	static bool VtInitSsdtHook();
	// Hook 指定下标 SSDT 函数
	static bool VtHookSsdtByIndex(ULONG32 ssdt_index, PVOID hook_address, CHAR param_number);

public:
	// Hook Msr Lstar 寄存器
	static bool VtHookMsrLstar();
	// Un Hook Msr Lstar 寄存器
	static bool VtUnHookMsrLstar();

public:
	// Efer Hook
	static bool VtEferHook();
	// #UD 异常处理
	static bool UdExceptionVtExitHandler(ULONG_PTR * Registers);
	// 模拟 SysCall 流程
	static bool VtSysCallEmulate(ULONG_PTR * Registers);
	// 模拟 SysRet 流程
	static bool VtSysRetEmulate(ULONG_PTR * Registers);

public:
	// 启动SsdtHook
	static bool VtStartHookSsdt();
	// 停止SsdtHook
	static bool VtStopHookSsdt();
};

#endif

