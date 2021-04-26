#pragma once

#ifndef KERNELFUNC
#define KERNELFUNC

// 该头文件用于定义未导出的内核函数

#include <ntifs.h>

EXTERN_C 
_IRQL_requires_(DISPATCH_LEVEL) // 必须以 DISPATCH_LEVEL 等级进入该函数
_IRQL_requires_same_			// 必须以 进入的等级 退出该函数
VOID KeGenericCallDpc(//
	_In_ PKDEFERRED_ROUTINE Routine,
	_In_opt_ PVOID Context
);

EXTERN_C 
_IRQL_requires_(DISPATCH_LEVEL) // 必须以 DISPATCH_LEVEL 等级进入该函数
_IRQL_requires_same_			// 必须以 进入的等级 退出该函数
LOGICAL KeSignalCallDpcSynchronize(
	_In_ PVOID SystemArgument2
);

EXTERN_C 
_IRQL_requires_(DISPATCH_LEVEL) // 必须以 DISPATCH_LEVEL 等级进入该函数
_IRQL_requires_same_			// 必须以 进入的等级 退出该函数
VOID KeSignalCallDpcDone(
	_In_ PVOID SystemArgument1
);

EXTERN_C // 获取 EPROCESS 结构中的进程名称
PCHAR PsGetProcessImageFileName(PEPROCESS Process);

EXTERN_C // 暂停进程
NTSTATUS PsSuspendProcess(PEPROCESS Process);

#endif
