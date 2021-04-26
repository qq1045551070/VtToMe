#pragma once
#ifndef TOOLS
#define TOOLS

#include "VtHeader.h"

/***************************************************内核功能函数**********************************************************/
// 修改Cr0寄存器, 去除写保护（内存保护机制）
KIRQL RemovWP();
// 复原Cr0寄存器
KIRQL UnRemovWP();
// 获取操作系统版本
ULONG GetWindowsVersion();

// 将 ring3 的内存映射到 ring0 并返回一个内核 LinerAddress
VOID * GetKernelModeLinerAddress(ULONG_PTR cr3, ULONG_PTR user_mode_address);
// 将 ring3 的内存映射到 ring0 并返回一个内核 LinerAddress
VOID FreeKernelModeLinerAddress(VOID * p, size_t size = 10);

// 获取 PXE
PULONG64 GetPxeAddress(PVOID addr);
// 获取 PDPTE
PULONG64 GetPpeAddress(PVOID addr);
// 获取 PDE
PULONG64 GetPdeAddress(PVOID addr);
// 获取 PTE
PULONG64 GetPteAddress(PVOID addr);

/***************************************************内核内存信息函数**********************************************************/
// 获取内核模块基址、大小 (通过驱动链表)
NTSTATUS GetKernelMoudleBaseAndSize(
	IN PDRIVER_OBJECT DriverObject,
	OUT PULONG_PTR szBase,
	OUT PULONG_PTR szSize);
// 内核内存特征查找地址
// szCode: 特征码
// szSize: 特征码大小
PVOID MmFindByCode(char * szCode, size_t szSize);
/**************************************************************************************************************************/

// 初始化工具类
NTSTATUS VtInitTools(PDRIVER_OBJECT DriverObject);

#endif

