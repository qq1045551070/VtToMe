#pragma once
#ifndef VTVMEXIT
#define VTVMEXIT

#include "VtHeader.h"

// 该类主要用于处理 VM-exit

// 用于统一处理 VM-EXIT
EXTERN_C FASTCALL
VOID VtVmExitRoutine(ULONG_PTR * Registers);

// 用于处理 CPUID VM-EXIT
EXTERN_C
VOID CpuidVmExitHandler(ULONG_PTR * Registers);

// 用于处理 CrX VM-EXIT
EXTERN_C
VOID CrAccessVtExitHandler(ULONG_PTR * Registers);

// 用于处理 VMCALL VM-EXIT
EXTERN_C
VOID VmcallVmExitHandler(ULONG_PTR * Registers);

// 处理读取 MSR VM-EXIT
EXTERN_C 
VOID MsrReadVtExitHandler(ULONG_PTR * Registers);

// 处理写入 MSR VM-EXIT
EXTERN_C
VOID MsrWriteVtExitHandler(ULONG_PTR * Registers);

// 用于处理 Nmi 中断
EXTERN_C
VOID NmiExceptionVtExitHandler(ULONG_PTR * Registers);

// 用于处理 外部中断
EXTERN_C
VOID ExternalInterruptVtExitHandler(ULONG_PTR * Registers);

// 处理对 GDT/IDT 访问导致的 VM-exit
EXTERN_C
VOID GdtrOrIdtrAccessVtExitHandler(ULONG_PTR * Registers);

// 处理对 LDT/TR 访问导致的 VM-exit
EXTERN_C
VOID LdtrOrTrAccessVtExitHandler(ULONG_PTR * Registers);

// 用于处理默认 VM-EXIT
EXTERN_C
VOID DefaultVmExitHandler(ULONG_PTR * Registers);


#endif

