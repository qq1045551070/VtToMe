#pragma once
#ifndef VTASM
#define VTASM

// 该类用于提供 VT 所需要的汇编函数

#include "VtHeader.h"

// 需要的指令
EXTERN_C ULONG_PTR __readcs(void);
EXTERN_C ULONG_PTR __readds(void);
EXTERN_C ULONG_PTR __readss(void);
EXTERN_C ULONG_PTR __reades(void);
EXTERN_C ULONG_PTR __readfs(void);
EXTERN_C ULONG_PTR __readgs(void);
EXTERN_C ULONG_PTR __sldt(void);
EXTERN_C ULONG_PTR __str(void);
EXTERN_C ULONG_PTR __sgdt(PGDT gdtr);
EXTERN_C void __invd(void);
EXTERN_C void __writeds(ULONG_PTR ds);
EXTERN_C void __writees(ULONG_PTR es);
EXTERN_C void __writefs(ULONG_PTR fs);
EXTERN_C void __writecr2(ULONG_PTR cr2);

// EPT 相关指令
EXTERN_C void __invept(ULONG_PTR Type, ULONG_PTR * EptpPhyAddr); // 刷新 EPT
EXTERN_C void __invvpid(ULONG_PTR Type, ULONG_PTR * EptpPhyAddr);

// Host、Guest 环境指令
EXTERN_C void __GetStackPointer(ULONG_PTR* StackPointer);
EXTERN_C void __GetNextInstructionPointer(ULONG_PTR* RipPointer);

// VmExit 处理指令
EXTERN_C void Asm_VmExitHandler();

// Vmcall 相关的指令
EXTERN_C void Asm_UpdateRspAndRip(ULONG_PTR Rsp, ULONG_PTR Rip); // 修改当前 Rsp\Rip

// @explain: vmcall 指令的调用
// @parameter: ULONG64 uCallNumber		序号
// @parameter: PVOID hook_liner_address	要hook的线性地址 (注意hook rin3时, 要先将cr3的切换为r3程序的cr3)
// @parameter: PVOID jmp_liner_address	要跳向的线性地址
// @return:  EXTERN_C void
EXTERN_C void Asm_VmxCall(ULONG64 uCallNumber, PVOID hook_liner_address = NULL, PVOID jmp_liner_address = NULL, PVOID * ret_address = NULL);

#endif