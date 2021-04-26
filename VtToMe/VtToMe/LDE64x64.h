// ;******************************************************
// ; LDE64 x64 relocatable (Length Disassembler Engine) for 64 bits plateforms
// ; FREEWARE
// ;
// ; coded by BeatriX 
// ; beatrix2004(at)free(dot)fr
// ;
// ; release : 1.6 - 02-23-09 - thanks to Zool@nder for bugfix on 'pop ds'
// ; release : 1.5 - 01-14-09
// ; release : 1.4 - 09-02-08
// ; thanks to Av0id , cyberbob and lena151 for their remarks and advices
// ;
// ;   Syntax to disassemble 32 bits target:
// ;   mov edx, 0
// ;   mov rcx, Address2Disasm
// ;   call LDE
// ;
// ;   Syntax to disassemble 64 bits target:
// ;   mov edx, 64
// ;   mov rcx, Address2Disasm
// ;   call LDE
// ;
// ;******************************************************

#ifndef LDE64X64
#define LDE64X64

#include <ntddk.h>

// 获取需要 HOOK 的字节
ULONG_PTR GetWriteCodeLen(PVOID HookLinerAddress, ULONG_PTR ShellCodeLen);

// 初始化LDE汇编引擎
void LDE_init();

#endif