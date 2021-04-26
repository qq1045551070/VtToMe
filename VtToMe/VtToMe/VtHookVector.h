#pragma once
#ifndef VTHOOKVECTOR
#define VTHOOKVECTOR

// 该类主要用于 Hook Gdt or Idt 中断

#include "VtHeader.h"

class VtHookVector : VtHeader
{
public:
	VtHookVector();
	~VtHookVector();

public:
	// 添加 Idt Hook (修改IDT对应的OFFSET)
	static void VtAddHookIdtVector(int vector, void* funcAddress);
	// 添加 Gdt Hook
};

#endif

