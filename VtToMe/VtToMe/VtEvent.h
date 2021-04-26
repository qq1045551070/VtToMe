#pragma once
#ifndef VTEVENT
#define VTEVENT

#include "VtHeader.h"

// 该类用于对 VM(Guest) 进行向量事件的注入

class VtEvent
{
public:
	VtEvent();
	~VtEvent();

public:
	// 注入中断指令
	static void VtInjectInterruption(
		InterruptionType interruption_type, InterruptionVector vector,
		bool deliver_error_code, ULONG32 error_code);

public:
	// 使用(pending) MTF 有两种方式 (参考【处理器虚拟化技术】(第4.14节))
	// (1). 通过事件注入方式, 注入一个中断类型为7(other)并且向量号为0的事件。MTF VM-exit 在 VM-entry 后被直接pending在guest第一条指令前。
	// (2). 通过设置MTF位(monitor trap flag)方式。MTF VM-exit 在 VM-entry 后被直接pending在guest第一条指令后。它属于trap类型的 VM-exit 。
	static void VtSetMonitorTrapFlag();
	static void VtCloseMonitorTrapFlag();
};

#endif
