#pragma once
#ifndef VTINSTALL
#define VTINSTALL

// 该类主要负责 VT 的启动和关闭

#include "VtHeader.h"

class VtInstall : public VtHeader
{
public:
	VtInstall();
	~VtInstall();

public:
	// 多核渲染启动
	static VOID VtStartCpusDrawing();
	// 多核渲染结束
	static VOID VtEndCpusDrawing();

	// 简化版启动 VT 并且初始化一些类
	static BOOLEAN VtSimplifyStart(VtInformaitonEntry is_use_ept);
	// 简化版结束 VT
	static BOOLEAN VtSimplifyStop();
};

#endif

