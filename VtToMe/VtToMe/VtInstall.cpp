#include "VtInstall.h"
#include "NeedKernelFunc.h"
#include "VtBase.h"
#include "VtEpt.h"
#include "VtSsdtHook.h"
#include "Tools.h"

VtBase * g_Vmxs[128] = { 0 }; // 最多支持 128 核
VtEpt * g_Ept;		// VtEpt类的指针
VtInformaitonEntry g_vt_informaiton = { 0 };

VtInstall::VtInstall()
{
}

VtInstall::~VtInstall()
{
}

// 启动 VT 的多核渲染 DPC 回调
VOID VtLoadProc(
	_In_ struct _KDPC* Dpc,
	_In_opt_ PVOID DeferredContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
)
{
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(DeferredContext);

	BOOLEAN is_user_ept = (g_vt_informaiton.u1.Bits.user_ept ? TRUE : FALSE);
	ULONG uCpuNumber = KeGetCurrentProcessorNumber();
	
	// 启动 VT
	g_Vmxs[uCpuNumber] = new VtBase();
	g_Vmxs[uCpuNumber]->m_CpuNumber = uCpuNumber;
	g_Vmxs[uCpuNumber]->VtIsUseEpt = is_user_ept; // 是否使用 EPT
	
	if (!g_Vmxs[uCpuNumber]->VtCheckIsEnable() && 
		g_Vmxs[uCpuNumber]->VtCheckIsSupported())
	{
		// 满足使用 VT 虚拟化的条件
		g_Vmxs[uCpuNumber]->VtEnable(); // 启用 VT
		if (g_vt_informaiton.u1.Bits.user_ssdt_hook) { // 是否启用 SSDT HOOK
			VtSsdtHook::VtStartHookSsdt();
		}
	}
	else
	{
		kprint(("[+]Cpu:[%d] 开启 VT 失败\n", uCpuNumber));
	}

	KeSignalCallDpcSynchronize(SystemArgument2);
	KeSignalCallDpcDone(SystemArgument1);
}

// 结束 VT 的多核渲染 DPC 回调
VOID VtUnLoadProc(
	_In_ struct _KDPC* Dpc,
	_In_opt_ PVOID DeferredContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
)
{
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(DeferredContext);
	
	ULONG uCpuNumber = KeGetCurrentProcessorNumber();
	if (g_Vmxs[uCpuNumber]->VtCheckIsSupported())
	{
		g_Vmxs[uCpuNumber]->VtClose(); // 关闭 VT
		delete g_Vmxs[uCpuNumber];
		g_Vmxs[uCpuNumber] = NULL;
		// 通知
		*(PBOOLEAN)DeferredContext = FALSE;

		if (g_vt_informaiton.u1.Bits.user_ssdt_hook)
		{
			VtSsdtHook::VtStopHookSsdt();
		}
	}
	else
	{
		kprint(("[+]Cpu:[%d] 关闭 VT 失败\n", uCpuNumber));
	}

	KeSignalCallDpcSynchronize(SystemArgument2);
	KeSignalCallDpcDone(SystemArgument1);
}

// 多核渲染启动
// @is_user_ept 是否使用 ept
VOID VtInstall::VtStartCpusDrawing()
{

	BOOLEAN is_user_ept_confirmation = g_vt_informaiton.u1.Bits.user_ept;
	if (is_user_ept_confirmation && !g_Ept)
	{
		// 启动一次就可以了(全局 EPT 模式)
		g_Ept = new VtEpt();
		if (!g_Ept->VtStartEpt()) // 启动 EPT
		{
			// 如果启动 EPT 失败
			is_user_ept_confirmation = FALSE; // 停止使用 EPT
			delete g_Ept;
			g_Ept = NULL;
		}
	}

	g_vt_informaiton.u1.Bits.user_ept = is_user_ept_confirmation;
	KeGenericCallDpc(VtLoadProc, NULL);
}

// 多核渲染结束
VOID VtInstall::VtEndCpusDrawing()
{
	BOOLEAN g_timeout = TRUE;
	
	KeGenericCallDpc(VtUnLoadProc, (PVOID)&g_timeout);

	// 等待 VT 结束
	while (true) {
		if (!g_timeout) {
			break;
		}
		if (g_timeout > 30 * 1000 * 1000) {
			return VOID();
		}
	}
	
	if (g_Ept && MmIsAddressValid(g_Ept))
	{
		// 卸载 EPT
		g_Ept->VtCloseEpt();
		delete g_Ept;
		g_Ept = NULL;
	}
}

// 简化版启动 VT 并且初始化一些类
BOOLEAN VtInstall::VtSimplifyStart(VtInformaitonEntry vt_information)
{
	BOOLEAN result = TRUE;
	NTSTATUS status = STATUS_SUCCESS;
	
	// 初始化 Tools 类
	status = VtInitTools((PDRIVER_OBJECT)vt_information.driver_object);
	if (!NT_SUCCESS(status)) {
		kprint(("VtInitTools 失败!\r\n"));
		return FALSE;
	}
	// 初始化 SSDT Hook 库
	result = VtSsdtHook::VtInitSsdtHook();
	if (!result) {
		kprint(("VtInitSsdtHook 失败!\r\n"));
		return result;
	}

	// 获取 VT 初始化信息
	g_vt_informaiton = vt_information;
	VtStartCpusDrawing();
	return result;
}

// 简化版结束 VT
BOOLEAN VtInstall::VtSimplifyStop()
{
	VtEndCpusDrawing();
	return TRUE;
}
