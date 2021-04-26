#include "VtInstall.h"
#include "VtEptHook.h"
#include "Tools.h"
#include "VtSsdtHook.h"
#include "VtAsm.h"
#include <ntifs.h>
#include <intrin.h>

typedef NTSTATUS (NTAPI*pFakeZwClose)(
	_In_ HANDLE Handle
);
pFakeZwClose g_ZwClose;

EXTERN_C
NTSTATUS FASTCALL NTAPI FakeZwClose(
	_In_ HANDLE Handle
)
{
	KdPrint(("进入 FakeZwClose!\r\n"));
	NTSTATUS status = STATUS_SUCCESS;
	KdBreakPoint();
	status = g_ZwClose(Handle);

	return status;
}

EXTERN_C
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	KdPrint(("[+] 驱动卸载ing...\n"));

	VtInstall::VtSimplifyStop();
}

EXTERN_C
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegisterPath)
{
	UNREFERENCED_PARAMETER(RegisterPath);
	NTSTATUS Status = STATUS_SUCCESS;
	KdPrint(("[+] [%#p]驱动加载中ing...\r\n", DriverEntry));
	DriverObject->DriverUnload = DriverUnload;

	VtInformaitonEntry vt_information = { 0 };
	vt_information.driver_object = DriverObject;	// 传递参数
	vt_information.u1.Bits.user_ept = TRUE;			// 启用 EPT
	vt_information.u1.Bits.user_ssdt_hook = TRUE;	// 启用 SSDT HOOK
	// 启动VT
	VtInstall::VtSimplifyStart(vt_information); 
	
	LARGE_INTEGER timeOut;
	timeOut.QuadPart = -1 * 1000 * 1000; // 0.1秒延迟加载, 以防 VT 未启动
	KeDelayExecutionThread(KernelMode, FALSE, &timeOut);

	

	

	//g_ZwClose = ZwClose;
	//VtSsdtHook::VtHookSsdtByIndex(SsdtIndex(&ZwClose), NtClose, 1);

	// 根据 OpCode 获取, Win10X64 NtOpenProcess 地址
	//char opcode[26] = {
	//	"\x48\x89\x5c\x24\x08\x48\x89\x6c\x24\x10\x48\x89\x74\x24\x18\x57\x48\x83\xec\x20\x8b\x79\x18\x33\xdb"
	//};
	//PVOID ntopenprocess_func_address = (PCHAR)MmFindByCode(opcode, 25) - 0x30;
	//if (ntopenprocess_func_address) {
	//	KdPrint(("NtOpenProcess Address: %#p", ntopenprocess_func_address));
	//}
	//
	//// 调用 VT 功能
	//bool result_bool = VtEptHook::VtSimplifyEptHook(ntopenprocess_func_address, FakeNtOpenProcess, (PVOID*)&NtOpenProcessRetAddr);
	//if (!result_bool) {
	//	KdPrint(("[+] NtOpenProcess Hook 失败!\r\n"));
	//}
	
	return Status;
}