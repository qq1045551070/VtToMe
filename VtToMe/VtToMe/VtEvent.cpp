#include "VtEvent.h"
#include "VtBase.h"

VtEvent::VtEvent()
{}

VtEvent::~VtEvent()
{}

// @explain: 注入中断指令
// @parameter: InterruptionType interruption_type	中断类型
// @parameter: InterruptionVector vector	中断向量号		 	
// @parameter: bool deliver_error_code		是否有错误码
// @parameter: ULONG32 error_code			有的话请填写
// @return:  void	不返回任何值
void VtEvent::VtInjectInterruption(
	InterruptionType interruption_type, InterruptionVector vector, 
	bool deliver_error_code, ULONG32 error_code)
{
	VmxVmExit_Interrupt_info inject_event = { 0 };
	inject_event.Bits.valid = true;
	inject_event.Bits.interruption_type = static_cast<ULONG32>(interruption_type);
	inject_event.Bits.vector = static_cast<ULONG32>(vector);
	inject_event.Bits.error_code_valid = deliver_error_code;
	VtBase::VmCsWrite(VmcsField::VM_ENTRY_INTR_INFO, inject_event.all);

	if (deliver_error_code)
	{
		// 如果有错误码
		VtBase::VmCsWrite(VmcsField::VM_ENTRY_EXCEPTION_ERROR_CODE, error_code);
	}
}

// 通过设置MTF位, 启用 MTF
void VtEvent::VtSetMonitorTrapFlag()
{
	VmxProcessorBasedControls vm_procctl = { 0 };
	vm_procctl.all = static_cast<ULONG32>(VtBase::VmCsRead(CPU_BASED_VM_EXEC_CONTROL));
	vm_procctl.Bits.monitor_trap_flag = true; // 启用 MTF
	VtBase::VmCsWrite(CPU_BASED_VM_EXEC_CONTROL, vm_procctl.all);
}

// 关闭MTF位
void VtEvent::VtCloseMonitorTrapFlag()
{
	VmxProcessorBasedControls vm_procctl = { 0 };
	vm_procctl.all = static_cast<ULONG32>(VtBase::VmCsRead(CPU_BASED_VM_EXEC_CONTROL));
	vm_procctl.Bits.monitor_trap_flag = false; // 关闭 MTF
	VtBase::VmCsWrite(CPU_BASED_VM_EXEC_CONTROL, vm_procctl.all);
}
