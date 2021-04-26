#include "VtHookVector.h"
#include "VtBase.h"


VtHookVector::VtHookVector()
{
}

VtHookVector::~VtHookVector()
{
}

// 添加 Idt Hook (修改IDT对应的OFFSET)
void VtHookVector::VtAddHookIdtVector(int vector, void* funcAddress)
{
	ULONG_PTR gdtl = VtBase::VmCsRead(GUEST_GDTR_LIMIT);
	if ((vector > gdtl) && (!funcAddress)) {
		// 超出 Gdt 表得最大下标 or 参数不对
		kprint(("参数不对!\r\n"));
		return void();
	}

	// 获取 Idt 基址
	ULONG_PTR idt_base = VtBase::VmCsRead(GUEST_IDTR_BASE);
	// 改写段描述符信息
	pIdtEntry64 idt_entry_x64 = (pIdtEntry64)(idt_base + vector * 16); // 注意x64下一个idt entry size为16
	idt_entry_x64->offset_high = HIDWORD(funcAddress);
	idt_entry_x64->idt_entry.Bits.offset_middle = HIWORD(LODWORD(funcAddress));
	idt_entry_x64->idt_entry.Bits.offset_low = LOWORD(LODWORD(funcAddress));

	VtBase::VmCsWrite(GUEST_IDTR_BASE, idt_base);
}
