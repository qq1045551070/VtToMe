#pragma once
#ifndef VTHEADER
#define VTHEADER

// 该类位置顶类, 用于结构体、通用函数类的定义

#include <ntifs.h>

// 定义操作系统版本
#define WINXP 51
#define WIN7  61
#define WIN8  62
#define WIN10 100

/* vmcall exit reason  */
#define CallEptHook 'hk'
#define CallDelEptHook 'dhk'
#define CallExitVt 'exit'
#define CallSsdtHook 'shk'
#define CallDelSsdtHook 'dshk'

/* REGS */
#define R_RAX 0
#define R_RCX 1
#define R_RDX 2
#define R_RBX 3
#define R_RSP 4
#define R_RBP 5
#define R_RSI 6
#define R_RDI 7
#define R_R8 8
#define R_R9 9
#define R_R10 10
#define R_R11 11
#define R_R12 12
#define R_R13 13
#define R_R14 14
#define R_R15 15
#define R_MAX 16

/**
 * @brief EFLAGS/RFLAGS
 *
 */
#define X86_FLAGS_CF            (1 << 0)
#define X86_FLAGS_PF            (1 << 2)
#define X86_FLAGS_AF            (1 << 4)
#define X86_FLAGS_ZF            (1 << 6)
#define X86_FLAGS_SF            (1 << 7)
#define X86_FLAGS_TF            (1 << 8)
#define X86_FLAGS_IF            (1 << 9)
#define X86_FLAGS_DF            (1 << 10)
#define X86_FLAGS_OF            (1 << 11)
#define X86_FLAGS_STATUS_MASK   (0xfff)
#define X86_FLAGS_IOPL_MASK     (3 << 12)
#define X86_FLAGS_IOPL_SHIFT    (12)
#define X86_FLAGS_NT            (1 << 14)
#define X86_FLAGS_RF            (1 << 16)
#define X86_FLAGS_VM            (1 << 17)
#define X86_FLAGS_AC            (1 << 18)
#define X86_FLAGS_VIF           (1 << 19)
#define X86_FLAGS_VIP           (1 << 20)
#define X86_FLAGS_ID            (1 << 21)
#define X86_FLAGS_RESERVED_ONES 0x2
#define X86_FLAGS_RESERVED      0xffc0802a

#define X86_FLAGS_RESERVED_BITS 0xffc38028
#define X86_FLAGS_FIXED         0x00000002

/* MSRs */
#define IA32_FEATURE_CONTROL_CODE		0x03A
#define IA32_SYSENTER_CS                        0x174
#define IA32_SYSENTER_ESP                       0x175
#define IA32_SYSENTER_EIP                       0x176
#define IA32_DEBUGCTL                           0x1D9
#define IA32_VMX_BASIC_MSR_CODE			0x480
#define IA32_VMX_PINBASED_CTLS                  0x481
#define IA32_VMX_PROCBASED_CTLS                 0x482
#define IA32_VMX_EXIT_CTLS                      0x483
#define IA32_VMX_ENTRY_CTLS                     0x484
#define IA32_VMX_MISC                           0x485
#define IA32_VMX_CR0_FIXED0                     0x486
#define IA32_VMX_CR0_FIXED1                     0x487
#define IA32_VMX_CR4_FIXED0                     0x488
#define IA32_VMX_CR4_FIXED1                     0x489
#define	IA32_FS_BASE    		   0xc0000100
#define	IA32_GS_BASE	                   0xc0000101
#define IA32_VMX_PROCBASED_CTLS2				0x0000048b

/* MSRs */
#define IA32_FEATURE_CONTROL_CODE		0x03A
#define IA32_SYSENTER_CS                        0x174
#define IA32_SYSENTER_ESP                       0x175
#define IA32_SYSENTER_EIP                       0x176
#define IA32_DEBUGCTL                           0x1D9
#define IA32_VMX_BASIC_MSR_CODE			0x480
#define IA32_VMX_PINBASED_CTLS                  0x481
#define IA32_VMX_PROCBASED_CTLS                 0x482
#define IA32_VMX_EXIT_CTLS                      0x483
#define IA32_VMX_ENTRY_CTLS                     0x484
#define IA32_VMX_MISC                           0x485
#define IA32_VMX_CR0_FIXED0                     0x486
#define IA32_VMX_CR0_FIXED1                     0x487
#define IA32_VMX_CR4_FIXED0                     0x488
#define IA32_VMX_CR4_FIXED1                     0x489
#define	IA32_FS_BASE    				   0xc0000100
#define	IA32_GS_BASE	                   0xc0000101
#define IA32_VMX_PROCBASED_CTLS2				0x0000048b

#define MSR_IA32_VMX_BASIC                      0x480
#define MSR_IA32_VMX_PINBASED_CTLS              0x481
#define MSR_IA32_VMX_PROCBASED_CTLS             0x482
#define MSR_IA32_VMX_EXIT_CTLS                  0x483
#define MSR_IA32_VMX_ENTRY_CTLS                 0x484
#define MSR_IA32_VMX_MISC                       0x485
#define MSR_IA32_VMX_CR0_FIXED0                 0x486
#define MSR_IA32_VMX_CR0_FIXED1                 0x487
#define MSR_IA32_VMX_CR4_FIXED0                 0x488
#define MSR_IA32_VMX_CR4_FIXED1                 0x489
#define MSR_IA32_VMX_VMCS_ENUM                  0x48a
#define MSR_IA32_VMX_PROCBASED_CTLS2            0x48b
#define MSR_IA32_VMX_EPT_VPID_CAP               0x48c
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS         0x48d
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS        0x48e
#define MSR_IA32_VMX_TRUE_EXIT_CTLS             0x48f
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS            0x490

#define MSR_IA32_MTRRCAP			0xfe
#define MSR_IA32_MTRR_DEF_TYPE			0x2ff
#define MSR_IA32_MTRR_PHYSBASE(n)		(0x200 + 2*(n))
#define MSR_IA32_MTRR_PHYSMASK(n)		(0x200 + 2*(n) + 1)
#define MSR_IA32_MTRR_FIX64K_00000		0x250
#define MSR_IA32_MTRR_FIX16K_80000		0x258
#define MSR_IA32_MTRR_FIX16K_A0000		0x259
#define MSR_IA32_MTRR_FIX4K_C0000		0x268
#define MSR_IA32_MTRR_FIX4K_C8000		0x269
#define MSR_IA32_MTRR_FIX4K_D0000		0x26a
#define MSR_IA32_MTRR_FIX4K_D8000		0x26b
#define MSR_IA32_MTRR_FIX4K_E0000		0x26c
#define MSR_IA32_MTRR_FIX4K_E8000		0x26d
#define MSR_IA32_MTRR_FIX4K_F0000		0x26e
#define MSR_IA32_MTRR_FIX4K_F8000		0x26f
#define MSR_GS_BASE		0xC0000101
#define MSR_IA32_EFER	0xC0000080
#define MSR_IA32_STAR	0xC0000081
#define MSR_LSTAR		0xC0000082
#define MSR_IA32_FMASK  0xC0000084
#define MSR_IA32_VMX_VMFUNC                 0x491
#define MSR_IA32_DEBUGCTL                   0x1D9
#define MSR_IA32_FEATURE_CONTROL            0x03A

#define CPU_BASED_VIRTUAL_INTR_PENDING          0x00000004
#define CPU_BASED_USE_TSC_OFFSETING             0x00000008
#define CPU_BASED_HLT_EXITING                   0x00000080
#define CPU_BASED_INVLPG_EXITING                0x00000200
#define CPU_BASED_MWAIT_EXITING                 0x00000400
#define CPU_BASED_RDPMC_EXITING                 0x00000800
#define CPU_BASED_RDTSC_EXITING                 0x00001000
#define CPU_BASED_CR3_LOAD_EXITING              0x00008000
#define CPU_BASED_CR3_STORE_EXITING             0x00010000
#define CPU_BASED_CR8_LOAD_EXITING              0x00080000
#define CPU_BASED_CR8_STORE_EXITING             0x00100000
#define CPU_BASED_TPR_SHADOW                    0x00200000
#define CPU_BASED_VIRTUAL_NMI_PENDING           0x00400000
#define CPU_BASED_MOV_DR_EXITING                0x00800000
#define CPU_BASED_UNCOND_IO_EXITING             0x01000000
#define CPU_BASED_ACTIVATE_IO_BITMAP            0x02000000
#define CPU_BASED_MONITOR_TRAP_FLAG             0x08000000
#define CPU_BASED_ACTIVATE_MSR_BITMAP           0x10000000
#define CPU_BASED_MONITOR_EXITING               0x20000000
#define CPU_BASED_PAUSE_EXITING                 0x40000000
#define CPU_BASED_ACTIVATE_SECONDARY_CONTROLS   0x80000000

#define PIN_BASED_EXT_INTR_MASK                 0x00000001
#define PIN_BASED_NMI_EXITING                   0x00000008
#define PIN_BASED_VIRTUAL_NMIS                  0x00000020
#define PIN_BASED_PREEMPT_TIMER                 0x00000040
#define PIN_BASED_POSTED_INTERRUPT              0x00000080

#define VM_EXIT_SAVE_DEBUG_CNTRLS               0x00000004
#define VM_EXIT_IA32E_MODE                      0x00000200
#define VM_EXIT_LOAD_PERF_GLOBAL_CTRL           0x00001000
#define VM_EXIT_ACK_INTR_ON_EXIT                0x00008000
#define VM_EXIT_SAVE_GUEST_PAT                  0x00040000
#define VM_EXIT_LOAD_HOST_PAT                   0x00080000
#define VM_EXIT_SAVE_GUEST_EFER                 0x00100000
#define VM_EXIT_LOAD_HOST_EFER                  0x00200000
#define VM_EXIT_SAVE_PREEMPT_TIMER              0x00400000
#define VM_EXIT_CLEAR_BNDCFGS                   0x00800000

#define VM_ENTRY_IA32E_MODE                     0x00000200
#define VM_ENTRY_SMM                            0x00000400
#define VM_ENTRY_DEACT_DUAL_MONITOR             0x00000800
#define VM_ENTRY_LOAD_PERF_GLOBAL_CTRL          0x00002000
#define VM_ENTRY_LOAD_GUEST_PAT                 0x00004000
#define VM_ENTRY_LOAD_GUEST_EFER                0x00008000
#define VM_ENTRY_LOAD_BNDCFGS                   0x00010000

#define SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES 0x00000001
#define SECONDARY_EXEC_ENABLE_EPT               0x00000002
#define SECONDARY_EXEC_DESCRIPTOR_TABLE_EXITING 0x00000004
#define SECONDARY_EXEC_ENABLE_RDTSCP            0x00000008
#define SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE   0x00000010
#define SECONDARY_EXEC_ENABLE_VPID              0x00000020
#define SECONDARY_EXEC_WBINVD_EXITING           0x00000040
#define SECONDARY_EXEC_UNRESTRICTED_GUEST       0x00000080
#define SECONDARY_EXEC_APIC_REGISTER_VIRT       0x00000100
#define SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY    0x00000200
#define SECONDARY_EXEC_PAUSE_LOOP_EXITING       0x00000400
#define SECONDARY_EXEC_ENABLE_INVPCID           0x00001000
#define SECONDARY_EXEC_ENABLE_VM_FUNCTIONS      0x00002000
#define SECONDARY_EXEC_ENABLE_VMCS_SHADOWING    0x00004000
#define SECONDARY_EXEC_ENABLE_PML               0x00020000
#define SECONDARY_EXEC_ENABLE_VIRT_EXCEPTIONS   0x00040000
#define SECONDARY_EXEC_XSAVES                   0x00100000
#define SECONDARY_EXEC_PCOMMIT                  0x00200000
#define SECONDARY_EXEC_TSC_SCALING              0x02000000
//---------------------------------------

// 内存对齐
#define ROUNDUP(x,align) ((x + align - 1) & ~(align - 1))
#define LOWORD(dword)  (((ULONG32)(dword)) & 0xFFFF)
#define HIWORD(dword)  ((((ULONG32)(dword)) >> 16) & 0xFFFF)
#define LODWORD(qword) (((ULONGLONG)(qword)) & 0xFFFFFFFF)
#define HIDWORD(qword) ((((ULONGLONG)(qword)) >> 32) & 0xFFFFFFFF)
#ifndef MAKEQWORD
#define MAKEQWORD(low, hi) ((((ULONGLONG)low) & 0xFFFFFFFF) | ((((ULONGLONG)hi) & 0xFFFFFFFF) << 32))
#endif

#if DBG_
#define kprint(_x_)\
		DbgPrint("[+]VtDbug: FuncName: [%s], Liner: [%d]-->", __FUNCTION__, __LINE__);\
		DbgPrint _x_ ;
#else
#define kprint(_x_)
#endif

#define VtDbgErrorPrint(x, s)\
	if ((x) != 0)\
	{\
		kprint(("Debug:%s 调用【失败】!\n", s));\
		return FALSE;\
	}

#pragma pack(push,1) // 注意1字节对齐

#define SsdtIndex(ptr) *(PULONG)((ULONG_PTR)ptr + 0x15) // 逆向 Zw 系列函数你会发现 +0x15 处是其系统服务号

// VMCS 区域信息定义
enum VmcsField {
	VIRTUAL_PROCESSOR_ID = 0x00000000,
	POSTED_INTR_NOTIFICATION_VECTOR = 0x00000002,
	EPTP_INDEX = 0x00000004,
	GUEST_ES_SELECTOR = 0x00000800,
	GUEST_CS_SELECTOR = 0x00000802,
	GUEST_SS_SELECTOR = 0x00000804,
	GUEST_DS_SELECTOR = 0x00000806,
	GUEST_FS_SELECTOR = 0x00000808,
	GUEST_GS_SELECTOR = 0x0000080a,
	GUEST_LDTR_SELECTOR = 0x0000080c,
	GUEST_TR_SELECTOR = 0x0000080e,
	GUEST_INTR_STATUS = 0x00000810,
	GUEST_PML_INDEX = 0x00000812,
	HOST_ES_SELECTOR = 0x00000c00,
	HOST_CS_SELECTOR = 0x00000c02,
	HOST_SS_SELECTOR = 0x00000c04,
	HOST_DS_SELECTOR = 0x00000c06,
	HOST_FS_SELECTOR = 0x00000c08,
	HOST_GS_SELECTOR = 0x00000c0a,
	HOST_TR_SELECTOR = 0x00000c0c,
	IO_BITMAP_A = 0x00002000,
	IO_BITMAP_B = 0x00002002,
	MSR_BITMAP = 0x00002004,
	VM_EXIT_MSR_STORE_ADDR = 0x00002006,
	VM_EXIT_MSR_LOAD_ADDR = 0x00002008,
	VM_ENTRY_MSR_LOAD_ADDR = 0x0000200a,
	PML_ADDRESS = 0x0000200e,
	TSC_OFFSET = 0x00002010,
	VIRTUAL_APIC_PAGE_ADDR = 0x00002012,
	APIC_ACCESS_ADDR = 0x00002014,
	PI_DESC_ADDR = 0x00002016,
	VM_FUNCTION_CONTROL = 0x00002018,
	EPT_POINTER = 0x0000201a,
	EOI_EXIT_BITMAP0 = 0x0000201c,
	EPTP_LIST_ADDR = 0x00002024,
	VMREAD_BITMAP = 0x00002026,
	VMWRITE_BITMAP = 0x00002028,
	VIRT_EXCEPTION_INFO = 0x0000202a,
	XSS_EXIT_BITMAP = 0x0000202c,
	TSC_MULTIPLIER = 0x00002032,
	GUEST_PHYSICAL_ADDRESS = 0x00002400,
	VMCS_LINK_POINTER = 0x00002800,
	GUEST_IA32_DEBUGCTL = 0x00002802,
	GUEST_PAT = 0x00002804,
	GUEST_EFER = 0x00002806,
	GUEST_PERF_GLOBAL_CTRL = 0x00002808,
	GUEST_PDPTE0 = 0x0000280a,
	GUEST_BNDCFGS = 0x00002812,
	HOST_PAT = 0x00002c00,
	HOST_EFER = 0x00002c02,
	HOST_PERF_GLOBAL_CTRL = 0x00002c04,
	PIN_BASED_VM_EXEC_CONTROL = 0x00004000, // 基于处理器的主vm执行控制信息域
	CPU_BASED_VM_EXEC_CONTROL = 0x00004002,
	EXCEPTION_BITMAP = 0x00004004,			// 异常 BitMap
	PAGE_FAULT_ERROR_CODE_MASK = 0x00004006,
	PAGE_FAULT_ERROR_CODE_MATCH = 0x00004008,
	CR3_TARGET_COUNT = 0x0000400a,
	VM_EXIT_CONTROLS = 0x0000400c,
	VM_EXIT_MSR_STORE_COUNT = 0x0000400e,
	VM_EXIT_MSR_LOAD_COUNT = 0x00004010,
	VM_ENTRY_CONTROLS = 0x00004012,
	VM_ENTRY_MSR_LOAD_COUNT = 0x00004014,
	VM_ENTRY_INTR_INFO = 0x00004016,
	VM_ENTRY_EXCEPTION_ERROR_CODE = 0x00004018,
	VM_ENTRY_INSTRUCTION_LEN = 0x0000401a,
	TPR_THRESHOLD = 0x0000401c,
	SECONDARY_VM_EXEC_CONTROL = 0x0000401e, // 基于处理器的辅助vm执行控制信息域的扩展字段 【Secondary Processor-Based VM-Execution Controls】
	PLE_GAP = 0x00004020,
	PLE_WINDOW = 0x00004022,
	VM_INSTRUCTION_ERROR = 0x00004400,
	VM_EXIT_REASON = 0x00004402,
	VM_EXIT_INTR_INFO = 0x00004404,
	VM_EXIT_INTR_ERROR_CODE = 0x00004406,   // See: VM-Instruction Error Numbers
	IDT_VECTORING_INFO = 0x00004408,
	IDT_VECTORING_ERROR_CODE = 0x0000440a,
	VM_EXIT_INSTRUCTION_LEN = 0x0000440c,
	VMX_INSTRUCTION_INFO = 0x0000440e,
	GUEST_ES_LIMIT = 0x00004800,
	GUEST_CS_LIMIT = 0x00004802,
	GUEST_SS_LIMIT = 0x00004804,
	GUEST_DS_LIMIT = 0x00004806,
	GUEST_FS_LIMIT = 0x00004808,
	GUEST_GS_LIMIT = 0x0000480a,
	GUEST_LDTR_LIMIT = 0x0000480c,
	GUEST_TR_LIMIT = 0x0000480e,
	GUEST_GDTR_LIMIT = 0x00004810,
	GUEST_IDTR_LIMIT = 0x00004812,
	GUEST_ES_AR_BYTES = 0x00004814,
	GUEST_CS_AR_BYTES = 0x00004816,
	GUEST_SS_AR_BYTES = 0x00004818,
	GUEST_DS_AR_BYTES = 0x0000481a,
	GUEST_FS_AR_BYTES = 0x0000481c,
	GUEST_GS_AR_BYTES = 0x0000481e,
	GUEST_LDTR_AR_BYTES = 0x00004820,
	GUEST_TR_AR_BYTES = 0x00004822,
	GUEST_INTERRUPTIBILITY_INFO = 0x00004824,
	GUEST_ACTIVITY_STATE = 0x00004826,
	GUEST_SMBASE = 0x00004828,
	GUEST_SYSENTER_CS = 0x0000482a,
	GUEST_PREEMPTION_TIMER = 0x0000482e,
	HOST_SYSENTER_CS = 0x00004c00,
	CR0_GUEST_HOST_MASK = 0x00006000,
	CR4_GUEST_HOST_MASK = 0x00006002,
	CR0_READ_SHADOW = 0x00006004,
	CR4_READ_SHADOW = 0x00006006,
	CR3_TARGET_VALUE0 = 0x00006008,
	EXIT_QUALIFICATION = 0x00006400, // (哪些指令该字段有效，请参考【处理器虚拟化技术】(第3.10.1.3节))
	GUEST_LINEAR_ADDRESS = 0x0000640a,
	GUEST_CR0 = 0x00006800,
	GUEST_CR3 = 0x00006802,
	GUEST_CR4 = 0x00006804,
	GUEST_ES_BASE = 0x00006806,
	GUEST_CS_BASE = 0x00006808,
	GUEST_SS_BASE = 0x0000680a,
	GUEST_DS_BASE = 0x0000680c,
	GUEST_FS_BASE = 0x0000680e,
	GUEST_GS_BASE = 0x00006810,
	GUEST_LDTR_BASE = 0x00006812,
	GUEST_TR_BASE = 0x00006814,
	GUEST_GDTR_BASE = 0x00006816,
	GUEST_IDTR_BASE = 0x00006818,
	GUEST_DR7 = 0x0000681a,
	GUEST_RSP = 0x0000681c,
	GUEST_RIP = 0x0000681e,
	GUEST_RFLAGS = 0x00006820,
	GUEST_PENDING_DBG_EXCEPTIONS = 0x00006822,
	GUEST_SYSENTER_ESP = 0x00006824,
	GUEST_SYSENTER_EIP = 0x00006826,
	HOST_CR0 = 0x00006c00,
	HOST_CR3 = 0x00006c02,
	HOST_CR4 = 0x00006c04,
	HOST_FS_BASE = 0x00006c06,
	HOST_GS_BASE = 0x00006c08,
	HOST_TR_BASE = 0x00006c0a,
	HOST_GDTR_BASE = 0x00006c0c,
	HOST_IDTR_BASE = 0x00006c0e,
	HOST_SYSENTER_ESP = 0x00006c10,
	HOST_SYSENTER_EIP = 0x00006c12,
	HOST_RSP = 0x00006c14,
	HOST_RIP = 0x00006c16,
};

typedef union _KGDTENTRY64
{
	struct
	{
		UINT16 LimitLow;
		UINT16 BaseLow;
		union
		{
			struct
			{
				UINT8 BaseMiddle;
				UINT8 Flags1;
				UINT8 Flags2;
				UINT8 BaseHigh;
			} Bytes;

			struct
			{
				UINT32 BaseMiddle : 8;
				UINT32 Type : 5;
				UINT32 Dpl : 2;
				UINT32 Present : 1;
				UINT32 LimitHigh : 4;
				UINT32 System : 1;
				UINT32 LongMode : 1;
				UINT32 DefaultBig : 1;
				UINT32 Granularity : 1;
				UINT32 BaseHigh : 8;
			} Bits;
		};
		UINT32 BaseUpper;
		UINT32 MustBeZero;
	}u1;
	struct
	{
		INT64 DataLow;
		INT64 DataHigh;
	}u2;
} KGDTENTRY64, *PKGDTENTRY64;

// 定义X86 IDT Entry (参考白皮书 Vol. 3A 6-17、【x86_x64体系探索及编程】(第16.9.2节))
typedef union _IdtEntry
{
	unsigned __int64 all;
	struct
	{
		unsigned short offset_low;			//!< [0:15]		目标代码 offset
		unsigned short segment_selector;	//!< [16:31]	目标代码段得selector, 必须为64位代码段
		unsigned short ist : 3;				//!< [0:2]		64位TSS中得IST指针
		unsigned short reserved : 5;		//!< [3:7]	
		unsigned short type : 5;			//!< [8:12]		0(System descriptor)、type
		unsigned short dpl : 2;				//!< [13:14]
		unsigned short present : 1;			//!< [15]
		unsigned short offset_middle;		//!< [16:31]
	}Bits;
}IdtEntry, *pIdtEntry;
static_assert(sizeof(IdtEntry) == sizeof(ULONG_PTR), "IdtEntry Size check");

// See: 64-Bit IDT Gate Descriptors
// 定义X64 IDT Entry (参考白皮书 Vol. 3A 6-17、【x86_x64体系探索及编程】(第16.9.2节))
typedef struct _IdtEntry64
{
	IdtEntry idt_entry;
	ULONG32 offset_high;
	ULONG32 reserved;
}IdtEntry64, *pIdtEntry64;
static_assert(sizeof(IdtEntry64) == sizeof(ULONG_PTR)*2, "IdtEntry64 Size check");

/* GDT */
typedef struct _GDT {
	USHORT uLimit;
	ULONG_PTR uBase;
} GDT, *PGDT;

/* IDT */
typedef struct _IDT {
	USHORT uLimit;
	ULONG_PTR uBase;
} IDT, *PIDT;

/* GUEST 环境结构体 */
typedef struct _GUEST_STATE {
	ULONG_PTR cs;
	ULONG_PTR ds;
	ULONG_PTR ss;
	ULONG_PTR es;
	ULONG_PTR fs;
	ULONG_PTR gs;
	GDT gdt;
	IDT idt;
	ULONG_PTR ldtr;
	ULONG_PTR tr;
	ULONG_PTR rsp;
	ULONG_PTR rip;
	ULONG_PTR rflags;
	ULONG_PTR cr0;
	ULONG_PTR cr4;
	ULONG_PTR cr3;
	ULONG_PTR dr7;
	ULONG_PTR msr_debugctl;
	ULONG_PTR msr_sysenter_cs;
	ULONG_PTR msr_sysenter_eip;
	ULONG_PTR msr_sysenter_esp;

	ULONG_PTR msr_perf_global_ctrl;
	ULONG_PTR msr_pat;
	ULONG_PTR msr_efer;
	ULONG_PTR msr_bndcfgs;
} GUEST_STATE, *PGUEST_STATE;

/* HOST 环境结构体 */
typedef struct _HOST_STATE {
	ULONG_PTR cr0;
	ULONG_PTR cr3;
	ULONG_PTR cr4;
	ULONG_PTR rsp;
	ULONG_PTR rip;
	ULONG_PTR cs;
	ULONG_PTR ds;
	ULONG_PTR ss;
	ULONG_PTR es;
	ULONG_PTR fs;
	ULONG_PTR gs;
	ULONG_PTR tr;
	ULONG_PTR fsbase;
	ULONG_PTR gsbase;
	ULONG_PTR trbase;
	GDT gdt;
	IDT idt;
	ULONG_PTR msr_sysenter_cs;
	ULONG_PTR msr_sysenter_esp;
	ULONG_PTR msr_sysenter_eip;
	ULONG_PTR msr_efer;
} HOST_STATE, *PHOST_STATE;

/* LDR_DATA_TABLE_ENTR */
typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG_PTR SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		}u3;
	}u1;
	union {
		struct {
			ULONG TimeDateStamp;
		}u4;
		struct {
			PVOID LoadedImports;
		}u5;
	}u2;
}LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

struct VtInformaitonEntry
{
	union
	{
		unsigned __int64 all;
		struct
		{
			unsigned user_ept : 1;			//!< [0] // 是否开启 VT EPT
			unsigned user_ssdt_hook : 1;	//!< [1] // 是否开启 SSDT HOOK
		}Bits;
	}u1;

	void * driver_object;	// 当前驱动对象
};
/******************************************以下是ssdt table相关信息定义*****************************************************/

// 定义 Ssdt 项
typedef struct _VtSsdtEntry
{
	ULONG32* ssdt_address;		// ssdt 表地址
	ULONG_PTR access_count;		// ssdt 表访问次数
	ULONG_PTR ssdt_funcnumber;	// ssdt 表函数个数
	UCHAR*   param_address;		// ssdt 函数参数个数表的地址
}VtSsdtEntry, *pVtSsdtEntry;

// 定义 Ssdt 表 (逆向分析x64下此表有3张)
typedef struct _VtSsdtTable
{
	VtSsdtEntry service_table;
	VtSsdtEntry service_table_shadow;
	VtSsdtEntry unknow1;
}VtSsdtTable, *pVtSsdtTable;

/***********************************以下是Interrupt or Exception Handling相关定义******************************************/

// @copydoc VmEntryInterruptionInformationField
// 参考 【处理器虚拟化技术】(第3.6.3.1节)
enum InterruptionType {
	kExternalInterrupt = 0,				// 外部硬件中断
	kReserved = 1,						// Not used for VM-Exit
	kNonMaskableInterrupt = 2,			// NMI 中断(不可屏蔽的外部中断)
	kHardwareException = 3,				// 硬件异常 (指 fault 或 abort 事件, 除#BP及#OF异常以外的所有异常, 包括BOUND与UD2指令产生的异常)(包括#DF,#TS,#NP,#SS,#GP,#PF,#AC)
	kSoftwareInterrupt = 4,             // 软件中断 (由 INT 指令产生的中断) (关于中断和异常可以参考【系统虚拟化：原理与实现】(第2.4节))
	kPrivilegedSoftwareException = 5,	// 特权级软件中断 Not used for VM-Exit
	kSoftwareException = 6,				// 软件异常 (指由 INT3 或 INT0指令产生的#BP与#OF异常, 它们属于trap事件)
	kOtherEvent = 7,					// 注入 MTF VM-exit 事件
};

// See: Call and Return Operation for Interrupt or Exception Handling Procedures
// 定义异常或中断的向量号 (参考白皮书 6-10 Vol. 1)
enum InterruptionVector
{
	EXCEPTION_VECTOR_DIVIDE_ERROR,		   // DIV 和 IDIV 指令导致的异常 (#DE)
	EXCEPTION_VECTOR_DEBUG,				   // 任何代码或数据的错误引用或 INT 1 指令导致的异常 (#DB)
	EXCEPTION_VECTOR_NMI_INTERRUPT,		   // 不可屏蔽中断 (#DB)
	EXCEPTION_VECTOR_BREAKPOINT,		   // INT 3 指令导致的异常 (#BP)
	EXCEPTION_VECTOR_OVERFLOW,			   // INT 0 指令导致的异常 (#OF)
	EXCEPTION_VECTOR_BOUND_RANGE_EXCEEDED, // BOUND 指令导致的异常 (#BR)
	EXCEPTION_VECTOR_INVALID_OPCODE,       // 无效的操作码导致的异常 (#UD)
	EXCEPTION_VECTOR_NO_MATH_COPROCESSOR,  // 浮点或 WAIT/FWAIT指令导致的异常 (#NM)
	EXCEPTION_VECTOR_DOUBLE_FAULT,		   // 双重错误导致的异常 (#DF)		
	EXCEPTION_VECTOR_RESERVED0,            // 浮点指令导致的异常 (#MF)
	EXCEPTION_VECTOR_INVALID_TSS,		   // 任务切换或TSS访问导致的异常 (#TS)
	EXCEPTION_VECTOR_SEGMENT_NOT_PRESENT,  // 加载段寄存器或访问系统段导致的异常 (#NP)
	EXCEPTION_VECTOR_STACK_SEGMENT_FAULT,  // 堆栈操作或SS寄存器加载导致的异常 (#SS)
	EXCEPTION_VECTOR_GENERAL_PROTECTION,   // 任何内存引用和其他保护检查导致的异常 (#GP)
	EXCEPTION_VECTOR_PAGE_FAULT,		   // 页面访问异常导致的异常 (#PF)	
	EXCEPTION_VECTOR_RESERVED1,			   // 保留(?)
	EXCEPTION_VECTOR_MATH_FAULT,           // 浮点或WAIT/FWAIT指令导致的异常 (#MF)
	EXCEPTION_VECTOR_ALIGNMENT_CHECK,      // 对齐检测导致的异常 (#AC)
	EXCEPTION_VECTOR_SIMD_FLOATING_POINT_NUMERIC_ERROR, // SIMD浮点指令致的异常 (#VE)
	EXCEPTION_VECTOR_VIRTUAL_EXCEPTION,    // EPT异常导致的异常 (#VE)

	// 21 ~ 31 Reserved

	// Maskable Interrupts

	//
	// NT (Windows) specific exception vectors.
	//
	APC_INTERRUPT = 31,
	DPC_INTERRUPT = 47,
	CLOCK_INTERRUPT = 209,
	IPI_INTERRUPT = 225,
	PMI_INTERRUPT = 254,
};

// See: Page-Fault Error Code
// 参考(白皮书 4-32 Vol. 3A、【处理器虚拟化技术】(第3.5.4节))
union PageFaultErrorCode {
	ULONG32 all;
	struct {
		ULONG32 present : 1;		//!< [0] 0 - 该错误是由于访问不存在页面导致的; 1 - 该错误是由于页面级别保护导致的
		ULONG32 read_write : 1;		//!< [1] 0 - 导致故障的访问是读取; 1 - 导致故障的访问是写入
		ULONG32 user : 1;			//!< [2] 0 - 该错误发生在非 UserMode 下; 1 - 该错误发生在 UserMode 下
		ULONG32 reserved1 : 1;		//!< [3]
		ULONG32 fetch : 1;			//!< [4] 0 - #PF 发生在fetch data时；1 - #PF 发生在fetch instruction
		ULONG32 protection_key : 1;	//!< [5]
		ULONG32 reserved2 : 9;		//!< [6:14]
		ULONG32 sgx_error : 1;		//!< [15]
	}Bits;
};
static_assert(sizeof(PageFaultErrorCode) == 4, "PageFaultErrorCode Size check");

/************************************************以下是vm exit信息域相关定义************************************************/

// See: VMX BASIC EXIT REASONS
// VM-exit 异常信息定义 (参考 【处理器虚拟化技术】(第3.10.1.2节))
enum VmxExitReason
{
	//软件异常导致的,要求异常位图中设置;出现了不可屏蔽中断Nmi并且要求vm执行域的NmiExit置1
	ExitExceptionOrNmi = 0,
	//An external interrupt arrived and the “external-interrupt exiting” VM-execution control was 1.
	ExitExternalInterrupt = 1,
	//3重异常,对它的处理直接蓝屏;The logical processor encountered an exception while attempting to call the double-fault handler and that exception did not itself cause a VM exit due to the exception bitmap
	ExitTripleFault = 2,


	//这几个没有控制域来进行关闭,但很少发生
	//An INIT signal arrived
	ExitInit = 3,
	//A SIPI arrived while the logical processor was in the “wait-for-SIPI” state.
	ExitSipi = 4,
	//An SMI arrived immediately after retirement of an I/O instruction and caused an SMM VM exit
	ExitIoSmi = 5,
	//An SMI arrived and caused an SMM VM exit (see Section 34.15.2) but not immediately after retirement of an I/O instruction
	ExitOtherSmi = 6,


	//At the beginning of an instruction, RFLAGS.IF was 1; events were not blocked by STI or by MOV SS; and the “interrupt-window exiting” VM-execution control was 1.
	ExitPendingInterrupt = 7,
	//At the beginning of an instruction, there was no virtual-NMI blocking; events were not blocked by MOV SS; and the “NMI-window exiting” VM-execution control was 1.
	ExitNmiWindow = 8,

	//必须处理 由指令引发的无条件vmexit,也无法在控制域中关闭
	// Guest software attempted a task switch.
	ExitTaskSwitch = 9,
	ExitCpuid = 10,
	ExitGetSec = 11,

	//Guest software attempted to execute HLT and the “HLT exiting” VM-execution control was 1.
	ExitHlt = 12,


	//必须处理  Guest software attempted to execute INVD.无法在控制域中关闭
	ExitInvd = 13,

	//Guest software attempted to execute INVLPG and the “INVLPG exiting” VM-execution control was 1.
	ExitInvlpg = 14,
	//Guest software attempted to execute RDPMC and the “RDPMC exiting” VM-execution control was 1.
	ExitRdpmc = 15,
	//Guest software attempted to execute RDTSC and the “RDTSC exiting” VM-execution control was 1.
	ExitRdtsc = 16,


	//Guest software attempted to execute RSM in SMM.直接忽略
	ExitRsm = 17,

	//必须处理 
	ExitVmcall = 18,
	ExitVmclear = 19,
	ExitVmlaunch = 20,
	ExitVmptrld = 21,
	ExitVmptrst = 22,
	ExitVmread = 23,
	ExitVmresume = 24,
	ExitVmwrite = 25,
	ExitVmoff = 26,
	ExitVmon = 27,

	//Guest software attempted to access CR0, CR3, CR4, or CR8 using CLTS, LMSW, or MOV CR and the VM-execution control fields 
	//indicate that a VM exit should occur (see Section 25.1 for details). This basic exit reason is not used for trap-like VM exits 
	//following executions of the MOV to CR8 instruction when the “use TPR shadow” VM-execution control is 1.
	//Such VM exits instead use basic exit reason 43.
	ExitCrAccess = 28,
	//Guest software attempted a MOV to or from a debug register and the “MOV-DR exiting” VM-execution control was 1.
	ExitDrAccess = 29,

	//io指令和msr访问都可以进行禁用.这里需要将use I/O bitmaps域置0,并且unconditional I/O exiting置0
	//IN, INS/INSB/INSW/INSD, OUT, OUTS/OUTSB/OUTSW/OUTSD
	//Guest software attempted to execute an I/O instruction and either: 1: The “use I/O bitmaps” VM-execution control was 0 
	//and the “unconditional I/O exiting” VM-execution control was 1. 2: The “use I/O bitmaps” VM-execution control was 1 
	//and a bit in the I/O bitmap associated with one of the ports accessed by the I/O instruction was 1.
	ExitIoInstruction = 30,

	//同理,禁用方式如上
	//Guest software attempted to execute RDMSR and either: 1: The “use MSR bitmaps” VM-execution control was 0. 
	//2: The value of RCX is neither in the range 00000000H – 00001FFFH nor in the range C0000000H – C0001FFFH. 越界意味着#GP异常
	//3: The value of RCX was in the range 00000000H – 00001FFFH and the nth bit in read bitmap for low MSRs is 1, where n was the value of RCX.
	//4: The value of RCX is in the range C0000000H – C0001FFFH and the nth bit in read bitmap for high MSRs is 1, where n is the value of RCX & 00001FFFH.
	ExitMsrRead = 31,
	ExitMsrWrite = 32,

	//致命错误 A VM entry failed one of the checks identified in Section 26.3.1.
	ExitInvalidGuestState = 33,  // See: BASIC VM-ENTRY CHECKS
	//A VM entry failed in an attempt to load MSRs. 
	ExitMsrLoading = 34,
	ExitUndefined35 = 35,
	//Guest software attempted to execute MWAIT and the “MWAIT exiting” VM-execution control was 1.
	ExitMwaitInstruction = 36,
	//A VM entry occurred due to the 1-setting of the “monitor trap flag” VM-execution control and injection of an MTF VM exit as part of VM entry.
	ExitMonitorTrapFlag = 37,
	ExitUndefined38 = 38,
	//Guest software attempted to execute MONITOR and the “MONITOR exiting” VM-execution control was 1.
	ExitMonitorInstruction = 39,
	//Either guest software attempted to execute PAUSE and the “PAUSE exiting” VM-execution control was 1 or 
	//the “PAUSE-loop exiting” VM-execution control was 1 and guest software executed a PAUSE loop with execution time exceeding PLE_Window
	ExitPauseInstruction = 40,
	//致命错误A machine-check event occurred during VM entry
	ExitMachineCheck = 41,
	ExitUndefined42 = 42,
	//The logical processor determined that the value of bits 7:4 of the byte at offset 080H on the virtual-APIC page 
	//was below that of the TPR threshold VM-execution control field while the “use TPR shadow” VMexecution control was 1 either as part of TPR virtualization (Section 29.1.2) or VM entry 
	ExitTprBelowThreshold = 43,
	//Guest software attempted to access memory at a physical address on the APIC-access page 
	//and the “virtualize APIC accesses” VM-execution control was 1
	ExitApicAccess = 44,
	//EOI virtualization was performed for a virtual interrupt whose vector indexed a bit set in the EOIexit bitmap
	ExitVirtualizedEoi = 45,
	//Guest software attempted to execute LGDT, LIDT, SGDT, or SIDT and the “descriptor-table exiting” VM-execution control was 1.
	ExitGdtrOrIdtrAccess = 46,
	//Guest software attempted to execute LLDT, LTR, SLDT, or STR and the “descriptor-table exiting” VM-execution control was 1
	ExitLdtrOrTrAccess = 47,
	//An attempt to access memory with a guest-physical address was disallowed by the configuration of the EPT paging structures.
	ExitEptViolation = 48,
	//致命错误An attempt to access memory with a guest-physical address encountered a misconfigured EPT paging-structure entry.
	ExitEptMisconfig = 49,
	//必须处理 Guest software attempted to execute INVEPT.
	ExitInvept = 50,
	//Guest software attempted to execute RDTSCP and the “enable RDTSCP” and “RDTSC exiting” VM-execution controls were both 1.
	ExitRdtscp = 51,
	//The preemption timer counted down to zero.
	ExitVmxPreemptionTime = 52,
	//必须处理 Guest software attempted to execute INVVPID.
	ExitInvvpid = 53,
	//Guest software attempted to execute WBINVD and the “WBINVD exiting” VM-execution control was 1.
	ExitWbinvd = 54,
	//必须处理 Guest software attempted to execute XSETBV.
	ExitXsetbv = 55,
	//Guest software completed a write to the virtual-APIC page that must be virtualized by VMM software
	ExitApicWrite = 56,
	//Guest software attempted to execute RDRAND and the “RDRAND exiting” VM-execution control was 1.
	ExitRdrand = 57,
	//Guest software attempted to execute INVPCID and the “enable INVPCID” and “INVLPG exiting” VM-execution controls were both 1.
	ExitInvpcid = 58,
	//可以关闭 Guest software invoked a VM function with the VMFUNC instruction and the VM function 
	//either was not enabled or generated a function-specific condition causing a VM exit.
	ExitVmfunc = 59,
	//可以关闭 Guest software attempted to execute ENCLS and “enable ENCLS exiting” VM-execution control was 1 and either (1) EAX < 63 
	//and the corresponding bit in the ENCLS-exiting bitmap is 1; or (2) EAX ≥ 63 and bit 63 in the ENCLS-exiting bitmap is 1
	ExitUndefined60 = 60,
	//可以关闭 Guest software attempted to execute RDSEED and the “RDSEED exiting” VM-execution control was 1.
	ExitRdseed = 61,
	//The processor attempted to create a page-modification log entry and the value of the PML index was not in the range 0–511.
	ExitUndefined62 = 62,
	//可以关闭 Guest software attempted to execute XSAVES, the “enable XSAVES/XRSTORS” was 1, 
	//and a bit was set in the logical-AND of the following three values: EDX:EAX, the IA32_XSS MSR, and the XSS-exiting bitmap.
	ExitXsaves = 63,
	//可以关闭 Guest software attempted to execute XRSTORS, the “enable XSAVES/XRSTORS” was 1, 
	//and a bit was set in the logical-AND of the following three values: EDX:EAX, the IA32_XSS MSR, and the XSS-exiting bitmap.
	ExitXrstors = 64,
};

/************************************************以下是cpuid指令相关定义************************************************/

// See: Feature Information Returned in the ECX Register (白皮书 3-212)
// CPUID: RAX 为 1 时, RCX 的定义
typedef union _CpudFeatureInfoByEcx
{
	ULONG32 all;
	struct
	{
		unsigned sse3 : 1;	    // [0 bit] Streaming SIMD Extensions 3 (SSE3). 值1表示处理器支持该技术。
		unsigned pclmulqdq : 1; // [1 bit] PCLMULQDQ. 值1表示处理器支持PCLMULQDQ指令。
		unsigned dtes64 : 1;	// [2 bit] 64-bit DS Area. 值1表示处理器使用64位布局支持DS区域。
		unsigned monitor : 1;   // [3 bit] MONITOR/MWAIT. 值1表示处理器支持此功能。
		unsigned ds_cpl : 1;    // [4 bit] CPL Qualified Debug Store. 值1表示处理器支持DebugStore特性的扩展，以允许CPL限定的分支消息存储。
		unsigned vmx : 1;	    // [5 bit] Virtual Machine Extensions(虚拟机扩展位). 值1表示处理器支持该技术。
		unsigned smx : 1;	    // [6 bit] Safer Mode Extensions. 值1表示处理器支持该技术。
		unsigned eist : 1;      // [7 bit] Enhanced Intel SpeedStep® technology(Intel SpeedStep 动态节能技术).值1表示处理器支持该技术。
		unsigned tm2 : 1;       // [8 bit] Thermal Monitor 2. 值1表示处理器是否支持该技术。
		unsigned ssse3 : 1;     // [9 bit] 值1表示存在补充流SIMD扩展3(SSSE3)。 值为0表示处理器中不存在指令扩展。
		unsigned cnxt_id : 1;   // [10 bit] L1 Context ID. 值1表示L1数据缓存模式可以设置为自适应模式或共享模式。 值为0表示不支持此功能
		unsigned sdbg : 1;      // [11 bit] 值1表示处理器支持用于硅调试的IA32_DEBUG_INTERFACE MSR。
		unsigned fma : 1;       // [12 bit] 值1表示处理器支持使用YMM状态的FMA扩展。
		unsigned cmpxchg16b : 1;// [13 bit] CMPXCHG16B Available. 值1表示该特性可用。
		unsigned xtrrupdatecontrol : 1; // [14 bit] xTPR Update Control. 值1表示处理器支持更改IA32_MISC_ENABLE[bit 23]。
		unsigned pdcm : 1;      // [15 bit] Perfmon and Debug Capability: 值1表示处理器支持性能和调试功能指示MSR IA32_PERF_CAPABILITIES
		unsigned reserved : 1;  // [16 bit] 保留
		unsigned pcid : 1;      // [17 bit] Process-context identifiers. A value of 1 indicates that the processor supports PCIDs and that software may set CR4.PCIDE to 1.
		unsigned dca : 1;       // [18 bit] A value of 1 indicates the processor supports the ability to prefetch data from a memory mapped device.
		unsigned sse41 : 1;     // [19 bit] A value of 1 indicates that the processor supports SSE4.1.
		unsigned sse42 : 1;     // [20 bit] A value of 1 indicates that the processor supports SSE4.2.
		unsigned x2apic : 1;    // [21 bit] A value of 1 indicates that the processor supports x2APIC feature.
		unsigned movbe : 1;     // [22 bit] A value of 1 indicates that the processor supports MOVBE instruction.
		unsigned popcnt : 1;    // [23 bit] A value of 1 indicates that the processor supports the POPCNT instruction.
		unsigned tsc_deadline : 1; // [24 bit] 值1表示处理器的本地APIC定时器支持使用TSC截止日期值进行一次操作。
		unsigned aesni : 1;     // [25 bit] A value of 1 indicates that the processor supports the AESNI instruction extensions.
		unsigned xsave : 1;     // [26 bit] A value of 1 indicates that the processor supports the XSAVE/XRSTOR processor extended states feature, the XSETBV / XGETBV instructions, and XCR0.
		unsigned osxsave : 1;   // [27 bit] A value of 1 indicates that the OS has set CR4.OSXSAVE[bit 18] to enable XSETBV/XGETBV instructions to access XCR0 and to support processor extended state management using XSAVE / XRSTOR.
		unsigned avx : 1;       // [28 bit] A value of 1 indicates the processor supports the AVX instruction extensions.
		unsigned f16c : 1;      // [29 bit] 值1表示处理器支持16位浮点转换指令。
		unsigned rdrand : 1;    // [30 bit] A value of 1 indicates that processor supports RDRAND instruction.
		unsigned notused : 1;   // [31 bit] Always returns 0.
	}Bits;
}CpudFeatureInfoByEcx, *pCpudFeatureInfoByEcx;
static_assert(sizeof(CpudFeatureInfoByEcx) == sizeof(ULONG32), "CpudFeatureInformationByEcx size error!");

/************************************************以下是重要msr寄存器相关定义************************************************/

// See: ARCHITECTURAL MSRS (请看白皮书 2-4 Vol.4)
// IA32_FEATURE_CONTROL 寄存器结构定义 
typedef union _Ia32FeatureControlMsr
{						   
	ULONGLONG all;
	struct
	{
		ULONGLONG lock : 1;					 // [0 bit] 置锁位, 为0则VMXON不能调用, 为1那么WRMSR(写 MSR 寄存器指令)不能去写这个寄存器。该位在系统上电后便不能修改。
											 // BIOS 通过修改这个寄存器来设置是否支持虚拟化操作。在支持虚拟化的操作下，BIOS还要设置Bit1和Bit2	
		ULONGLONG enable_smx : 1;			 // [1 bit] 为 0, 则 VMXON 不能在SMX(安全扩展模式, 请参考intel白皮书5-34)操作系统中调用
		ULONGLONG enable_vmxon : 1;          // [2 bit] 为 0, 则 VMXON 不能在SMX操作系统外调用
		ULONGLONG reserved1 : 5;             //!< [3:7]
		ULONGLONG enable_local_senter : 7;   //!< [8:14]
		ULONGLONG enable_global_senter : 1;  //!< [15]
		ULONGLONG reserved2 : 16;            //!<
		ULONGLONG reserved3 : 32;            //!< [16:63]
	}Bits;
}Ia32FeatureControlMsr, *pIa32FeatureControlMsr;
static_assert(sizeof(Ia32FeatureControlMsr) == sizeof(ULONGLONG), "Ia32FeatureControlMsr size error!");

// See: VPID AND EPT CAPABILITIES (请看白皮书 Vol. 3D A-7, 【处理器虚拟化技术】(157页))
typedef union _Ia32VmxEptVpidCapMsr
{
	unsigned __int64 all;
	struct {
		unsigned support_execute_only_pages : 1;                        //!< [0]    为1时, 允许 execeute-only
		unsigned reserved1 : 5;                                         //!< [1:5]  
		unsigned support_page_walk_length4 : 1;                         //!< [6]	支持4级页表
		unsigned reserved2 : 1;                                         //!< [7]	
		unsigned support_uncacheble_memory_type : 1;                    //!< [8]	EPT 允许使用 UC 类型(0),请参考【处理器虚拟化技术】(第4.4.1.3节)
		unsigned reserved3 : 5;                                         //!< [9:13] 
		unsigned support_write_back_memory_type : 1;                    //!< [14]	EPT 允许使用 WB 类型(6)
		unsigned reserved4 : 1;                                         //!< [15]
		unsigned support_pde_2mb_pages : 1;                             //!< [16]	EPT 支持2MB页面
		unsigned support_pdpte_1_gb_pages : 1;                          //!< [17]	EPT 支持1GB页面
		unsigned reserved5 : 2;                                         //!< [18:19]
		unsigned support_invept : 1;                                    //!< [20]	为1时, 支持 invept 指令
		unsigned support_accessed_and_dirty_flag : 1;                   //!< [21]	为1时, 支持 dirty 标志位
		unsigned reserved6 : 3;                                         //!< [22:24]
		unsigned support_single_context_invept : 1;                     //!< [25]	为1时, 支持 single-context invept
		unsigned support_all_context_invept : 1;                        //!< [26]	为1时, 支持 all-context invept
		unsigned reserved7 : 5;                                         //!< [27:31]
		unsigned support_invvpid : 1;                                   //!< [32]	为1时, 支持 invvpid 指令
		unsigned reserved8 : 7;                                         //!< [33:39]
		unsigned support_individual_address_invvpid : 1;                //!< [40]	为1时, 支持 individual-address invvpid 指令
		unsigned support_single_context_invvpid : 1;                    //!< [41]	为1时, 支持 single-context invvpid 指令
		unsigned support_all_context_invvpid : 1;                       //!< [42]	为1时, 支持 all-context invvpid 指令
		unsigned support_single_context_retaining_globals_invvpid : 1;  //!< [43]	为1时, 支持 single-context-retaining-globals invvpid
		unsigned reserved9 : 20;                                        //!< [44:63]
	}Bits;
}Ia32VmxEptVpidCapMsr, *pIa32VmxEptVpidCapMsr;
static_assert(sizeof(Ia32VmxEptVpidCapMsr) == sizeof(ULONGLONG), "Ia32VmxEptVpidCapMsr size error!");

// See: BASIC VMX INFORMATION (请看白皮书 Vol. 3D A-1)
typedef union _Ia32VmxBasicMsr
{
	unsigned __int64 all;
	struct {
		unsigned revision_identifier : 31;    //!< [0:30]
		unsigned reserved1 : 1;               //!< [31]    总为0
		unsigned region_size : 12;            //!< [32:43]
		unsigned region_clear : 1;            //!< [44]
		unsigned reserved2 : 3;               //!< [45:47]
		unsigned supported_ia64 : 1;          //!< [48]
		unsigned supported_dual_moniter : 1;  //!< [49]
		unsigned memory_type : 4;             //!< [50:53]
		unsigned vm_exit_report : 1;          //!< [54]
		unsigned vmx_capability_hint : 1;     //!< [55]
		unsigned reserved3 : 8;               //!< [56:63] 保留
	} Bits;
}Ia32VmxBasicMsr, *pIa32VmxBasicMsr;
static_assert(sizeof(Ia32VmxBasicMsr) == sizeof(ULONGLONG), "Ia32VmxBasicMsr size error!");

// See: Extended Feature Enable Register
// 定义 IA32_EFER 寄存器结构体 (参考白皮书 Vol. 3A 2-9)
union Ia32VmxEfer
{
	unsigned __int64 all;
	struct
	{
		unsigned sce : 1;				//!< [0]  是否启用 x64 的 syscall/sysret 指令
		unsigned reserved1 : 7;			//!< [1:7]
		unsigned lme : 1;				//!< [8]  Enables IA-32e mode operation.
		unsigned reserved2 : 1;			//!< [9]
		unsigned lma : 1;				//!< [10] Indicates IA-32e mode is active when set.
		unsigned nxe : 1;				//!< [11] 是否启用执行禁用位(XD)
	}Bits;
};

// See: Definitions of Primary Processor-Based VM-Execution Controls (请看白皮书 24-10 Vol.3C)
// 处理器 VMX non-root operation 模式下的主要行为由这个字段控制
typedef union _VmxProcessorBasedControls {
	unsigned int all;
	struct
	{
		unsigned reserved1 : 2;                   //!< [0:1] 保留，固定为0
		unsigned interrupt_window_exiting : 1;    //!< [2]   为1时, 在IF=1斌且中断没被阻塞时, 产生 VM-EXIT
		unsigned use_tsc_offseting : 1;           //!< [3]   为1时, 读取TSC值时, 返回的TSC值加上一个偏移值
		unsigned reserved2 : 3;                   //!< [4:6] 保留，固定为1
		unsigned hlt_exiting : 1;                 //!< [7]   为1时，执行HLT指令产生的 VM-EXIT
		unsigned reserved3 : 1;                   //!< [8]	 保留，固定为1
		unsigned invlpg_exiting : 1;              //!< [9]   为1时，执行INVLPG指令产生VM-EXIT
		unsigned mwait_exiting : 1;               //!< [10]  为1时，执行MWAIT指令产生VM-EXIT
		unsigned rdpmc_exiting : 1;               //!< [11]  为1时，执行RDPMC指令产生VM-EXIT
		unsigned rdtsc_exiting : 1;               //!< [12]  为1时，执行RDTSC指令产生VM-EXIT
		unsigned reserved4 : 2;                   //!< [13:14] 保留，固定为1
		unsigned cr3_load_exiting : 1;            //!< [15]  为1时, 写CR3寄存器产生VM-EXIT
		unsigned cr3_store_exiting : 1;           //!< [16]  为1时, 读CR3寄存器产生VM-EXIT
		unsigned reserved5 : 2;                   //!< [17:18] 保留，固定为0
		unsigned cr8_load_exiting : 1;            //!< [19]  为1时, 写CR8寄存器产生VM-EXIT
		unsigned cr8_store_exiting : 1;           //!< [20]  为1时, 读CR8寄存器产生VM-EXIT
		unsigned use_tpr_shadow : 1;              //!< [21]  为1时, 启用"virtual-APIC page"页面来虚拟化local APIC
		unsigned nmi_window_exiting : 1;          //!< [22]  为1时, 开virtual-NMI window 时产生VM-EXIT
		unsigned mov_dr_exiting : 1;              //!< [23]  为1时, 读写DR寄存器产生VM-EXIT
		unsigned unconditional_io_exiting : 1;    //!< [24]  为1时, 执行IN/OUT或INS/OUTS类指令产生VM-EXIT
		unsigned use_io_bitmaps : 1;              //!< [25]  为1时, 启用I/O bitmap
		unsigned reserved6 : 1;                   //!< [26]  保留，固定为1
		unsigned monitor_trap_flag : 1;           //!< [27]  为1时, 启用MTF调试功能
		unsigned use_msr_bitmaps : 1;             //!< [28]  为1时, 启用MSR bitmap
		unsigned monitor_exiting : 1;             //!< [29]  为1时, 执行MONITOR指令产生VM-EXIT
		unsigned pause_exiting : 1;               //!< [30]  为1时, 执行PAUSE指令产生VM-EXIT
		unsigned activate_secondary_control : 1;  //!< [31]  为1时, secondary processor-based VM-execution control 字段有效
	}Bits;
}VmxProcessorBasedControls, *pVmxProcessorBasedControls;
static_assert(sizeof(VmxProcessorBasedControls) == sizeof(ULONG), "VmxProcessorBasedControls size error!");

// See: Definitions of Secondary Processor-Based VM-Execution Controls (请看白皮书 Vol.3C 24-11)
// 该字段用于提供 VMX 扩展的控制功能, 只在 VmxProcessorBasedControls.activate_secondary_control 为1时有效
typedef union _VmxSecondaryProcessorBasedControls
{
	unsigned int all;
	struct {
		unsigned virtualize_apic_accesses : 1;            //!< [0] 为1时, 虚拟化访问 APIC-access page
		unsigned enable_ept : 1;                          //!< [1] 为1时, 启用EPT
		unsigned descriptor_table_exiting : 1;            //!< [2] 为1时, 访问GDTR/LDTR/IDTR或者TR产生VM-EXIT
		unsigned enable_rdtscp : 1;                       //!< [3] 为0时, 执行RDTSCP产生#UD异常
		unsigned virtualize_x2apic_mode : 1;              //!< [4] 为1时, 虚拟化访问x2APIC MSR
		unsigned enable_vpid : 1;                         //!< [5] 为1时, 启用VPID机制
		unsigned wbinvd_exiting : 1;                      //!< [6] 为1时, 执行WBINVD指令产生VM-EXIT
		unsigned unrestricted_guest : 1;                  //!< [7] 为1时, Guest 可以使用非分页保护模式或实模式
		unsigned apic_register_virtualization : 1;        //!< [8] 为1时, 支持访问virtual-APIC page 内的虚拟寄存器
		unsigned virtual_interrupt_delivery : 1;          //!< [9] 为1时, 支持虚拟中断的delivery
		unsigned pause_loop_exiting : 1;                  //!< [10] 为1时, 决定PASUE指令是否产生VM-EXIT
		unsigned rdrand_exiting : 1;                      //!< [11] 为1时, 执行RDRAND指令产生VM-EXIT
		unsigned enable_invpcid : 1;                      //!< [12] 为0时, 执行INVPCID指令产生#UD异常
		unsigned enable_vm_functions : 1;                 //!< [13] 为1时, VMX non-root operation 内可以执行VMFUNC指令
		unsigned vmcs_shadowing : 1;                      //!< [14] 为1时, VMX non-root operation 内可以执行VMREAD和VMWRITE指令
		unsigned enable_encls_exiting : 1;                //!< [15] 为1时, 执行ENCLS指令产生VM-EXIT
		unsigned rdseed_exiting : 1;                      //!< [16] 为1时, 执行RDSEED指令产生VM-EXIT
		unsigned enable_pml : 1;                          //!< [17] 为1时, 执行RDSEED指令产生VM-EXIT
		unsigned ept_violation_ve : 1;                    //!< [18] If this control is 1, an access to a guest-physical address that sets an EPT dirty bit first adds an entry to the page - modification log.
		unsigned conceal_vmx_from_pt : 1;                 //!< [19] 
		unsigned enable_xsaves_xstors : 1;                //!< [20] 如果此控件为0，则XSAVES或XRSTORS的任一执行都会导致#UD。
		unsigned reserved1 : 1;                           //!< [21] 
		unsigned mode_based_execute_control_for_ept : 1;  //!< [22] If this control is 1, EPT execute permissions are based on whether the linear address being accessed is supervisor mode or user mode.
		unsigned sun_page_write_permissions_for_ept : 1;  //!< [23] If this control is 1, EPT write permissions may be specified at the granularity of 128 bytes.
		unsigned reserved2 : 1;                           //!< [24]
		unsigned use_tsc_scaling : 1;                     //!< [25]
		unsigned reserved3 : 2;                           //!< [26:27]
		unsigned enable_enclv_exiting : 1;				  //!< [28] 
	}Bits;
}VmxSecondaryProcessorBasedControls, *pVmxSecondaryProcessorBasedControls;
static_assert(sizeof(VmxSecondaryProcessorBasedControls) == sizeof(ULONG), "VmxSecondaryProcessorBasedControls size error!");

// See: Definitions of Pin-Based VM-Execution Controls (白皮书 Vol. 3C 24-9)
// 该字段用于管理处理器异常事件(如：中断等)
typedef union _VmxPinBasedControls 
{
	unsigned int all;
	struct {
		unsigned external_interrupt_exiting : 1;    //!< [0]    // 为1时, 发生外部中断则产生 VM-EXIT
		unsigned reserved1 : 2;                     //!< [1:2]  // 保留, 固定为1
		unsigned nmi_exiting : 1;                   //!< [3]    // 为1时, 发生NMI则产生 VM-EXIT
		unsigned reserved2 : 1;                     //!< [4]	// 保留, 固定为1
		unsigned virtual_nmis : 1;                  //!< [5]	// 为1时, 定义 virtual NMI
		unsigned activate_vmx_peemption_timer : 1;  //!< [6]	// 为1时，启用 vmx-peemption 定时器
		unsigned process_posted_interrupts : 1;     //!< [7]	// 为1时，启用 posted-interrupt processing 机制处理虚拟中断
	}Bits;
}VmxPinBasedControls, *pVmxPinBasedControls;
static_assert(sizeof(VmxPinBasedControls) == sizeof(ULONG), "VmxPinBasedControls size error!");

/************************************************以下是vm entry控制域相关定义************************************************/

// See: Definitions of VM-Entry Controls (白皮书 Vol. 3C 24-19、【处理器虚拟化技术】第3.6节)
// 该字段用于控制 VMX 的基本操作
typedef union _VmxVmEntryControls
{
	unsigned int all;
	struct {
		unsigned reserved1 : 2;                          //!< [0:1] 
		unsigned load_debug_controls : 1;                //!< [2]	为1时, 从(guest-state)加载debug寄存器
		unsigned reserved2 : 6;                          //!< [3:8]
		unsigned ia32e_mode_guest : 1;                   //!< [9]	为1时, 进入IA-32e模式
		unsigned entry_to_smm : 1;                       //!< [10]	为1时, 进入SMM模式
		unsigned deactivate_dual_monitor_treatment : 1;  //!< [11]	为1时, 返回executive monitor, 关闭 SMM 双重监控处理
		unsigned reserved3 : 1;                          //!< [12]
		unsigned load_ia32_perf_global_ctrl : 1;         //!< [13]	为1时, 加载 ia32_perf_global_ctrl
		unsigned load_ia32_pat : 1;                      //!< [14]	为1时, 加载 ia32_pat
		unsigned load_ia32_efer : 1;                     //!< [15]	为1时, 加载 ia32_efer
		unsigned load_ia32_bndcfgs : 1;                  //!< [16]	为1时, 加载 ia32_bndcfgs
		unsigned conceal_vmentries_from_intel_pt : 1;    //!< [17]	
	}Bits;
}VmxVmEntryControls, *pVmxVmEntryControls;
static_assert(sizeof(VmxVmEntryControls) == sizeof(ULONG), "VmxVmEntryControls size error!");

/************************************************以下是vm exit控制域相关定义************************************************/

// See: Definitions of VM-Exit Controls (白皮书 24-18 Vol. 3C、【处理器虚拟化技术】第3.7.1节)
// 该字段用于控制发生 VM-EXIT 时的处理器行为
typedef union _VmxVmExitControls
{
	unsigned int all;
	struct {
		unsigned reserved1 : 2;                        //!< [0:1]	
		unsigned save_debug_controls : 1;              //!< [2]		为1时, 保存debug寄存器
		unsigned reserved2 : 6;                        //!< [3:8]
		unsigned host_address_space_size : 1;          //!< [9]		为1时, 返回到IA-32e模式
		unsigned reserved3 : 2;                        //!< [10:11]
		unsigned load_ia32_perf_global_ctrl : 1;       //!< [12]	为1时, 加载 ia32_perf_global_ctrl
		unsigned reserved4 : 2;                        //!< [13:14]
		unsigned acknowledge_interrupt_on_exit : 1;    //!< [15]	为1时, VM-exit 时处理器响应中断寄存器, 读取中断向量号
		unsigned reserved5 : 2;                        //!< [16:17]
		unsigned save_ia32_pat : 1;                    //!< [18]	为1时, 保存 ia32_pat
		unsigned load_ia32_pat : 1;                    //!< [19]	为1时, 加载 ia32_pat
		unsigned save_ia32_efer : 1;                   //!< [20]	为1时, 保存 ia32_efer
		unsigned load_ia32_efer : 1;                   //!< [21]	为1时, 加载 ia32_efer
		unsigned save_vmx_preemption_timer_value : 1;  //!< [22]	为1时, VM-exit 时保存VMX定时器计数值
		unsigned clear_ia32_bndcfgs : 1;               //!< [23]	此控件确定IA32_BNDCFGS的MSR是否在VM退出时被清除。
		unsigned conceal_vmexits_from_intel_pt : 1;    //!< [24]
	}Bits;
}VmxVmExitControls, *pVmxVmExitControls;
static_assert(sizeof(VmxVmExitControls) == sizeof(ULONG), "VmxVmExitControls size error!");

/************************************************以下是vm exit信息域相关定义************************************************/

// See: Format of Exit Reason in Basic VM-Exit Information
// 定义 Exit reason 字段 (参考 【处理器虚拟化技术】(第3.10.1.1节))
typedef union _VmExitInformation
{
	unsigned int all;
	struct
	{
		unsigned short reason;                     //!< [0:15]	保存VM退出原因值
		unsigned short reserved1 : 12;             //!< [16:27]
		unsigned short pending_mtf_vm_exit : 1;    //!< [28]	为1时，指示SMM VM-exit 时, 存在 pending MTF VM-exit 事件
		unsigned short vm_exit_from_vmx_root : 1;  //!< [29]	为1时，指示SMM VM-exit从VMX root-operation 
		unsigned short reserved2 : 1;              //!< [30]
		unsigned short vm_entry_failure : 1;       //!< [31]	为1时, 表明是在VM-entry过程中引发VM-exit
	}Bits;
}VmExitInformation, *pVmExitInformation;

// See: Format of the VM-Exit Interruption-Information Field
// (直接向量事件类含义, 请参考【处理器虚拟化技术】(第3.10.2节、3.10.3.1节))
// 定义 instruction 字段结构体 (参考白皮书 Vol. 3C 24-23,【处理器虚拟化技术】(第3.10.2.1节))
typedef union _VmxVmExit_Interrupt_info
{
	ULONG32 all;
	struct {
		ULONG32 vector : 8;             //!< [0:7]		记录异常或中断的向量号
		ULONG32 interruption_type : 3;  //!< [8:10]		中断类型 (0-外部中断; 1-保留; 2-NMI; 3-硬件异常; 4-保留; 5-保留; 6-软件异常; 7-保留)
		ULONG32 error_code_valid : 1;   //!< [11]		为 1 时，有错误码 (外部中断、NMI及软件异常并不存在错误码)
		ULONG32 nmi_unblocking : 1;     //!< [12]		为 1 时, 表示"blocaking by NMI"被解除
		ULONG32 reserved : 18;          //!< [13:30]	为 0
		ULONG32 valid : 1;              //!< [31]		为 1 时， VM-Exit Interruption-Information 字段有效
	}Bits;
}VmxVmExit_Interrupt_info, *pVmxVmExit_Interrupt_info;
static_assert(sizeof(VmxVmExit_Interrupt_info) == sizeof(ULONG32), "VmxVmExit_Interrupt_info size error!");

// See: Format of the VM-Exit Instruction-Information Field (参考白皮书 27-16 Vol. 3C)
// LIDT, LGDT, SIDT, or SGDT
// 定义 Gdtr Or Idtr Access Instruction-Information 结构体
union GdtrOrIdtrInstInformation
{
	ULONG32 all;
	struct {
		ULONG32 scalling : 2;                //!< [0:1]		寄存器索引	(0: no scaling; 1: scale by 2; 2: scale by 4; 3: scale by 8;)
		ULONG32 reserved1 : 5;               //!< [2:6]
		ULONG32 address_size : 3;            //!< [7:9]		地址大小		(0: 16-bit; 1: 32-bit; 2: 64-bit)
		ULONG32 reserved2 : 1;               //!< [10]
		ULONG32 operand_size : 1;            //!< [11]		操作数大小	(0: 16-bit; 1: 32-bit)
		ULONG32 reserved3 : 3;               //!< [12:14]
		ULONG32 segment_register : 3;        //!< [15:17]	段选择子(0-ES、1-CS、2-SS、3-DS、4-FS、5-GS)
		ULONG32 index_register : 4;          //!< [18:21]	操作数寄存器(0-RAX、1-RCX、2-RDX、3-RBX、4-RSP、5-RBP、6-RSI、7-RDI、(8~15)-(R8~R15))
		ULONG32 index_register_invalid : 1;  //!< [22]		是否有 index_register (0 = valid; 1 = invalid)
		ULONG32 base_register : 4;           //!< [23:26]	基址寄存器(0-RAX、1-RCX、2-RDX、3-RBX、4-RSP、5-RBP、6-RSI、7-RDI、(8~15)-(R8~R15))
		ULONG32 base_register_invalid : 1;   //!< [27]		是否有 base_register (0 = valid; 1 = invalid)
		ULONG32 instruction_identity : 2;    //!< [28:29]	指令访问类型 （0-SGDT、1-SIDT、2-LGDT、3-LIDT）
		ULONG32 reserved4 : 2;               //!< [30:31]
	}Bits;
};
static_assert(sizeof(GdtrOrIdtrInstInformation) == sizeof(ULONG32), "GdtrOrIdtrInstInformation size error!");

// See: Format of the VM-Exit Instruction-Information Field (参考白皮书 27-18 Vol. 3C)
// LLDT, LTR, SLDT, and STR
// 定义 Ldtr Or Tr Access Instruction-Information 结构体
union LdtrOrTrInstInformation {
	ULONG32 all;
	struct {
		ULONG32 scalling : 2;                //!< [0:1]		寄存器索引	(0: no scaling; 1: scale by 2; 2: scale by 4; 3: scale by 8;)
		ULONG32 reserved1 : 1;               //!< [2]
		ULONG32 register1 : 4;               //!< [3:6]		(0-RAX、1-RCX、2-RDX、3-RBX、4-RSP、5-RBP、6-RSI、7-RDI、(8~15)-(R8~R15))
		ULONG32 address_size : 3;            //!< [7:9]		地址大小		(0: 16-bit; 1: 32-bit; 2: 64-bit)
		ULONG32 register_access : 1;         //!< [10]		Mem/Reg (0 = memory; 1 = register).
		ULONG32 reserved2 : 4;               //!< [11:14]	
		ULONG32 segment_register : 3;        //!< [15:17]	段选择子(0-ES、1-CS、2-SS、3-DS、4-FS、5-GS)
		ULONG32 index_register : 4;          //!< [18:21]	操作数寄存器(0-RAX、1-RCX、2-RDX、3-RBX、4-RSP、5-RBP、6-RSI、7-RDI、(8~15)-(R8~R15))
		ULONG32 index_register_invalid : 1;  //!< [22]		是否有 index_register (0 = valid; 1 = invalid)
		ULONG32 base_register : 4;           //!< [23:26]	基址寄存器(0-RAX、1-RCX、2-RDX、3-RBX、4-RSP、5-RBP、6-RSI、7-RDI、(8~15)-(R8~R15))
		ULONG32 base_register_invalid : 1;   //!< [27]		是否有 base_register (0 = valid; 1 = invalid)
		ULONG32 instruction_identity : 2;    //!< [28:29]	指令访问类型 （0-SLDT、1-STR、2-LLDT、3-LTR）
		ULONG32 reserved4 : 2;               //!< [30:31]
	}Bits;
};
static_assert(sizeof(LdtrOrTrInstInformation) == 4, "LdtrOrTrInstInformation Size check");

/************************************************以下是exit qualification字段的相关定义************************************************/

// See: Exit Qualification for Control-Register Accesses (参考【处理器虚拟化技术】(第3.10.1.10节))
// 访问控制寄存器引发的 VM-exit (白皮书 27-6 Vol. 3C, 注意访问寄存器除了使用MOV-CR类指令, 还包括CLTS和LMSW指令。)
enum MovCrAccessType {
	kMoveToCr = 0, // MOV crx, reg
	KMobeFromCr,   // MOV reg, crx
	kClts,
	kLmsw
};
typedef union _CrxVmExitQualification
{
	ULONG_PTR all;
	struct
	{
		ULONG_PTR crn : 4;				  //!< [0:3]	记录访问的控制寄存器
		ULONG_PTR access_type : 2;		  //!< [4:5]	访问类型 (MovCrAccessType)
		ULONG_PTR lmsw_operand_type : 1;  //!< [6]		LMSW指令的操作数类型
		ULONG_PTR reserved1 : 1;          //!< [7]		
		ULONG_PTR gp_register : 4;        //!< [8:11]	记录使用的通用寄存器
		ULONG_PTR reserved2 : 4;          //!< [12:15]	
		ULONG_PTR lmsw_source_data : 16;  //!< [16:31]	LMSW指令的源操作数
		ULONG_PTR reserved3 : 32;         //!< [32:63]
	}Bits;
}CrxVmExitQualification, *pCrxVmExitQualification;

/************************************************以下是寄存器相关定义************************************************/

// See: CONTROL REGISTERS (白皮书 2-14 Vol.3A)
typedef union _Cr4
{
	ULONG_PTR all;
	struct
	{
		unsigned vme : 1; // [0 bit] Virtual Mode Extensions
		unsigned pvi : 1; // [1 bit] Virtual-8086 Mode Extensions
		unsigned tsd : 1; // [2 bit] Time Stamp Disable
		unsigned de : 1;  // [3 bit] Debugging Extensions
		unsigned pse : 1; // [4 bit] Page Size Extensions
		unsigned pae : 1; // [5 bit] Physical Address Extension
		unsigned mce : 1; // [6 bit] Machine-Check Enable
		unsigned pge : 1; // [7 bit] Page Global Enable
		unsigned pce : 1; // [8 bit] Performance-Monitoring Counter Enable
		unsigned osfxsr : 1; // [9 bit] Operating System Support for FXSAVE and FXRSTOR instructions
		unsigned osxmmexcpt : 1; // [10 bit] Operating System Support for Unmasked SIMD Floating-Point Exceptions
		unsigned umip : 1;	     // [11 bit] User-Mode Instruction Prevention. (设置时，如果CPL>0：SGDT、SIDT、SLDT、SMSW和STR，则无法执行。 这种执行的尝试会导致一般保护异常(#GP))
		unsigned reserved1 : 1;  // [12 bit]
		unsigned vmxe : 1;       // [13 bit] VMX-Enable Bit. 设置时启用VMX操作。
		unsigned smxe : 1;		 // [14 bit] SMX-Enable Bit. 
		unsigned reserved2 : 1;  // [15 bit]
		unsigned fsgsbase : 1;   // [16 bit] 启用指令RDFSBASE、RDGSBASE、WRFSBASE和WRGSBASE。
		unsigned pcide : 1;      // [17 bit] PCID-Enable Bit
		unsigned osxsave : 1;    // [18 bit] XSAVE and Processor Extended States-Enable Bit.
		unsigned reserved3 : 1;  // [19 bit]
		unsigned smep : 1;       // [20 bit] SMEP-Enable Bit
		unsigned smap : 1;       // [21 bit] SMAP-Enable Bit
		unsigned pke : 1;        // [22 bit] Protection-Key-Enable Bit (Enables 4-level paging ???)
	}Bits;
}Cr4, *pCr4;
static_assert(sizeof(Cr4) == sizeof(ULONG_PTR), "Cr4 size error!");

// SYSTEM FLAGS AND FIELDS IN THE EFLAGS REGISTER (白皮书 2-10 Vol. 3A)
// rflag 寄存器的定义
typedef union _FlagRegister {
	ULONG_PTR all;
	struct {
		unsigned cf : 1;          //!< [0] Carry flag
		unsigned reserved1 : 1;   //!< [1] Always 1
		unsigned pf : 1;          //!< [2] Parity flag
		unsigned reserved2 : 1;   //!< [3] Always 0
		unsigned af : 1;          //!< [4] Borrow flag
		unsigned reserved3 : 1;   //!< [5] Always 0
		unsigned zf : 1;          //!< [6] Zero flag
		unsigned sf : 1;          //!< [7] Sign flag
		unsigned tf : 1;          //!< [8] Trap flag
		unsigned intf : 1;        //!< [9] Interrupt flag
		unsigned df : 1;          //!< [10] Direction flag
		unsigned of : 1;          //!< [11] Overflow flag
		unsigned iopl : 2;        //!< [12:13] I/O privilege level
		unsigned nt : 1;          //!< [14] Nested task flag
		unsigned reserved4 : 1;   //!< [15] Always 0
		unsigned rf : 1;          //!< [16] Resume flag
		unsigned vm : 1;          //!< [17] Virtual 8086 mode
		unsigned ac : 1;          //!< [18] Alignment check
		unsigned vif : 1;         //!< [19] Virtual interrupt flag
		unsigned vip : 1;         //!< [20] Virtual interrupt pending
		unsigned id : 1;          //!< [21] Identification flag
		unsigned reserved5 : 10;  //!< [22:31] Always 0
	} Bits;
}FlagRegister, *pFlagRegister;
static_assert(sizeof(FlagRegister) == sizeof(ULONG_PTR), "rflags size error!");

/****************************************************************************************************************/

#pragma pack(pop)

class VtHeader
{
public:
	VtHeader();
	~VtHeader();

public:
	// 重载操作符
	_IRQL_requires_max_(DISPATCH_LEVEL) // 使用该函数的最大 IRQL 等级为 DISPATCH_LEVEL
	void * __cdecl operator new(unsigned __int64 size)
	{
		PHYSICAL_ADDRESS highest;
		highest.QuadPart = 0xFFFFFFFFFFFFFFFF;
		void * address = MmAllocateContiguousMemory(size, highest);
		if (address)
			RtlSecureZeroMemory(address, size);
		return address;
	}

	_IRQL_requires_max_(DISPATCH_LEVEL) // 使用该函数的最大 IRQL 等级为 DISPATCH_LEVEL
	void __cdecl operator delete(void *p, size_t size)
	{
		UNREFERENCED_PARAMETER(size);
		if (p) {
			MmFreeContiguousMemory(p);
			p = NULL;
		}
	}

public:
	// 定义申请内存的函数
	_IRQL_requires_max_(DISPATCH_LEVEL) // 使用该函数的最大 IRQL 等级为 DISPATCH_LEVEL
	static void * kmalloc(size_t size)
	{
		PHYSICAL_ADDRESS maxAddr;
		PVOID address = NULL;

		maxAddr = { 0 };
		maxAddr.QuadPart = 0xFFFFFFFFFFFFFFFF;
		address = MmAllocateContiguousMemory(size, maxAddr);
		if (address)
			RtlSecureZeroMemory(address, size);

		return address;
	}

	// 定义释放内存的函数
	_IRQL_requires_max_(DISPATCH_LEVEL) // 使用该函数的最大 IRQL 等级为 DISPATCH_LEVEL
	static void kFree(void * p)
	{
		if (p) {
			MmFreeContiguousMemory(p);
			p = NULL;
		}
	}
};

#endif

