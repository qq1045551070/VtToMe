#pragma once
#ifndef VTEPT
#define VTEPT

#include "VtHeader.h"

// 该类主要用于 EPT 的初始化与扩展

#pragma pack(push,1) // 注意1字节对齐
/****************************************************EPT相关结构体定义******************************************************/

// See: Extended-Page-Table Pointer (EPTP)
// 定义 Eptp 结构体 (参考 【处理器虚拟化技术】(第3.5.17节))
typedef union _EptPointer
{
	ULONG64 all;
	struct
	{
		ULONG64 memory_type : 3;	   //!< [0:2] 指示 EPT paging-structure 的内存类型(属于VMM管理的数据区域), 当前支持UC(0)/WB(6)类型
		ULONG64 page_walk_length : 3;  //!< [3:5] 指示 EPT 页表结构, 这个值加上1才是真正的级数。(如：它的值为3时表示有4级页表结构)
		ULONG64 enable_accessed_and_dirty_flags : 1;  //!< [6] 指示EPT页表结构项里的access与dirty标志位有效。(处理器才会更新这两个标志位)
		ULONG64 reserved1 : 5;		   //!< [7:11] 指示 EPT 页表结构, 这个值加上1才是真正的级数。(如：它的值为3时表示有4级页表结构)
		ULONG64 pml4_address : 36;	   //!< [12:48-1] EPT PML4T PHY 地址
		ULONG64 reserved2 : 16;        //!< [48:63]
	}Bits;
}EptPointer, *pEptPointer;
static_assert(sizeof(EptPointer) == sizeof(ULONG64), "EptPointer Size Mismatch");

// See: Format of an EPT PML4 Entry (PML4E) that References an EPT Page-Directory-Pointer Table
//      Page-Directory-Pointer Table
// 定义 PML4 结构体 (参考 白皮书 Vol. 3C 28-3, 【处理器虚拟化技术】(第6.1.5节))
typedef union _EptPml4Entry
{
	ULONG64 all;
	struct {
		ULONG64 read_access : 1;                                  //!< [0]		是否可读
		ULONG64 write_access : 1;                                 //!< [1]		是否可写
		ULONG64 execute_access : 1;                               //!< [2]		是否可执行
		ULONG64 reserved1 : 5;                                    //!< [3:7]	保留
		ULONG64 accessed : 1;                                     //!< [8]		页面是否被访问
		ULONG64 ignored1 : 1;                                     //!< [9]
		ULONG64 execute_access_for_user_mode_linear_address : 1;  //!< [10]		Execute access for user-mode linear addresses.
		ULONG64 ignored2 : 1;                                     //!< [11]
		ULONG64 pdpt_address : 36;                                //!< [12:48-1] EPT PDPT 的 PHY 地址 (N == 48)
		ULONG64 reserved2 : 4;                                    //!< [48:51]
		ULONG64 ignored3 : 12;                                    //!< [52:63]
	}Bits;
}EptPml4Entry, *pEptPml4Entry;
static_assert(sizeof(EptPml4Entry) == sizeof(ULONG64), "EptPml4Entry Size Mismatch");

// See: Format of an EPT Page-Directory-Pointer-Table Entry (PDPTE) that References an EPT Page Directory
// 定义 PDPTE 结构体 (参考 白皮书 28-6 Vol. 3C, 【处理器虚拟化技术】(第6.1.5节))
typedef union _EptPdptEntry
{
	ULONG64 all;
	struct {
		ULONG64 read_access : 1;                                  //!< [0]		是否可读
		ULONG64 write_access : 1;                                 //!< [1]		是否可写
		ULONG64 execute_access : 1;                               //!< [2]		是否可执行
		ULONG64 reserved1 : 5;                                    //!< [3:7]
		ULONG64 accessed : 1;                                     //!< [8]		页面是否被访问
		ULONG64 ignored1 : 1;                                     //!< [9]
		ULONG64 execute_access_for_user_mode_linear_address : 1;  //!< [10]
		ULONG64 ignored2 : 1;                                     //!< [11]
		ULONG64 pdt_address : 36;                                 //!< [12:48-1] EPT PDT 的 PHY 地址 (N == 48)
		ULONG64 reserved2 : 4;                                    //!< [48:51]
		ULONG64 ignored3 : 12;                                    //!< [52:63]
	}Bits;
}EptPdptEntry, *pEptPdptEntry;
static_assert(sizeof(EptPdptEntry) == sizeof(ULONG64), "EptPdptEntry Size Mismatch");

// See: Format of an EPT Page-Directory Entry (PDE) that References an EPT Page Table
// 定义 PDPTE 结构体 (参考 白皮书 28-8 Vol. 3C, 【处理器虚拟化技术】(第6.1.5节))
typedef union _EptPdEntry
{
	ULONG64 all;
	struct {
		ULONG64 read_access : 1;                                  //!< [0]		是否可读
		ULONG64 write_access : 1;                                 //!< [1]		是否可写
		ULONG64 execute_access : 1;                               //!< [2]		是否可执行
		ULONG64 reserved1 : 4;                                    //!< [3:6]
		ULONG64 must_be0 : 1;                                     //!< [7]		Must be 0 (otherwise, this entry maps a 2-MByte page)
		ULONG64 accessed : 1;                                     //!< [8]		是否被访问过
		ULONG64 ignored1 : 1;                                     //!< [9]		
		ULONG64 execute_access_for_user_mode_linear_address : 1;  //!< [10]
		ULONG64 ignored2 : 1;                                     //!< [11]
		ULONG64 pt_address : 36;                                  //!< [12:48-1] EPT PT 的 PHY 地址 (N == 48)
		ULONG64 reserved2 : 4;                                    //!< [48:51]
		ULONG64 ignored3 : 12;                                    //!< [52:63]
	}Bits;
}EptPdEntry, *pEptPdEntry;
static_assert(sizeof(EptPdEntry) == sizeof(ULONG64), "EptPdEntry Size Mismatch");

// See: Format of an EPT Page-Table Entry that Maps a 4-KByte Page
// 定义 PTE 结构体 (参考 白皮书 28-8 Vol. 3C 28-9, 【处理器虚拟化技术】(第6.1.5节))
typedef union _EptPtEntry
{
	ULONG64 all;
	struct {
		ULONG64 read_access : 1;                                  //!< [0]		是否可读
		ULONG64 write_access : 1;                                 //!< [1]		是否可写
		ULONG64 execute_access : 1;                               //!< [2]		是否可执行
		ULONG64 memory_type : 3;                                  //!< [3:5]	指示 guest-physical address 页面 cache 的内存类型
		ULONG64 ignore_pat_memory_type : 1;                       //!< [6]		为1时, PAT内存类型被忽略(当CR0.CD = 0时, 最终的HPA页面的内存类型由PAT内存类型及EPT内存类型联合决定)
		ULONG64 ignored1 : 1;                                     //!< [7]
		ULONG64 accessed : 1;                                     //!< [8]		是否被访问过
		ULONG64 dirty_written : 1;                                //!< [9]		是否被写过
		ULONG64 execute_access_for_user_mode_linear_address : 1;  //!< [10]
		ULONG64 ignored2 : 1;                                     //!< [11]
		ULONG64 physial_address : 36;                             //!< [12:48-1] EPT 4kb内存 的 PHY 地址 (N == 48)
		ULONG64 reserved1 : 4;                                    //!< [48:51]
		ULONG64 Ignored3 : 11;                                    //!< [52:62]
		ULONG64 suppress_ve : 1;                                  //!< [63]
	}Bits;
}EptPtEntry, *pEptPtEntry;
static_assert(sizeof(EptPtEntry) == sizeof(ULONG64), "EptPtEntry Size Mismatch");

/*************************************************************************************************************************/
#pragma pack(pop)

class VtEpt : public VtHeader
{
public:
	VtEpt();
	~VtEpt();

public:
	// Ept 信息
	EptPointer m_Eptp;

private:
	// 设置 EPTP 相关信息
	VOID VtSetEptPointer(PVOID Pml4Address);

public:
	// 通过物理地址获取 Ept PTE 指针
	pEptPtEntry VtGetPteByPhyAddress(ULONG_PTR PhyAddress);

public:
	// 开启	EPT
	BOOLEAN	VtStartEpt();
	// 关闭	EPT
	VOID	VtCloseEpt();

public:
	// 处理 Ept VM-exit 产生的回调
	VOID EptViolationVtExitHandler(ULONG_PTR * Registers);

protected:
	// 初始化 EPT
	BOOLEAN VtInitEpt();
	

};

#endif

