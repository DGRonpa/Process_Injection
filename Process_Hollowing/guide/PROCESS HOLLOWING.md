# PROCESS HOLLOWING (又名进程替换和RUNPE)

## 介绍

'Process hollowing is yet another tool in the kit of those who seek to hide the presence of a process'. 
大概就是, 用无害的进程来运行恶意代码, 可以用来隐藏恶意代码. 从外部看是无害的正常程序
, 但是那个程序已经被寄生了, 所以可以有效隐藏恶意进程的存在. 干脆叫Parasitic Injection 算了.

过程简单来说就是, 启动器随便创建并挂起一个进程(例如`svchost.exe`), 清空中挂起的无害进程的内存空间, 然后填入恶意代码运行.


### 简略过程

该程序通过调用CreateProcess并将流程创建标志设置为CREATE_SUSPENDED（0x00000004）完成。新进程的主线程被创建为挂起状态，直到ResumeThread函数被调用才会运行。接下来，恶意软件需要用恶意的有效载荷来替换合法文件的内容。这可以通过调用ZwUnmapViewOfSection或NtUnmapViewOfSection来取消映射目标进程的内存。这两个API基本上释放了一个部分指向的所有内存。现在内存被取消映射，加载器执行VirtualAllocEx为恶意软件分配新内存，并使用WriteProcessMemory将每个恶意软件的部分写入目标进程空间。恶意软件调用SetThreadContext将entrypoint指向已编写的新代码段。最后，恶意软件通过调用ResumeThread来恢复挂起的线程。

1. 创建挂起的进程。
2. 卸载掉原来的模块。
3. 写入新的文件。
4. 恢复现场。


## 代码实现

### 创建挂起的进程

Creating The Process The target process must be created in the suspended state. This can be achieved by passing the `CREATE_SUSPENDED` flag to the `CreateProcess()` function via the `dwCreationFlags` parameter.

Once the process is created its memory space can be modified using the handle provided by the `hProcess` member of the `PROCESS_INFORMATION` structure.

### 获取模块信息 (模块基址)

https://github.com/kernelm0de/RunPE-ProcessHollowing/blob/master/main.cpp



## 补充

### 适用范围


### 缺点

## Reference Resources

1. github上的一个攻击样例. 介绍非常详细, 包括peb啥的, 主要参考这个. [https://github.com/m0n0ph1/Process-Hollowing](https://github.com/m0n0ph1/Process-Hollowing)
2. 看雪论坛上的一个样本实现, 也是参考m0n0ph1的.[https://bbs.pediy.com/thread-224706-1.htm](https://bbs.pediy.com/thread-224706-1.htm) 
3. `Rebhip`恶意软件便是利用了这种注入技巧
4. github上的另一个攻击样例, 更容易懂一点, 特别是在PEB这块[https://github.com/kernelm0de/RunPE-ProcessHollowing/blob/master/main.cpp](https://github.com/kernelm0de/RunPE-ProcessHollowing/blob/master/main.cpp)

# 知识补充

## PEB结构(文档化进程环境块)

> 微软的参考文档, 但结构不是很详细 [https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)<br>
> 详细结构 [https://blog.csdn.net/qq_31694351/article/details/51532581](https://blog.csdn.net/qq_31694351/article/details/51532581)

### 结构

第一次接触是在反调试那块, 每个进程有PEB结构(文档化进程环境块), 第二个字节是 `BeingDebugged`属性 

```
typedef struct _PEB 
{ 
  BOOLEAN                 InheritedAddressSpace;
  BOOLEAN                 ReadImageFileExecOptions;	// 对应微软文档里的Reserved1[2]
  BOOLEAN                 BeingDebugged;
  BOOLEAN                 Spare;
  HANDLE                  Mutant;
  PVOID                   ImageBaseAddress;	// Reserved3[2]
  PPEB_LDR_DATA           LoaderData;
  PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
  PVOID                   SubSystemData;
  PVOID                   ProcessHeap;
  PVOID                   FastPebLock;
  PPEBLOCKROUTINE         FastPebLockRoutine;
  PPEBLOCKROUTINE         FastPebUnlockRoutine;
  ULONG                   EnvironmentUpdateCount;
  PPVOID                  KernelCallbackTable;
  PVOID                   EventLogSection;
  PVOID                   EventLog;
  PPEB_FREE_BLOCK         FreeList;
  ULONG                   TlsExpansionCounter;
  PVOID                   TlsBitmap;
  ULONG                   TlsBitmapBits[0x2];
  PVOID                   ReadOnlySharedMemoryBase;
  PVOID                   ReadOnlySharedMemoryHeap;
  PPVOID                  ReadOnlyStaticServerData;
  PVOID                   AnsiCodePageData;
  PVOID                   OemCodePageData;
  PVOID                   UnicodeCaseTableData;
  ULONG                   NumberOfProcessors;
  ULONG                   NtGlobalFlag;
  BYTE                    Spare2[0x4];
  LARGE_INTEGER           CriticalSectionTimeout;
  ULONG                   HeapSegmentReserve;
  ULONG                   HeapSegmentCommit;
  ULONG                   HeapDeCommitTotalFreeThreshold;
  ULONG                   HeapDeCommitFreeBlockThreshold;
  ULONG                   NumberOfHeaps;
  ULONG                   MaximumNumberOfHeaps;
  PPVOID                  *ProcessHeaps;
  PVOID                   GdiSharedHandleTable;
  PVOID                   ProcessStarterHelper;
  PVOID                   GdiDCAttributeList;
  PVOID                   LoaderLock;
  ULONG                   OSMajorVersion;
  ULONG                   OSMinorVersion;
  ULONG                   OSBuildNumber;
  ULONG                   OSPlatformId;
  ULONG                   ImageSubSystem;
  ULONG                   ImageSubSystemMajorVersion;
  ULONG                   ImageSubSystemMinorVersion;
  ULONG                   GdiHandleBuffer[0x22];
  ULONG                   PostProcessInitRoutine;
  ULONG                   TlsExpansionBitmap;
  BYTE                    TlsExpansionBitmapBits[0x80];
  ULONG                   SessionId; 
} PEB, *PPEB;
```

### ImageBaseAddress

`ImageBaseAddress`保存的是进程映像基址，就是PE头文件中的`IMAGE_OPTIONAL_HEADER->ImageBase`对应的值。

* 对于EXE来说，默认的`ImageBase`为`0x400000`
* 对于DLL来说，是`0x10000000`

但存在重定位的现象, 所以基地址可能不是默认地址.

复习一遍, exe文件不太可能会发生重定位, 除非开了地址随机化保护. 因为一个进程一般就一个exe模块. 但dll文件会发生重定位, 因为一个exe文件, 进程打开的时候, 大都需要加载复数的dll文件, 不可能都加载到同一个基地址.
