#include "stdafx.h"
#include <DbgHelp.h>
#define BUFFER_SIZE 2000

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

#define CountRelocationEntries(dwBlockSize)		\
	(dwBlockSize -								\
	sizeof(BASE_RELOCATION_BLOCK)) /			\
	sizeof(BASE_RELOCATION_ENTRY)


//API定义
typedef NTSTATUS(WINAPI* _NtQueryInformationProcess)(
	HANDLE ProcessHandle,
	DWORD ProcessInformationClass,
	PVOID ProcessInformation,
	DWORD ProcessInformationLength,
	PDWORD ReturnLength
	);
typedef NTSTATUS(WINAPI* _NtUnmapViewOfSection)(
	HANDLE ProcessHandle,
	PVOID BaseAddress
	);
typedef struct _PEB_FREE_BLOCK // 2 elements, 0x8 bytes
{
	struct _PEB_FREE_BLOCK * pNext;
	DWORD dwSize;
} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;


typedef struct _UNICODE_STR
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR pBuffer;
} UNICODE_STR, *PUNICODE_STR;


typedef struct _PEB_LDR_DATA //, 7 elements, 0x28 bytes
{
	DWORD dwLength;
	DWORD dwInitialized;
	LPVOID lpSsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	LPVOID lpEntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;


typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STR ImagePathName;
	UNICODE_STR CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;
typedef struct __PEB // 65 elements, 0x210 bytes
{
	BYTE bInheritedAddressSpace;
	BYTE bReadImageFileExecOptions;
	BYTE bBeingDebugged;
	BYTE bSpareBool;
	LPVOID lpMutant;
	LPVOID lpImageBaseAddress;
	PPEB_LDR_DATA pLdr;
	LPVOID lpProcessParameters;
	LPVOID lpSubSystemData;
	LPVOID lpProcessHeap;
	PRTL_CRITICAL_SECTION pFastPebLock;
	LPVOID lpFastPebLockRoutine;
	LPVOID lpFastPebUnlockRoutine;
	DWORD dwEnvironmentUpdateCount;
	LPVOID lpKernelCallbackTable;
	DWORD dwSystemReserved;
	DWORD dwAtlThunkSListPtr32;
	PPEB_FREE_BLOCK pFreeList;
	DWORD dwTlsExpansionCounter;
	LPVOID lpTlsBitmap;
	DWORD dwTlsBitmapBits[2];
	LPVOID lpReadOnlySharedMemoryBase;
	LPVOID lpReadOnlySharedMemoryHeap;
	LPVOID lpReadOnlyStaticServerData;
	LPVOID lpAnsiCodePageData;
	LPVOID lpOemCodePageData;
	LPVOID lpUnicodeCaseTableData;
	DWORD dwNumberOfProcessors;
	DWORD dwNtGlobalFlag;
	LARGE_INTEGER liCriticalSectionTimeout;
	DWORD dwHeapSegmentReserve;
	DWORD dwHeapSegmentCommit;
	DWORD dwHeapDeCommitTotalFreeThreshold;
	DWORD dwHeapDeCommitFreeBlockThreshold;
	DWORD dwNumberOfHeaps;
	DWORD dwMaximumNumberOfHeaps;
	LPVOID lpProcessHeaps;
	LPVOID lpGdiSharedHandleTable;
	LPVOID lpProcessStarterHelper;
	DWORD dwGdiDCAttributeList;
	LPVOID lpLoaderLock;
	DWORD dwOSMajorVersion;
	DWORD dwOSMinorVersion;
	WORD wOSBuildNumber;
	WORD wOSCSDVersion;
	DWORD dwOSPlatformId;
	DWORD dwImageSubsystem;
	DWORD dwImageSubsystemMajorVersion;
	DWORD dwImageSubsystemMinorVersion;
	DWORD dwImageProcessAffinityMask;
	DWORD dwGdiHandleBuffer[34];
	LPVOID lpPostProcessInitRoutine;
	LPVOID lpTlsExpansionBitmap;
	DWORD dwTlsExpansionBitmapBits[32];
	DWORD dwSessionId;
	ULARGE_INTEGER liAppCompatFlags;
	ULARGE_INTEGER liAppCompatFlagsUser;
	LPVOID lppShimData;
	LPVOID lpAppCompatInfo;
	UNICODE_STR usCSDVersion;
	LPVOID lpActivationContextData;
	LPVOID lpProcessAssemblyStorageMap;
	LPVOID lpSystemDefaultActivationContextData;
	LPVOID lpSystemAssemblyStorageMap;
	DWORD dwMinimumStackCommit;
} _PEB, *_PPEB;


struct PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	PVOID PebBaseAddress;//这个字段本应该位DWORD，但是在64位模式下会被截断，所以改成了PVOID。
	PVOID Reserved2[2];
	DWORD UniqueProcessId;
	PVOID Reserved3;
};


typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct {
	LPVOID address;
	LPVOID alignedAddress;
	ULONG_PTR size;
	DWORD characteristics;
	BOOL last;
} SECTIONFINALIZEDATA, *PSECTIONFINALIZEDATA;



_PPEB ReadRemotePEB(HANDLE hProcess);
PLOADED_IMAGE ReadRemoteImage(HANDLE hProcess, LPVOID lpImageBaseAddress);
PLOADED_IMAGE GetLoadedImage(ULONG_PTR dwImageBase);
BOOL CopySections(HANDLE hProcess, ULONG_PTR targetBaseAddress, ULONG_PTR srcBuffer);
BOOL FinalizeSections(HANDLE hProcess, ULONG_PTR targetBaseAddress, ULONG_PTR srcBuffer);
inline DWORD AlignValueUp(DWORD value, DWORD alignment)
{
	return (value + alignment - 1) & ~(alignment - 1);
}						hProcess,
						(PVOID)((ULONG_PTR)pPEB->lpImageBaseAddress + dwFieldAddress),
						&upBuffer,
						sizeof(ULONG_PTR), 0
					);

					upBuffer += upDelta;
					bool bSuccess = WriteProcessMemory
					(
						hProcess,
						(PVOID)((ULONG_PTR)pPEB->lpImageBaseAddress + dwFieldAddress),
						&upBuffer,
						sizeof(ULONG_PTR),

						0
					);
					if (!bSuccess)
					{
						cout << "Failed to Rebase" << endl;
						continue;
					}
				}//end for
			}//end while

			break;
		}//end for
	if (!FinalizeSections(hProcess, (ULONG_PTR)pPEB->lpImageBaseAddress, (ULONG_PTR)pBuffer))
	{
		cout << "Finalize Section Failed." << endl;
		return hProcess;
	}
	DWORD dwBreakpoint = 0xCC;
	ULONG_PTR dwEntryPoint = (ULONG_PTR)pPEB->lpImageBaseAddress +
		pSourceHeader->OptionalHeader.AddressOfEntryPoint;
	LPCONTEXT pContext = new CONTEXT();
	pContext->ContextFlags = CONTEXT_INTEGER;
	cout << "-->Getting Thread Context." << endl;
	if (!GetThreadContext(lpProcessInformation->hThread, pContext))
	{
		cout << "Get Context Failed." << endl;
		return hProcess;
	}
#ifdef  _WIN64
	pContext->Rcx = dwEntryPoint;
#else
	pContext->Eax = dwEntryPoint;
#endif //  _WIN64
	cout << "Setting Thread Context." << endl;
	if (!SetThreadContext(lpProcessInformation->hThread, pContext))
	{
		cout << "Setting Context Failed." << endl;
		return hProcess;
	}
	cout << "Resuming Thread." << endl;
	if (!ResumeThread(lpProcessInformation->hThread))
	{
		cout << "Resume Thread Failed" << endl;
		return hProcess;
	}

	return hProcess;
}
