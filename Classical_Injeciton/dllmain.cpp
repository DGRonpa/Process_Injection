// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <stdlib.h>
#include <windows.h>
#include <iostream>
using namespace std;


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	//system("cmd /k calc");
	//system("cmd /k \"C:\\Tools\\LoadPe\\LordPE.EXE\"");

	char cCommandLine[] = "C:\\Tools\\LoadPe\\LordPE.EXE";
	PROCESS_INFORMATION pi;
	STARTUPINFO si = { sizeof(si) };
	// 启动进程 
	BOOL ret = CreateProcess(NULL, cCommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	cout << GetLastError() << endl;
    return TRUE;
}

