
#include "stdafx.h"
#include <windows.h>
#include <tlhelp32.h>

BOOL WINAPI InjectDllToProcess(DWORD dwTargetPid ,LPCTSTR DllPath );
DWORD ProcesstoPid(char *Processname);
BOOL EnableDebugPrivilege();

int main(int argc, char* argv[])
{
#ifdef _WIN64
	char szProcName[MAX_PATH] = "HostProc64.exe";
	char szDllPath[MAX_PATH] = "F:\\Program2016\\DllInjection\\MsgDll64.dll";
#else
	char szProcName[MAX_PATH] = "HostProc.exe";
	char szDllPath[MAX_PATH] = "F:\\Program2016\\DllInjection\\MsgDll.dll";
#endif
	
	DWORD dwPid = ProcesstoPid(szProcName);
	EnableDebugPrivilege();
	InjectDllToProcess(dwPid,szDllPath);
	return 0;
}

//注入
BOOL WINAPI InjectDllToProcess(DWORD dwTargetPid ,LPCTSTR DllPath )//传入的参数是目标进程ID, DLL路径
{
    HANDLE hProc = NULL;
	hProc=OpenProcess(PROCESS_ALL_ACCESS,
		FALSE,
		dwTargetPid
		);

    if(hProc == NULL)
    {
        printf("[-] OpenProcess Failed.\n");
        return FALSE;
    }
	
    LPTSTR psLibFileRemote = NULL;
	
    //`VirtualAllocEx` 向目标进程中开辟空间, 长度为lstrlen(DllPath)+1
    psLibFileRemote=(LPTSTR)VirtualAllocEx(hProc, NULL, lstrlen(DllPath)+1,
		MEM_COMMIT, PAGE_READWRITE);
	
    if(psLibFileRemote == NULL)
    {
        printf("[-] VirtualAllocEx Failed.\n");
        return FALSE;
    }
	
    //`WriteProcessMemory`写入Dll文件路径, 进程/目标空间/写入的内容/长度
    if(WriteProcessMemory(hProc, psLibFileRemote, (void *)DllPath, lstrlen(DllPath)+1, NULL) == 0)
    {
        printf("[-] WriteProcessMemory Failed.\n");
        return FALSE;
    }
	
    //获取`LoadLibrary`的地址, 并且设置成`pfnStartAddr`
    PTHREAD_START_ROUTINE pfnStartAddr=(PTHREAD_START_ROUTINE)
        GetProcAddress(GetModuleHandle("Kernel32"),"LoadLibraryA");
	
    if(pfnStartAddr == NULL)
    {
        printf("[-] GetProcAddress Failed.\n");
        return FALSE;
    }

    //`pfnStartAddr`指针指向创建后的线程的起始地址, 线程会直接开始执行LoadLibraryA
	//`psLibFileRemote`指向要传递给线程的变量, 所以线程会把那块的DLL的名字当做变量
    HANDLE hThread = CreateRemoteThread(hProc,
        NULL,
        0,
        pfnStartAddr,
        psLibFileRemote,
        0,
        NULL);
	
    if(hThread == NULL)
    {
        printf("[-] CreateRemoteThread Failed. ErrCode = %d\n",GetLastError());
        return FALSE;
    }

	printf("[*]Inject Succesfull.\n");
    return TRUE;
}


DWORD ProcesstoPid(char *Processname) //PID(Process ID) 传进来的参数是目标进程名
{
	HANDLE hProcessSnap=NULL;
	DWORD ProcessId=0;
	PROCESSENTRY32 pe32={0};
	hProcessSnap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0); //枚举指定进程或所有进程的堆或模块状态的API，它返回一个快照. 其中TH32CS_SNAPPROCESS这个参数, create a snapshot including all processes in the system.
	if(hProcessSnap==(HANDLE)-1)
	{
		printf("\nCreateToolhelp32Snapshot() Error: %d",GetLastError());
		return 0;
	}
	pe32.dwSize=sizeof(PROCESSENTRY32);
	if(Process32First(hProcessSnap,&pe32)) //用于搜索进程
	{
		do
		{
			if(!stricmp(Processname,pe32.szExeFile)) //对比搜索结果是否是目标process
			{
				ProcessId=pe32.th32ProcessID;
				break;
			}
		}
		while(Process32Next(hProcessSnap,&pe32)); //直到下一个process 为NULL
	}
	else
	{
		printf("\nProcess32First() Error: %d",GetLastError());
		return 0;
	}
	CloseHandle(hProcessSnap); 
	return ProcessId;//返回目标进程的ID
}

BOOL EnableDebugPrivilege() //提权
{ 
	TOKEN_PRIVILEGES tkp; 
	HANDLE hToken; 
	if (!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&hToken))     //�򿪵�ǰ����ʧ�� 
		return FALSE; 
	LookupPrivilegeValue(NULL,SE_DEBUG_NAME,&tkp.Privileges[0].Luid); //�鿴��ǰȨ��
	tkp.PrivilegeCount = 1; 
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; 
	AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0); //����Ȩ�ޣ���������
	return TRUE; 
}