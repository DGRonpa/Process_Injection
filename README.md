# Process injection

挑了适合攻击背景的进程注入方式

[https://i.blackhat.com/USA-19/Thursday/us-19-Kotler-Process-Injection-Techniques-Gotta-Catch-Them-All-wp.pdf](https://i.blackhat.com/USA-19/Thursday/us-19-Kotler-Process-Injection-Techniques-Gotta-Catch-Them-All-wp.pdf)

## Execute shellcode loader

1. TLS Code Execute
2. SEH Code Execute

## Search Target Process

1. SnapShot
2. QuerySystemInformation

## Open Remote Process

1. OpenProcess
	* NtOpenProcess
2. DLL注入
	* 注册表
	* 挂钩

## Transfer Shellcode across Processes (Write-What-Where)

[https://modexp.wordpress.com/2018/07/15/process-injection-sharing-payload/](https://modexp.wordpress.com/2018/07/15/process-injection-sharing-payload/)

1. Classical
	* VirtualAllocEx + WriteProcessMemory
	* NtAllocateVirtualMemory + NtWriteProcessMemory
2. Dll Hollowing
	* Dll + WriteProcessMemory
3. Mapping (CreateSection)
	* CreateFileMapping → MapViewOfFile → MapViewOfFile2 + memcpy
	* NtCreateSection → NtMapViewOfSection +memcpy
	* CreateFileMapping → MapViewOfFile → NtMapViewOfSection +memcpy
4. ROP链 (AtomBombing/  PowerLoaderEx/ Ghost-Writing)
	* NtOpenSection
	* NtMapViewOfSection
	* Ghost-Writing代码实例[https://i.blackhat.com/USA-19/Thursday/us-19-Kotler-Process-Injection-Techniques-Gotta-Catch-Them-All-wp.pdf](https://i.blackhat.com/USA-19/Thursday/us-19-Kotler-Process-Injection-Techniques-Gotta-Catch-Them-All-wp.pdf)
5. AtomBombing (中间涉及到APC, 多一步注入)
	* GlobalAddAtom + NtQueueApcThread + GlobalGetAtomName
6. memset/memmove (Thread must be in alertable state)
	* ntdll!NtQueueApcThread
	* [https://i.blackhat.com/USA-19/Thursday/us-19-Kotler-Process-Injection-Techniques-Gotta-Catch-Them-All-wp.pdf](https://i.blackhat.com/USA-19/Thursday/us-19-Kotler-Process-Injection-Techniques-Gotta-Catch-Them-All-wp.pdf)

## Trigger Shellcode

[https://modexp.wordpress.com/2018/07/12/process-injection-writing-payload/](https://modexp.wordpress.com/2018/07/12/process-injection-writing-payload/)

1. Thread procedure (CreateRemoteThread)
	* CreateRemoteThread
	* RtlCreateUserThread
	* NtCreateThreadEx
	* ZwCreateThreadEx
2. Asynchronous Procedure Call (APC/ Early Bird)
	* QueueUserAPC
	* NtQueueApcThread	(能调用三个参数)
	* NtQueueApcThreadEx
	* ZwQueueApcThread
	* ZwQueueApcThreadEx
	* RtlQueueApcWow64Thread
3. Thread Hijack (Ghost Writing)
	* SetThreadContext + ResumeThread
	* Variant: use NtQueueApcThread(thread,SetThreadContext,-2 /* GetCurrentThread pseudo handle */,context,NULL) [https://i.blackhat.com/USA-19/Thursday/us-19-Kotler-Process-Injection-Techniques-Gotta-Catch-Them-All-wp.pdf](https://i.blackhat.com/USA-19/Thursday/us-19-Kotler-Process-Injection-Techniques-Gotta-Catch-Them-All-wp.pdf)

5. Kernel Callback Table (切换虚表)
	* SendMessage
6. ALPC callback (重写虚表)
	* VirtualQueryEx
	* NtDuplicateObject
	* NtConnectPort
	* ReadProcessMemory
7. DLL
	* Via CreateRemoteThread
	* Windows hook
	* App_init


