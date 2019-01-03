#include "SSDT.h"

UCHAR RetCode[] = "\x33\xC0"				//xor eax,eax
				  "\xC3";					//ret

typedef struct _MODULE_INFO
{
	ULONG_PTR DllEntry;
	HANDLE ProcessID;
}MODULE_INFO, *PMODULE_INFO;

typedef struct _USER_PROTECT_MEMORY
{
	PVOID	  ProtectBase;
	ULONG_PTR ProtectSize;
	ULONG	  OldProtectAccess;
}USER_PROTECT_MEMORY, *PUSER_PROTECT_MEMORY;

typedef NTSTATUS(*NTPROTECTVIRTUALMEMORY)(IN HANDLE ProcessHandle,
	IN OUT PVOID *UnsafeBaseAddress,
	IN OUT SIZE_T *UnsafeNumberOfBytesToProtect,
	IN ULONG NewAccessProtection,
	OUT PULONG UnsafeOldAccessProtection);

BOOLEAN Local_ProtectVirtualMemory(IN PVOID UnsafeBaseAddress,IN SIZE_T UnsafeNumberOfBytesToProtect, IN ULONG NewAccessProtection)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	PUSER_PROTECT_MEMORY UserProtectMemroy = NULL;
	ULONG_PTR RegionSize = 0;

	SSDT Ssdt;
	NTPROTECTVIRTUALMEMORY NtProtectVirtualMemory = NULL;

	RegionSize = sizeof(USER_PROTECT_MEMORY);
	

	Ssdt.FindSSDT();
	Ssdt.LoadNtdll();
	NtProtectVirtualMemory = (NTPROTECTVIRTUALMEMORY)Ssdt.GetSSDTProcByName("NtProtectVirtualMemory");
	if (NtProtectVirtualMemory == NULL)
	{
		KdPrint(("获取NtProtectVirtualMemory失败！\n"));
		return FALSE;
	}

	Status = ZwAllocateVirtualMemory(NtCurrentProcess(), (PVOID*)&UserProtectMemroy, 0, &RegionSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!NT_SUCCESS(Status))
	{
		KdPrint(("ZwAllocateVirtualMemory Fail!Status : %x\n",Status));
		return FALSE;
	}

	UserProtectMemroy->ProtectBase = UnsafeBaseAddress;
	UserProtectMemroy->ProtectSize = UnsafeNumberOfBytesToProtect;
	UserProtectMemroy->OldProtectAccess = 0;

	Status = NtProtectVirtualMemory(NtCurrentProcess(), &UserProtectMemroy->ProtectBase, &UserProtectMemroy->ProtectSize, NewAccessProtection, &UserProtectMemroy->OldProtectAccess);
	if (!NT_SUCCESS(Status))
	{
		KdPrint(("NtProtectVirtualMemory Fail!Status : %x\n", Status));
		return FALSE;
	}

	return TRUE;
}

VOID PatchThread(PVOID ThreadParam)
{
	MODULE_INFO *ModuleInfo = NULL;
	PEPROCESS AttachedProcess = NULL;
	KAPC_STATE ApcState = { 0 };

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	do
	{
		ModuleInfo = (MODULE_INFO *)ThreadParam;
		if (ModuleInfo == NULL)
			break;

		Status = PsLookupProcessByProcessId(ModuleInfo->ProcessID, &AttachedProcess);
		if (!NT_SUCCESS(Status))
			break;

		KeStackAttachProcess(AttachedProcess, &ApcState);

		if (Local_ProtectVirtualMemory((PVOID)ModuleInfo->DllEntry, sizeof(RetCode) - 1, PAGE_EXECUTE_READWRITE))
			RtlCopyMemory((PVOID)ModuleInfo->DllEntry, RetCode, sizeof(RetCode) - 1);

		KeUnstackDetachProcess(&ApcState);

	} while (FALSE);
	
	if (ModuleInfo != NULL)
		sfFreeMemory(ModuleInfo);

	if (AttachedProcess != NULL)
		ObDereferenceObject(AttachedProcess);

	PsTerminateSystemThread(STATUS_SUCCESS);
}

VOID Sleep(ULONG MilliSeconds)
{
	LARGE_INTEGER SleepTime = { 0 };
	SleepTime.QuadPart = -10 * 1000 * (LONG)MilliSeconds;

	KeDelayExecutionThread(KernelMode, FALSE, &SleepTime);
}

//在该死的Image回调里面，加了把锁。没法调用对内存
VOID PreventDll(ULONG_PTR ImageBase,HANDLE ProcessId)
{
	IMAGE_DOS_HEADER *DosHeader = NULL;
	IMAGE_NT_HEADERS *NtHeader = NULL;

	ULONG_PTR DllEntry = 0;
	MODULE_INFO *ModuleInfo = NULL;

	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	HANDLE ThreadHandle = NULL;

	__debugbreak();

	DosHeader = (IMAGE_DOS_HEADER *)ImageBase;
	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return;

	NtHeader = (IMAGE_NT_HEADERS *)(ImageBase + DosHeader->e_lfanew);
	if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
		return;

	DllEntry = ImageBase + NtHeader->OptionalHeader.AddressOfEntryPoint;

	ModuleInfo = (MODULE_INFO *)sfAllocateMemory(sizeof(MODULE_INFO));
	if (ModuleInfo == NULL)
		return; 

	ModuleInfo->DllEntry = DllEntry;
	ModuleInfo->ProcessID = ProcessId;

	Status = PsCreateSystemThread(&ThreadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, PatchThread, (PVOID)ModuleInfo);
	if (NT_SUCCESS(Status))
		ZwClose(ThreadHandle);

	/*这里有个问题很烦，LoadImage回调里面无法调用ZwAllocate/Protect之类的函数，就需要开个线程去搞这个事。
	但是有可能主线程更快，所以还没等到我patch内存，那块内存已经运行了，所以很烦，这里直睡眠一段时间等待那个线程。
	目前没想到更好的解决方案（手动摘除进程锁有点烦）。*/
	Sleep(2 * 1000);
}

VOID LoadImageNotify(
	__in PUNICODE_STRING FullImageName,
	__in HANDLE ProcessId,                
	__in PIMAGE_INFO ImageInfo
	)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	UNICODE_STRING FilterDllPath = { 0 };

	RtlInitUnicodeString(&FilterDllPath, L"*\\XXX*");

	//如果是要过滤的dll名称
	if (FsRtlIsNameInExpression(&FilterDllPath, FullImageName, TRUE, NULL) == TRUE)
		PreventDll((ULONG_PTR)ImageInfo->ImageBase,ProcessId);

}

EXTERN_C VOID Unload(PDRIVER_OBJECT DriverObject)
{
	PsRemoveLoadImageNotifyRoutine(LoadImageNotify);
	KdPrint(("Unload Success!\n"));
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegString)
{
	KdPrint(("Entry Driver!\n"));
	PsSetLoadImageNotifyRoutine(LoadImageNotify);

	DriverObject->DriverUnload = Unload;
	return STATUS_SUCCESS;
}