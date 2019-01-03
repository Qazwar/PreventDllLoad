#include "SSDT.h"

UCHAR RetCode[] = "\x33\xC0"				//xor eax,eax
				  "\xC3";					//ret

typedef struct _MODULE_INFO
{
	ULONG_PTR DllEntry;
	HANDLE ProcessID;
	HANDLE LoadImageThreadId;
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

typedef NTSTATUS(*NTOPENTHREAD)(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL
	);

typedef NTSTATUS(*NTSUSPENDTHREAD)(
	IN HANDLE ThreadHandle,
	OUT PULONG PreviousSuspendCount OPTIONAL
	);

typedef NTSTATUS(*NTRESUMETHREAD)(
	IN HANDLE ThreadHandle,
	OUT PULONG PreviousSuspendCount OPTIONAL
	);

PVOID GetProcAddress(WCHAR *ProcName)
{
	UNICODE_STRING uProcName = { 0 };
	RtlInitUnicodeString(&uProcName, ProcName);

	return MmGetSystemRoutineAddress(&uProcName);
}

BOOLEAN Local_PatchOEP(IN PVOID OEP_Address, IN PVOID PatchBuffer, IN SIZE_T PatchSize, IN HANDLE SuspendThreadId)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	PUSER_PROTECT_MEMORY UserProtectMemroy = NULL;
	ULONG_PTR RegionSize = 0;

	SSDT Ssdt;
	NTPROTECTVIRTUALMEMORY NtProtectVirtualMemory = NULL;

	HANDLE SuspendThreadHandle = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	CLIENT_ID ClientId = { 0 };

	NTOPENTHREAD NtOpenThread = NULL;
	NTSUSPENDTHREAD NtSuspendThread = NULL;
	NTRESUMETHREAD NtResumeThread = NULL;

	Ssdt.FindSSDT();
	Ssdt.LoadNtdll();
	NtProtectVirtualMemory = (NTPROTECTVIRTUALMEMORY)Ssdt.GetSSDTProcByName("NtProtectVirtualMemory");
	if (NtProtectVirtualMemory == NULL)
	{
		KdPrint(("��ȡNtProtectVirtualMemoryʧ�ܣ�\n"));
		return FALSE;
	}

	NtOpenThread = (NTOPENTHREAD)GetProcAddress(L"NtOpenThread");
	if (NtOpenThread == NULL)
	{
		KdPrint(("��ȡNtOpenThreadʧ�ܣ�\n"));
		return FALSE;
	}

	NtSuspendThread = (NTSUSPENDTHREAD)Ssdt.GetSSDTProcByName("NtSuspendThread");
	if (NtSuspendThread == NULL)
	{
		KdPrint(("��ȡNtSuspendThreadʧ�ܣ�\n"));
		return FALSE;
	}

	NtResumeThread = (NTRESUMETHREAD)Ssdt.GetSSDTProcByName("NtResumeThread");
	if (NtResumeThread == NULL)
	{
		KdPrint(("��ȡNtResumeThreadʧ�ܣ�\n"));
		return FALSE;
	}

	ClientId.UniqueThread = SuspendThreadId;
	InitializeObjectAttributes(&ObjectAttributes, 0, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);
	Status = NtOpenThread(&SuspendThreadHandle, THREAD_ALL_ACCESS, &ObjectAttributes, &ClientId);
	if (!NT_SUCCESS(Status))
	{
		KdPrint(("NtOpenThread Fail!Status : %x\n", Status));
		return FALSE;
	}

	//����NtSuspendThreadȥ��ͣ�������һ����ֵ������ڳ�LoadImage�ص�֮ǰ���̲߳��ᱻ��ͣ
	//������ִ��OEP֮ǰ�̻߳ᱻ��ͣ���������ʱ����Է��ĵ��޸�OEP
	Status = NtSuspendThread(SuspendThreadHandle, NULL);
	if (!NT_SUCCESS(Status))
	{
		KdPrint(("NtSuspendThread Fail!Status : %x\n", Status));
		return FALSE;
	}

	RegionSize = sizeof(USER_PROTECT_MEMORY);
	Status = ZwAllocateVirtualMemory(NtCurrentProcess(), (PVOID*)&UserProtectMemroy, 0, &RegionSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!NT_SUCCESS(Status))
	{
		KdPrint(("ZwAllocateVirtualMemory Fail!Status : %x\n", Status));
		return FALSE;
	}

	UserProtectMemroy->ProtectBase = OEP_Address;
	UserProtectMemroy->ProtectSize = PatchSize;
	UserProtectMemroy->OldProtectAccess = 0;

	Status = NtProtectVirtualMemory(NtCurrentProcess(), &UserProtectMemroy->ProtectBase, &UserProtectMemroy->ProtectSize, PAGE_EXECUTE_READWRITE, &UserProtectMemroy->OldProtectAccess);
	if (!NT_SUCCESS(Status))
	{
		KdPrint(("NtProtectVirtualMemory Fail!Status : %x\n", Status));
		return FALSE;
	}

	RtlCopyMemory(UserProtectMemroy->ProtectBase, PatchBuffer, PatchSize);

	Status = NtResumeThread(SuspendThreadHandle, NULL);
	if (!NT_SUCCESS(Status))
	{
		KdPrint(("NtResumeThread Fail!Status : %x\n", Status));
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
		Local_PatchOEP((PVOID)ModuleInfo->DllEntry, RetCode, sizeof(RetCode) - 1, ModuleInfo->LoadImageThreadId);
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

//�ڸ�����Image�ص����棬���˰�����û�����ö��ڴ�
VOID PreventDll(ULONG_PTR ImageBase,HANDLE ProcessId)
{
	IMAGE_DOS_HEADER *DosHeader = NULL;
	IMAGE_NT_HEADERS *NtHeader = NULL;

	ULONG_PTR DllEntry = 0;
	MODULE_INFO *ModuleInfo = NULL;

	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	HANDLE ThreadHandle = NULL;

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
	ModuleInfo->LoadImageThreadId = PsGetCurrentThreadId();

	Status = PsCreateSystemThread(&ThreadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, PatchThread, (PVOID)ModuleInfo);
	if (NT_SUCCESS(Status))
		ZwClose(ThreadHandle);

	//Ϊ�˷��㣬˯��2s�ȴ���NtSuspendThread
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

	//�����Ҫ���˵�dll����
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