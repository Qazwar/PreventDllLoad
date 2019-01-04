#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntddscsi.h>		

CHAR * PsGetProcessImageFileName(__in PEPROCESS Process);

FLT_PREOP_CALLBACK_STATUS
PreAcquireSection(
__inout PFLT_CALLBACK_DATA Data,
__in PCFLT_RELATED_OBJECTS FltObjects,
__deref_out_opt PVOID *CompletionContext
);

NTSTATUS Unload(__in FLT_FILTER_UNLOAD_FLAGS Flags);

PFLT_FILTER m_Filter;

CONST FLT_OPERATION_REGISTRATION CallBack[] = {
	{
		IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
		0,
		PreAcquireSection,
		NULL
	},
	{ IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration =
{
	sizeof(FLT_REGISTRATION),
	FLT_REGISTRATION_VERSION,
	NULL,
	NULL,
	CallBack,
	Unload,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};


FLT_PREOP_CALLBACK_STATUS
PreAcquireSection(
__inout PFLT_CALLBACK_DATA Data,
__in PCFLT_RELATED_OBJECTS FltObjects,
__deref_out_opt PVOID *CompletionContext
)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	FLT_PREOP_CALLBACK_STATUS CallBackStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;

	ULONG ProcessId = 0;
	PEPROCESS EProcess = NULL;
	UNICODE_STRING FilterFileName = { 0 };

	PFLT_FILE_NAME_INFORMATION NameInfo = NULL;

	do
	{
		ProcessId = FltGetRequestorProcessId(Data);
		Status = PsLookupProcessByProcessId((HANDLE)ProcessId, &EProcess);
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("»ñÈ¡½ø³Ì¶ÔÏóÊ§°Ü£¡×´Ì¬£º%x£¡\n", Status));
			break;
		}

		if (strstr(PsGetProcessImageFileName(EProcess), "calc") == NULL)
			break;

		Status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &NameInfo);
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("FltGetFileNameInformationÊ§°Ü£¡×´Ì¬£º%x£¡\n", Status));
			break;
		}

		Status = FltParseFileNameInformation(NameInfo);
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("FltParseFileNameInformationÊ§°Ü£¡×´Ì¬£º%x£¡\n", Status));
			break;
		}

		KdPrint(("AcquireSectionFileName:%wZ\n", &NameInfo->Name));

		RtlInitUnicodeString(&FilterFileName, L"*XXX.DLL");
		if (FsRtlIsNameInExpression(&FilterFileName, &NameInfo->Name, TRUE, NULL) == TRUE)
		{
			Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
			CallBackStatus = FLT_PREOP_COMPLETE;
		}

		FltReleaseFileNameInformation(NameInfo);

	} while (FALSE);

	if (EProcess != NULL)
		ObDereferenceObject(EProcess); 

	return CallBackStatus;
}

NTSTATUS InitFltFilter(PDRIVER_OBJECT DriverObject)
{
	NTSTATUS Status;

	Status = FltRegisterFilter(DriverObject, &FilterRegistration, &m_Filter);
	if (!NT_SUCCESS(Status))
	{
		KdPrint(("Register Filter UnSuccess!Status = %x\n", Status));
		return STATUS_UNSUCCESSFUL;
	}

	Status = FltStartFiltering(m_Filter);
	if (!NT_SUCCESS(Status))
	{
		KdPrint(("Start Filter UnSuccess!Status = %x\n", Status));
		FltUnregisterFilter(m_Filter);
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

NTSTATUS Unload(__in FLT_FILTER_UNLOAD_FLAGS Flags)
{
	KdPrint(("Unload Success!\n"));

	FltUnregisterFilter(m_Filter);

	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegString)
{
	if (!NT_SUCCESS(InitFltFilter(DriverObject)))
		return STATUS_UNSUCCESSFUL;

	return STATUS_SUCCESS;
}