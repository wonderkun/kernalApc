#include "mydriver.h"



GET_ADDRESS Hash = { 0 };

NTSTATUS DllInject(HANDLE ProcessId, PEPROCESS Peprocess, PETHREAD Pethread, BOOLEAN Alert) {

	HANDLE hProcess;
	OBJECT_ATTRIBUTES oa = { sizeof(OBJECT_ATTRIBUTES) };
	CLIENT_ID cidprocess = { 0 };
	CHAR DllFormatPath[] = DLLPATH;

	ULONG Size = strlen(DllFormatPath) + 1;
	PVOID pvMemory = NULL;

	cidprocess.UniqueProcess = ProcessId;
	cidprocess.UniqueThread = 0;

	if (NT_SUCCESS(ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cidprocess))) {

		if (NT_SUCCESS(ZwAllocateVirtualMemory(hProcess, &pvMemory, 0, &Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {

			KAPC_STATE KasState;
			PKAPC Apc;
			KeStackAttachProcess(Peprocess, &KasState);
			strcpy(pvMemory, DllFormatPath);
			KeUnstackDetachProcess(&KasState);

			Apc = (PKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC));
			if (Apc && Hash.pvLoadLibraryExA) {
				DbgPrint("I am in dllinject:[%p],pvMemory:[%p]", Hash.pvLoadLibraryExA, pvMemory);
				//DbgBreakPoint();

				KeInitializeApc(Apc, Pethread, 0, (PKKERNEL_ROUTINE)APCKernelRoutine, 0, (PKNORMAL_ROUTINE)Hash.pvLoadLibraryExA, UserMode, pvMemory);
				KeInsertQueueApc(Apc, 0, 0, IO_NO_INCREMENT);
				return STATUS_SUCCESS;
			}
		}
		ZwClose(hProcess);
	}
	return STATUS_NO_MEMORY;
}


PVOID NTAPI RtlxFindExportedRoutineByName(_In_ PVOID DllBase, _In_ PANSI_STRING ExportName)
{
	//直到Windows 10操作系统，RtlFindExportedRoutineByName 才被ntoskrnl导出，以下代码来自React OS
	PULONG NameTable;
	PUSHORT OrdinalTable;
	PIMAGE_EXPORT_DIRECTORY ExportDirectory;
	LONG Low = 0, Mid = 0, High, Ret;
	USHORT Ordinal;
	PVOID Function;
	ULONG ExportSize;
	PULONG ExportTable;

	// 获取导入表：
	ExportDirectory = RtlImageDirectoryEntryToData(DllBase, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &ExportSize);

	if (!ExportDirectory)
	{
		return NULL;
	}
	// Setup name tables.
	NameTable = (PULONG)((ULONG_PTR)DllBase + ExportDirectory->AddressOfNames);
	OrdinalTable = (PUSHORT)((ULONG_PTR)DllBase + ExportDirectory->AddressOfNameOrdinals);

	// Do a binary search.
	High = ExportDirectory->NumberOfNames - 1; //导出函数
	for (Low = 0; Low <= High; Low++) {

		Ret = strcmp(ExportName->Buffer, (PCHAR)DllBase + NameTable[Low]);
		if (Ret == 0) break;

	}

	// Check if we couldn't find it.
	if (High < Low)
	{
		return NULL;
	}

	// Otherwise, this is the ordinal.
	Ordinal = OrdinalTable[Low]; //获得导出序号

	// Validate the ordinal.
	if (Ordinal >= ExportDirectory->NumberOfFunctions)
	{
		return NULL;
	}

	// Resolve the address and write it.
	ExportTable = (PULONG)((ULONG_PTR)DllBase + ExportDirectory->AddressOfFunctions);
	Function = (PVOID)((ULONG_PTR)DllBase + ExportTable[Ordinal]);

	// We found it!
	NT_ASSERT(
		(Function < (PVOID)ExportDirectory) ||
		(Function > (PVOID)((ULONG_PTR)ExportDirectory + ExportSize))
	);
	return Function;
}


VOID SirifeWorkerRoutine(PVOID Context) {

	//DLL Inject
	PSIRIFEF_INJECTION_DATA sf = (PSIRIFEF_INJECTION_DATA)Context;
	DllInject(sf->ProcessId, sf->Process, sf->Ethread, FALSE);
	KeSetEvent(&((PSIRIFEF_INJECTION_DATA)Context)->Event, 0, FALSE);
	return;
}

VOID NTAPI APCKernelRoutine(_In_ PKAPC Apc,
	_Inout_ PKNORMAL_ROUTINE* NormalRoutine,
	_Inout_ PVOID* NormalContext,
	_Inout_ PVOID* SystemArgument1,
	_Inout_ PVOID* SystemArgument2) {

	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	ExFreePool(Apc);
	return;
}


VOID NTAPI APCInjectorRoutine(_In_ PKAPC Apc,
	_Inout_ PKNORMAL_ROUTINE* NormalRoutine,
	_Inout_ PVOID* NormalContext,
	_Inout_ PVOID* SystemArgument1,
	_Inout_ PVOID* SystemArgument2) {

	ExFreePool(Apc);

	SIRIFEF_INJECTION_DATA sf;
	RtlSecureZeroMemory(&sf, sizeof(SIRIFEF_INJECTION_DATA));

	sf.Ethread = KeGetCurrentThread();
	sf.Process = IoGetCurrentProcess();
	sf.ProcessId = PsGetCurrentProcessId();

	KeInitializeEvent(&sf.Event, NotificationEvent, FALSE);

	ExInitializeWorkItem(&sf.workItem, (PWORKER_THREAD_ROUTINE)SirifeWorkerRoutine, &sf);
	ExQueueWorkItem(&sf.workItem, DelayedWorkQueue);

	KeWaitForSingleObject(&sf.Event, Executive, KernelMode, TRUE, 0);
	return;
}

void LoadImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
	if (FullImageName != NULL)
	{
		DbgPrint("load dll: [%wZ]", FullImageName);
		WCHAR kernal32Mask[] = L"*\\KERNEL32.DLL"; //C:\Windows\System32\Kernel32.dll 
		UNICODE_STRING kernel32us;
		RtlInitUnicodeString(&kernel32us, kernal32Mask);

		ANSI_STRING loadLibraryAs;
		RtlInitAnsiString(&loadLibraryAs, "LoadLibraryA");

		if (FsRtlIsNameInExpression(&kernel32us, FullImageName, TRUE, NULL)) {

			DbgPrint("Process %d Find kernel32 .", ProcessId);

			PKAPC Apc;
			if (Hash.Kernel32dll == 0) {
				Hash.Kernel32dll = (PVOID)ImageInfo->ImageBase;
				// find loadlibrary function address 
				Hash.pvLoadLibraryExA = RtlxFindExportedRoutineByName(Hash.Kernel32dll, &loadLibraryAs);
			}

			Apc = (PKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC));

			if (Apc) {

				KeInitializeApc(Apc, KeGetCurrentThread(), OriginalApcEnvironment, (PKKERNEL_ROUTINE)APCInjectorRoutine, 0, 0, KernelMode, 0);
				KeInsertQueueApc(Apc, 0, 0, IO_NO_INCREMENT);
			}
		}
	}
	return;
}


VOID Unload(IN PDRIVER_OBJECT pDriverobject) {
	PsRemoveLoadImageNotifyRoutine(&LoadImageNotifyRoutine);
};


NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	NTSTATUS status = STATUS_SUCCESS;
	PsSetLoadImageNotifyRoutine(&LoadImageNotifyRoutine);
	pDriverObject->DriverUnload = (PDRIVER_UNLOAD)Unload;
	return status;
}