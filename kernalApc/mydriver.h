#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>

typedef PVOID(*fnLoadLibraryExA)(
	LPCSTR lplibFileName,
		HANDLE hFile,
		ULONG dwFlags
);

typedef struct _SIRIFEF_INJECTION_DATA{
	BOOLEAN Executing; 
	PEPROCESS Process; 
	PETHREAD Ethread; 
	KEVENT Event;
	WORK_QUEUE_ITEM workItem;
	ULONG ProcessId;
}SIRIFEF_INJECTION_DATA, *PSIRIFEF_INJECTION_DATA;

typedef struct _GET_ADDRESS {
	PVOID Kernel32dll;
	fnLoadLibraryExA pvLoadLibraryExA;

}GET_ADDRESS,*PGET_ADDRESS;

typedef enum _KAPC_ENVIRONMENT
{
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT;


typedef
VOID
(NTAPI *PKNORMAL_ROUTINE)(
	_In_ PVOID NormalContext,
	_In_ PVOID SystemArgument1,
	_In_ PVOID SystemArgument2
	);

typedef
VOID
(NTAPI *PKKERNEL_ROUTINE)(
	_In_ PKAPC Apc,
	_Inout_ PKNORMAL_ROUTINE* NormalRoutine,
	_Inout_ PVOID* NormalContext,
	_Inout_ PVOID* SystemArgument1,
	_Inout_ PVOID* SystemArgument2
	);

typedef
VOID
(NTAPI *PKRUNDOWN_ROUTINE) (
	_In_ PKAPC Apc
	);

NTKERNELAPI
VOID
NTAPI
KeInitializeApc(
	_Out_ PRKAPC Apc,
	_In_ PETHREAD Thread,
	_In_ KAPC_ENVIRONMENT Environment,
	_In_ PKKERNEL_ROUTINE KernelRoutine,
	_In_opt_ PKRUNDOWN_ROUTINE RundownRoutine,
	_In_opt_ PKNORMAL_ROUTINE NormalRoutine,
	_In_opt_ KPROCESSOR_MODE ApcMode,
	_In_opt_ PVOID NormalContext
);

NTKERNELAPI
BOOLEAN
NTAPI
KeInsertQueueApc(
	_Inout_ PRKAPC Apc,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2,
	_In_ KPRIORITY Increment
);

NTKERNELAPI
BOOLEAN
NTAPI
KeAlertThread(
	_Inout_ PKTHREAD Thread,
	_In_ KPROCESSOR_MODE AlertMode
);

NTKERNELAPI
BOOLEAN
NTAPI
KeTestAlertThread(
	_In_ KPROCESSOR_MODE AlertMode
);

PVOID  RtlImageDirectoryEntryToData(
	PVOID   Base,
	BOOLEAN MappedAsImage,
	USHORT  DirectoryEntry,
	PULONG  Size
);


// my function 

NTSTATUS DllInject(HANDLE ProcessId, PEPROCESS Peprocess, PETHREAD Pethread, BOOLEAN Alert);

PVOID
NTAPI
RtlxFindExportedRoutineByName(
	_In_ PVOID DllBase,
	_In_ PANSI_STRING ExportName
);

VOID SirifeWorkerRoutine(PVOID Context);

VOID NTAPI APCKernelRoutine(_In_ PKAPC Apc,
	_Inout_ PKNORMAL_ROUTINE* NormalRoutine,
	_Inout_ PVOID* NormalContext,
	_Inout_ PVOID* SystemArgument1,
	_Inout_ PVOID* SystemArgument2);

VOID NTAPI APCInjectorRoutine(_In_ PKAPC Apc,
	_Inout_ PKNORMAL_ROUTINE* NormalRoutine,
	_Inout_ PVOID* NormalContext,
	_Inout_ PVOID* SystemArgument1,
	_Inout_ PVOID* SystemArgument2);

void LoadImageNotifyRoutine(
	PUNICODE_STRING FullImageName,
	HANDLE ProcessId,
	PIMAGE_INFO ImageInfo
);

VOID Unload(IN PDRIVER_OBJECT pDriverobject);

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath);

#define DLLPATH "C:\\Test\\injectDll.dll"