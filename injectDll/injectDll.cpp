// injectDll.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include "injectDll.h"
#include <stdio.h>
#define DLL_PATH "C:\\Test\\reflective_loader.dll"
#define BREAK_WITH_ERROR(message) MessageBoxA(NULL,message,"Error",MB_OK);return 0;

DWORD Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress)
{
	WORD wIndex = 0;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);
	if (dwRva < pSectionHeader[0].PointerToRawData)
	{
		return dwRva;
	}
	for (wIndex = 0; wIndex < pNtHeaders->FileHeader.NumberOfSections; wIndex++)
	{
		if (dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData))
		{
			return (dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData);
		}
	}
	return 0;
}

DWORD GetReflectiveLoaderOffset(VOID * lpReflectiveDllBuffer)
{
	UINT_PTR uiBaseAddress = 0;
	UINT_PTR uiExportDir = 0;
	UINT_PTR uiNameArray = 0;
	UINT_PTR uiAddressArray = 0;
	UINT_PTR uiNameOrdinals = 0;
	DWORD dwCounter = 0;
#ifdef WIN_X64
	DWORD dwCompiledArch = 2;
#else
	DWORD dwCompiledArch = 1;
#endif
	uiBaseAddress = (UINT_PTR)lpReflectiveDllBuffer;
	uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;
	if (((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x010B) // PE32
	{
		if (dwCompiledArch != 1)
			return 0;
	}
	else if (((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x020B) // PE64
	{
		if (dwCompiledArch != 2)
			return 0;
	}
	else
	{
		return 0;
	}
	uiNameArray = (UINT_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	uiExportDir = uiBaseAddress + Rva2Offset(((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress, uiBaseAddress);
	uiNameArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames, uiBaseAddress);
	uiAddressArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions, uiBaseAddress);
	uiNameOrdinals = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals, uiBaseAddress);
	dwCounter = ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->NumberOfNames;
	while (dwCounter--)
	{
		char * cpExportedFunctionName = (char *)(uiBaseAddress + Rva2Offset(DEREF_32(uiNameArray), uiBaseAddress));
		if (strstr(cpExportedFunctionName, "ReflectiveLoader") != NULL)
		{
			uiAddressArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions, uiBaseAddress);
			uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));
			return Rva2Offset(DEREF_32(uiAddressArray), uiBaseAddress);
		}
		uiNameArray += sizeof(DWORD);
		uiNameOrdinals += sizeof(WORD);
	}
	return 0;
}

HANDLE LoadRemoteLibrary(LPVOID lpLibraryBuffer, DWORD dwLength)
{
	DWORD dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpLibraryBuffer);
	if (!dwReflectiveLoaderOffset)
	{
		return INVALID_HANDLE_VALUE;
	}
	LPTHREAD_START_ROUTINE lpReflectiveLoader = (LPTHREAD_START_ROUTINE)((ULONG_PTR)lpLibraryBuffer + dwReflectiveLoaderOffset);
	HANDLE hThread = INVALID_HANDLE_VALUE;
	DWORD dwThreadId;
	hThread = CreateRemoteThread(GetCurrentProcess(), NULL, 0, lpReflectiveLoader, NULL, NULL, &dwThreadId);
	if (hThread == INVALID_HANDLE_VALUE)
	{
		MessageBoxA(NULL, "Failed to create Thread!", "Info", MB_OK);
	}
	return hThread;
}

DWORD WINAPI ReflectiveDllLoader(LPVOID lpParam)
{
	HANDLE hFile = CreateFileA(DLL_PATH, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		BREAK_WITH_ERROR("Failed to open the DLL file");
	}
	DWORD dwLength = GetFileSize(hFile, NULL);
	if (dwLength == INVALID_FILE_SIZE || dwLength == 0)
	{
		BREAK_WITH_ERROR("Failed to get the DLL file size");
	}
	LPVOID lpBuffer = VirtualAlloc(NULL, dwLength, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!lpBuffer)
	{
		BREAK_WITH_ERROR("Failed to alloc memory");
	}
	DWORD dwNumberBytesRead;
	if (ReadFile(hFile, lpBuffer, dwLength, &dwNumberBytesRead, NULL) == FALSE)
	{
		BREAK_WITH_ERROR("Failed to read file");
	}
	HANDLE hThread = LoadRemoteLibrary(lpBuffer, dwLength);
	if (hThread == INVALID_HANDLE_VALUE)
	{
		BREAK_WITH_ERROR("Failed to inject the DLL");
	}
	return 0;
}
