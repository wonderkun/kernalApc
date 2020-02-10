// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include "injectDll.h"
#include <stdio.h>
#include <Windows.h>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
	{
		//MessageBoxA(NULL, "Who Are You?", "This Is From APC!", MB_OK | MB_ICONWARNING);
		ReflectiveDllLoader(0);
		break;
	}
    case DLL_THREAD_ATTACH:
		break;
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

