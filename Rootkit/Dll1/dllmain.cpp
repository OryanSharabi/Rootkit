// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "dll_main.h"
#include "iathooker.h"
#include "apihook.h"
#include <string>




BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    
    FILETIME  lpCreationTime, lpExitTime, lpKernelTime, lpUserTime;

    GetProcessTimes(GetModuleHandleA(NULL), &lpCreationTime, &lpExitTime, &lpKernelTime, &lpUserTime);
    LONGLONG tCreate = *(LONGLONG*)&lpCreationTime;

    DWORD currentID = GetCurrentProcessId();
    std::string num = std::to_string(tCreate);
    num += std::to_string(currentID);

    HANDLE hMutex = CreateMutex(NULL, TRUE, LPCWSTR(num.c_str()));
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        return TRUE;
    }

    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:

            main();
            apihook_main();
            
        case DLL_THREAD_ATTACH:

            break;
        case DLL_THREAD_DETACH:

            break;
        case DLL_PROCESS_DETACH:

            break;
    }
    return TRUE;
}

