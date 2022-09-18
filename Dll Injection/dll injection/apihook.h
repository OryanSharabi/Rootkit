#include <Windows.h>
#include <stdint.h>
#include <stdio.h>

typedef struct _API_HOOK
{
	BOOL Hooked;
    PVOID FunctionAddress;
	PVOID Hook;
	char OrigBytes[5];
    LPVOID OrigFunction;
}API_HOOK, * PAPI_HOOK;



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
      0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //mov 8 bytes into r10. BA = JMP
      0x41, 0xFF, 0xE2 //jmp r10
    };

    uint64_t  addrToJumpTo64 = (uint64_t)addrToJumpTo;
    memcpy(&absJumpInstructions[2], &addrToJumpTo64, sizeof(addrToJumpTo64));
    memcpy(absJumpMemory, absJumpInstructions, sizeof(absJumpInstructions));
}

BOOL WINAPI InitAPIHook(PAPI_HOOK Hook, PVOID HookedFunction)
{
    printf("4\n");
    if (Hook->Hooked == TRUE)
    {
        return FALSE;
        
    }

    HMODULE hModule = GetModuleHandleW(L"ntdll.dll");
    

    if (hModule == NULL)
    {
        Hook->Hooked = FALSE;
        printf("GetModuleHandle Get Last error: %d\n", GetLastError());
        return FALSE;
        
    }

    Hook->FunctionAddress = GetProcAddress(hModule, "NtResumeThread");
    if (Hook->FunctionAddress == NULL)
    {
        Hook->Hooked = FALSE;
        printf("GetProcAddress Get Last error: %d\n", GetLastError());
        return FALSE;
        
    }
    
    printf("HookedFunction memory address: %p\n", HookedFunction);
     
    printf("ntresumethread memory address: %p\n", Hook->FunctionAddress);
     
    PVOID relayFuncMemory = AllocatePageNearAddress(Hook->FunctionAddress);
    printf("relayFuncMemory memory address: %p\n", relayFuncMemory);

    if (AllocatePageNearAddress == nullptr) {
        printf("AllocatePageNearAddress faild");
        return FALSE;
    }

    WriteAbsoluteJump64(relayFuncMemory, HookedFunction); //write relay func instructions

    //now that the relay function is built, we need to install the E9 jump into the target func,
    //this will jump to the relay function
    DWORD oldProtect;
    if (VirtualProtect(Hook->FunctionAddress, 1024, PAGE_EXECUTE_READWRITE, &oldProtect) == 0) {
        printf("VirtualProtect Get Last error: %d\n", GetLastError());
        return FALSE;
    }


    //32 bit relative jump opcode is E9, takes 1 32 bit operand for jump offset
    uint8_t jmpInstruction[5] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };

    //to fill out the last 4 bytes of jmpInstruction, we need the offset between 
    //the relay function and the instruction immediately AFTER the jmp instruction
    const uint64_t relAddr = (uint64_t)relayFuncMemory - ((uint64_t)Hook->FunctionAddress + 5);
    memcpy(jmpInstruction + 1, &relAddr, 4);

    //copy the original 5 bytes to another memory location
    Hook->OrigFunction =VirtualAlloc(NULL, 21, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(Hook->OrigBytes, Hook->FunctionAddress, 5);


    

    if (Hook->OrigFunction == NULL)
    {
        printf("VirtualAlloc Get Last error: %d\n", GetLastError());
        return FALSE;
    }



    uint8_t  JumpToOrg[] =
    {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x49, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, //mov 8 bytes into r10. BA = JMP
      0x00, 0x00, 0x00, 0x41, 0xFF, 0xE3 //jmp r10
    };


    uint64_t hook_address = (uint64_t)Hook->FunctionAddress + 8;

    memcpy(&JumpToOrg[0], Hook->FunctionAddress, 5);
    memcpy(&JumpToOrg[10], &hook_address, 8);
    memcpy(Hook->OrigFunction, JumpToOrg, 21);


    printf("Hook->OrigFunction memory address: %p\n", Hook->OrigFunction);


    //install the hook
    memcpy(Hook->FunctionAddress, jmpInstruction, 5);

    Hook->Hooked = TRUE;
    printf("5\n");
    VirtualProtect(Hook->FunctionAddress, 1024, oldProtect, &oldProtect);

    return TRUE;
}