# Rootkit #
**64 bit usermode rootkit for windows machine.**

Rootkit is a malicious code designed to conceal the existence of other 
malware to make the malware difficult for the victim to detect.

User-mode rootkits modify user-space applications.

This rootkit hides malware's processes and files from the user by IAT Hooking and Inline Hooking techniques.

## IAT Hooking ##
IAT hooking is a classic user-space rootkit method that hides files, processes,
or network connections on the local system. This hooking method modifies
the import address table (IAT), or the export address table (In our case, the IAT).

## Inline Hooking ##
Inline hooking overwrites the API function code contained in the imported
DLLs, so it must wait until the DLL is loaded to begin executing. 
IAT hooking simply modifies the pointers, but inline hooking changes the actual function code.

A malicious rootkit performing inline hooking will replace the first 5 bytes in the 
start of the code with a jump that takes the execution to the malicious code.

In 64 bit, the jump takes the execution to the *"relay function"* that’s close enough to the target function to be reachable by a 5 byte jump.
If we throw this in the beginning of hooked functions instead of the 5 byte jump from before, 
we’d limit the number of functions that we could hook to those with 13 or more bytes (Because we can't do absolute jump).
The 5 bytes jump will be an absolute jump to the *"relay function"*.
The *"relay function"* will jump to a *"trampoline function"*. 
The *"trampoline function"*'s job is to execute the original bytes from the function that we hooked and then jump past the installed hook.

## Injection ##
The injection is a simple dll injection(can be used as 32 or 64 bit injection).
The injection injects the rootkit to Sysinternals programs, cmd.exe, Task Manager and Windows Explorer.

## Usage ##
#### Injection ####
* You can call the *"DllInjectionByName"* function In order to inject into more processes.
* Change the *"MALICIOUS_DLL"* to the Rootkit dll path.

#### Rootkit ####
* In iathooker.cpp change the process name you want to hide in the *HookedNtQuerySystemInformation*.
* In iathooker.cpp change the process name you want to hide in the *newFindNextFileW*.
* In iathooker.cpp change the process name you want to hide in the *newFindFirstFileExW*.
* In apihook.cpp change the process name you want to hide in the *HasPrefix*.


### Tested Enviroment ###
1. Tested on Windows 10.
2. Applications used in testing:
    
    * Windows Task Manager - IAT hook to NtQuerySystemInformation.
    * Process Explorer (procexp64.exe & procexp.exe) - IAT hook to NtQuerySystemInformation.
    * cmd.exe - dir command - IAT hook to FindNextFileW & FindFirstFileExW.
    * Explorer.exe - api hook to NtQueryDirectoryFile
   
### Know Issues ###
1. Tasklist will show the process because it uses a different struct from Task Manager and Process Explorer.
2. Except for Explorer.exe, all the processes inject the rootkit to their child process.

### Resources ###
IAT Hooking - Digital Whisper https://www.digitalwhisper.co.il/files/Zines/0x12/DW18-3-IAT_Hooking.pdf

Userland Rootkits - Digital Whisper https://www.digitalwhisper.co.il/files/Zines/0x14/DW20-1-Userland-Rootkits.pdf

Basic Windows API Hooking https://medium.com/geekculture/basic-windows-api-hooking-acb8d275e9b8

X64 Function Hooking by Example http://kylehalladay.com/blog/2020/11/13/Hooking-By-Example.html

