#include "detours.h"
#include <iostream>


void WINAPI SetWindowsHookEx_Hook(_In_ int idHook,
	_In_ HOOKPROC lpfn,
	_In_opt_ HINSTANCE hmod,
	_In_ DWORD dwThreadId);

struct changedAddress
{
	int permissions;
	int address;
	int size;
};

struct InfluencedProcess
{
	HANDLE processHandle;
	int processId;
	std::string processName;
	//int levelOfInfluence
	changedAddress* changedAddresses;
};

struct FileHandle

{
	HANDLE handle;
	LPCWSTR fileName;
	DWORD permissions;
	FileHandle* next;
};


FileHandle* currentFileHandle = NULL;
FileHandle* firstFileHandle = NULL;
DWORD OriginalCreateFileW;
//array of influenced processes

HANDLE
WINAPI
CreateFileW_Hook(
	_In_ LPCWSTR lpFileName,
	_In_ DWORD dwDesiredAccess,
	_In_ DWORD dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_ DWORD dwCreationDisposition,
	_In_ DWORD dwFlagsAndAttributes,
	_In_opt_ HANDLE hTemplateFile
);


void inlineHooking()
{
	//starting the detours
	static HHOOK(WINAPI * SetWindowsHookExFunc)(_In_ int idHook,
		_In_ HOOKPROC lpfn,
		_In_opt_ HINSTANCE hmod,
		_In_ DWORD dwThreadId) = SetWindowsHookExW;
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	LONG errorCode = DetourAttach(&(PVOID&)SetWindowsHookExFunc, SetWindowsHookEx_Hook);
	DetourTransactionCommit();
}




void IATHooking()
{
	DWORD baseAddress = (DWORD)GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
	PIMAGE_NT_HEADERS peHeader = (PIMAGE_NT_HEADERS)(baseAddress + (*dosHeader).e_lfanew);
	IMAGE_OPTIONAL_HEADER32 optionalHeader = (*peHeader).OptionalHeader;
	IMAGE_DATA_DIRECTORY importDirectory = (optionalHeader).DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(baseAddress + importDirectory.VirtualAddress);

	int i = 0;
	GetProcAddress(GetModuleHandle(L"kernel32.dll"), "CreateFileW");

	while (importDescriptor[i].Characteristics != 0)
	{
		char* dllName = (char*)importDescriptor[i].Name + baseAddress;
		std::cout << dllName << std::endl;
		PIMAGE_THUNK_DATA INTTable = (PIMAGE_THUNK_DATA)(importDescriptor[i].OriginalFirstThunk + baseAddress);
		PIMAGE_THUNK_DATA IATTable = (PIMAGE_THUNK_DATA)(importDescriptor[i].FirstThunk + baseAddress);
		while ((*INTTable).u1.AddressOfData != 0)
		{
			PIMAGE_IMPORT_BY_NAME name = (PIMAGE_IMPORT_BY_NAME)((*INTTable).u1.AddressOfData + baseAddress);
			DWORD oldFunction;
			VirtualProtect(IATTable, 4096, PAGE_READWRITE, &oldFunction);
			if (strcmp((char*)(name->Name), "CreateFileW") == 0)
			{
				IATTable->u1.Function = (DWORD)&CreateFileW_Hook;
			}
			INTTable++;
			IATTable++;
		}

		i++;
	}
}

int main()
{
	firstFileHandle = new FileHandle;
	currentFileHandle = firstFileHandle;
	OriginalCreateFileW = (DWORD)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "CreateFileW");
	inlineHooking();
	IATHooking();
	CreateFileW(L"test.txt", GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);





	return 1;
}


void handleFiles(FileHandle* firstFileHandle)
{

}

void WINAPI SetWindowsHookEx_Hook(_In_ int idHook, _In_ HOOKPROC lpfn, _In_opt_ HINSTANCE hmod, _In_ DWORD dwThreadId)
{
	if (idHook == WH_KEYBOARD || idHook == WH_KEYBOARD_LL)
	{
		std::cout << "keyboard hook has been detected" << std::endl;
	}
	else if (idHook == WH_MOUSE || idHook == WH_MOUSE_LL)
	{
		std::cout << "mouse hook has been detected." << std::endl;
	}

}

HANDLE WINAPI CreateFileW_Hook(_In_ LPCWSTR lpFileName, _In_ DWORD dwDesiredAccess, _In_ DWORD dwShareMode, _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes, _In_ DWORD dwCreationDisposition, _In_ DWORD dwFlagsAndAttributes, _In_opt_ HANDLE hTemplateFile)
{
	currentFileHandle->fileName = lpFileName;
	currentFileHandle->permissions = dwDesiredAccess;
	typedef HANDLE WINAPI CreateFileWFormat(_In_ LPCWSTR lpFileName, _In_ DWORD dwDesiredAccess, _In_ DWORD dwShareMode, _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes, _In_ DWORD dwCreationDisposition, _In_ DWORD dwFlagsAndAttributes, _In_opt_ HANDLE hTemplateFile);
	CreateFileWFormat* f = (CreateFileWFormat*)OriginalCreateFileW;
	HANDLE returnedHandle = f(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	currentFileHandle->handle = returnedHandle;
	currentFileHandle->next = new FileHandle;
	currentFileHandle = currentFileHandle->next;
	return returnedHandle;
}


