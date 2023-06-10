#ifdef DLL_EXPORT
#define DECLDIR __declspec(dllexport)
#else
#define DECLDIR __declspec(dllimport)
#endif


#include "detours.h"
#include <iostream>
#include <string>

extern "C"
{



	void WINAPI SetWindowsHookEx_Hook(_In_ int idHook,
		_In_ HOOKPROC lpfn,
		_In_opt_ HINSTANCE hmod,
		_In_ DWORD dwThreadId);

	LSTATUS WINAPI RegSetKeyValueA_Hook(_In_ HKEY hKey, _In_opt_ LPCSTR lpSubKey, _In_opt_ LPCSTR lpValueName, _In_ DWORD dwType, _In_reads_bytes_opt_(cbData) LPCVOID lpData, _In_ DWORD cbData);
	SHORT WINAPI GetAsyncKeyState_Hook(int vKey);

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

	struct SocketInfo
	{
		SOCKET socket;
		const char* address;
		int port;
		SocketInfo* next;
	};
	
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

	BOOL WINAPI WriteFile_Hook(_In_ HANDLE hFile,
		_In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer,
		_In_ DWORD nNumberOfBytesToWrite,
		_Out_opt_ LPDWORD lpNumberOfBytesWritten,
		_Inout_opt_ LPOVERLAPPED lpOverlapped);

	BOOL WINAPI WriteFileEx_Hook(
		_In_ HANDLE hFile,
		_In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer,
		_In_ DWORD nNumberOfBytesToWrite,
		_Inout_ LPOVERLAPPED lpOverlapped,
		_In_ LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
	);

	VOID
		WINAPI
		Sleep_Hook(
			_In_ DWORD dwMilliseconds
		);

	//int(*GetMyFunctionAddress())(int, int)
}