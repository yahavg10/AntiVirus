#include "StackReader.h"
#include <TlHelp32.h>
#include <thread>
#include <nlohmann/json.hpp>
#include <fstream>

DWORD(WINAPI* NtQuerySystemInformation)(DWORD SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
DWORD(WINAPI* NtQueryInformationThread)(HANDLE ThreadHandle, DWORD ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
DWORD(WINAPI* NtOpenThread)(HANDLE* ThreadHandle, DWORD DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes, CLIENT_ID* ClientId);

DWORD dwGlobal_Stack[MAX_STACK_SIZE];

SYSTEM_PROCESS_INFORMATION* pGlobal_SystemProcessInfo = NULL;

DWORD GetSystemProcessInformation()
{
	DWORD dwAllocSize = 0;
	DWORD dwStatus = 0;
	DWORD dwLength = 0;
	BYTE* pSystemProcessInfoBuffer = NULL;

	// free previous handle info list (if one exists)
	if (pGlobal_SystemProcessInfo != NULL)
	{
		free(pGlobal_SystemProcessInfo);
	}

	// get system handle list
	dwAllocSize = 0;
	for (;;)
	{
		if (pSystemProcessInfoBuffer != NULL)
		{
			// free previous inadequately sized buffer
			free(pSystemProcessInfoBuffer);
			pSystemProcessInfoBuffer = NULL;
		}

		if (dwAllocSize != 0)
		{
			// allocate new buffer
			pSystemProcessInfoBuffer = (BYTE*)malloc(dwAllocSize);
			if (pSystemProcessInfoBuffer == NULL)
			{
				return 1;
			}
		}

		// get system handle list
		dwStatus = NtQuerySystemInformation(SystemProcessInformation, (void*)pSystemProcessInfoBuffer, dwAllocSize, &dwLength);
		if (dwStatus == 0)
		{
			// success
			break;
		}
		else if (dwStatus == STATUS_INFO_LENGTH_MISMATCH)
		{
			// not enough space - allocate a larger buffer and try again (also add an extra 1kb to allow for additional data between checks)
			dwAllocSize = (dwLength + 1024);
		}
		else
		{
			// other error
			free(pSystemProcessInfoBuffer);
			return 1;
		}
	}

	// store handle info ptr
	pGlobal_SystemProcessInfo = (SYSTEM_PROCESS_INFORMATION*)pSystemProcessInfoBuffer;

	return 0;
}


DWORD doesStringExistInStack(DWORD dwStackSize,std::string toFind,BYTE* threadStack)
{
	DWORD dwCopyLength = 0;
	BYTE* pCurrStackPtr = NULL;
	DWORD dwStringDataLength = 0;
	BYTE bStackValue[MAX_STACK_VALUE_SIZE];

	// find strings allocated on stack
	pCurrStackPtr = threadStack;
	for (DWORD i = 0; i < dwStackSize; i++)
	{
		// ignore if the current value is null
		if (*pCurrStackPtr == 0x00)
		{
			pCurrStackPtr++;
			continue;
		}

		if (memcmp(pCurrStackPtr, toFind.c_str(),toFind.size()) == 0)
		{
			return 1;
		}
		
		pCurrStackPtr++;
	}

	return 0;
}

DWORD GetStackStrings(HANDLE hProcess, HANDLE hThread, DWORD dwThreadID,std::string toFind)
{
	THREAD_BASIC_INFORMATION ThreadBasicInformationData;
	NT_TIB ThreadTEB;
	DWORD dwStackSize = 0;

	// get thread basic information
	memset((void*)&ThreadBasicInformationData, 0, sizeof(ThreadBasicInformationData));
	if (NtQueryInformationThread(hThread, ThreadBasicInformation, &ThreadBasicInformationData, sizeof(THREAD_BASIC_INFORMATION), NULL) != 0)
	{
		return 1;
	}

	// read thread TEB
	memset((void*)&ThreadTEB, 0, sizeof(ThreadTEB));
	if (ReadProcessMemory(hProcess, ThreadBasicInformationData.TebBaseAddress, &ThreadTEB, sizeof(ThreadTEB), NULL) == 0)
	{
		return 1;
	}

	// calculate thread stack size
	dwStackSize = (DWORD)ThreadTEB.StackBase - (DWORD)ThreadTEB.StackLimit;
	BYTE* threadStack = new BYTE[dwStackSize];
	ReadProcessMemory(hProcess,ThreadTEB.StackLimit,threadStack,dwStackSize,0);
	if (dwStackSize > sizeof(dwGlobal_Stack))
	{
		return 1;
	}
	return doesStringExistInStack(dwStackSize,toFind,threadStack);
}

DWORD DoesStringExistInProcess(HANDLE hProcess,std::string toFind, DWORD SafeThread)
{
	HANDLE hThread = NULL;
	SYSTEM_PROCESS_INFORMATION* pCurrProcessInfo = NULL;
	SYSTEM_PROCESS_INFORMATION* pNextProcessInfo = NULL;
	SYSTEM_PROCESS_INFORMATION* pTargetProcessInfo = NULL;
	SYSTEM_THREAD_INFORMATION* pCurrThreadInfo = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes;
	DWORD dwStatus = 0;
	  
	// get snapshot of processes/threads
	if (GetSystemProcessInformation() != 0)
	{
		return 1;
	}

	// find the target process in the list
	pCurrProcessInfo = pGlobal_SystemProcessInfo;
	for (;;)
	{
		// check if this is the target PID
		if ((DWORD)pCurrProcessInfo->UniqueProcessId == GetProcessId(hProcess))
		{
			// found target process
			pTargetProcessInfo = pCurrProcessInfo;
			break;
		}

		// check if this is the end of the list
		if (pCurrProcessInfo->NextEntryOffset == 0)
		{
			// end of list
			break;
		}
		else
		{
			// get next process ptr
			pNextProcessInfo = (SYSTEM_PROCESS_INFORMATION*)((BYTE*)pCurrProcessInfo + pCurrProcessInfo->NextEntryOffset);
		}

		// go to next process
		pCurrProcessInfo = pNextProcessInfo;
	}

	// ensure the target process was found in the list
	if (pTargetProcessInfo == NULL)
	{
		return 1;
	}

	// loop through all threads within the target process
	pCurrThreadInfo = (SYSTEM_THREAD_INFORMATION*)((BYTE*)pTargetProcessInfo + sizeof(SYSTEM_PROCESS_INFORMATION));
	for (DWORD i = 0; i < pTargetProcessInfo->NumberOfThreads; i++)
	{

		// open thread
		memset((void*)&ObjectAttributes, 0, sizeof(ObjectAttributes));
		ObjectAttributes.Length = sizeof(ObjectAttributes);
			dwStatus = NtOpenThread(&hThread, THREAD_QUERY_INFORMATION, &ObjectAttributes, &pCurrThreadInfo->ClientId);
			if (dwStatus == 0)
			{
				int thread_id = GetThreadId(hThread);
				if (GetThreadId(hThread) == SafeThread)
				{
					continue;
				}

				// extract strings from the stack of this thread
				if (GetStackStrings(hProcess, hThread, (DWORD)pCurrThreadInfo->ClientId.UniqueThread, toFind))
				{
					return 1;
				}
				// close handle
				CloseHandle(hThread);
			}
		// move to the next thread
		pCurrThreadInfo++;
	}

	return 0;
}

DWORD GetNtdllFunctions()
{
	// get NtQueryInformationThread ptr
	NtQueryInformationThread = (unsigned long(__stdcall*)(void*, unsigned long, void*, unsigned long, unsigned long*))GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationThread");
	if (NtQueryInformationThread == NULL)
	{
		return 1;
	}

	// get NtQuerySystemInformation function ptr
	NtQuerySystemInformation = (unsigned long(__stdcall*)(unsigned long, void*, unsigned long, unsigned long*))GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");
	if (NtQuerySystemInformation == NULL)
	{
		return 1;
	}

	// get NtOpenThread function ptr
	NtOpenThread = (unsigned long(__stdcall*)(void**, unsigned long, struct OBJECT_ATTRIBUTES*, struct CLIENT_ID*))GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtOpenThread");
	if (NtOpenThread == NULL)
	{
		return 1;
	}

	return 0;
}

void handleStackJson(std::string jsonFile)
{
	HANDLE hMutex = OpenMutexA(MUTEX_ALL_ACCESS, FALSE, "resultsFileMutex");
	WaitForSingleObject(hMutex, INFINITE);
	nlohmann::json fullJson;
	std::ifstream in(jsonFile, std::ifstream::ate | std::ifstream::binary);
	std::streampos file_size = in.tellg();
	in.close();
	if (file_size == 0)
	{
		fullJson = { {"Stack","Found"} };
	}
	else
	{
		std::ifstream json_file(jsonFile);
		fullJson = nlohmann::json::parse(json_file);
		if (fullJson.at("Stack") != NULL)
		{
			fullJson += { {"Stack", "Found"} };
		}
		json_file.close();
	}
	std::ofstream file(jsonFile);
	file << fullJson;
	file.close();


}


void handleStack(HANDLE processHandle,DWORD SafeThread)
{
	char dataToFind[] = "secretpass";
	DebugActiveProcess(GetProcessId(processHandle));
	if (DoesStringExistInProcess(processHandle, dataToFind, SafeThread))
	{
		std::cout << "Found string in stack";
		//handleStackJson("C:\\Users\\maorb\\Downloads\\virusbustersproject\\virusbustersproject\\filesToCheck\\DyanmicMemoryData\\current_results.json");
	}
	DebugActiveProcessStop(GetProcessId(processHandle));
}


BOOL CALLBACK EnumThreadWndProc(
	_In_ HWND   hwnd,
	_In_ LPARAM lParam
)
{
	DWORD currentThreadId = GetCurrentThreadId();
	DWORD otherThreadId = GetWindowThreadProcessId(hwnd, NULL);
	if (otherThreadId == 0) return 1;
	if (otherThreadId != currentThreadId)
	{
		AttachThreadInput(currentThreadId, otherThreadId, TRUE);
	}

	SetActiveWindow(hwnd);

	if (otherThreadId != currentThreadId)
	{
		AttachThreadInput(currentThreadId, otherThreadId, FALSE);
	}
	return FALSE;
}


void handleChromeBeingSelected(HANDLE chromeHandle)
{
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (h != INVALID_HANDLE_VALUE) {
		THREADENTRY32 te;
		te.dwSize = sizeof(te);
		if (Thread32First(h, &te)) {
			do
			{
			if (te.th32OwnerProcessID == GetProcessId(chromeHandle))
			{
				EnumThreadWindows(te.th32ThreadID, &EnumThreadWndProc, 0);

			}
			} while (Thread32Next(h, &te));
		}
		CloseHandle(h);
	}
}





int main(int argc, char* argv[])
{
	if (GetNtdllFunctions() != 0)
	{
		return 1;
	}

	// get ntdll function ptrs

	PROCESS_INFORMATION* info2 = new PROCESS_INFORMATION();
	STARTUPINFOA* startupinfo2 = new STARTUPINFOA();
	//CreateProcessA("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, startupinfo2, info2);
	//CreateProcessA("../x64/Debug/PacketSniffer.exe", NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, startupinfo2, info2);
	HANDLE hMutex = CreateMutexA(NULL,false,"resultsFileMutex");
	ReleaseMutex(hMutex);
	CHAR path[MAX_PATH] = {0};
	
	//get oldest file
	PROCESS_INFORMATION* info = new PROCESS_INFORMATION();
	STARTUPINFOA* startupinfo = new STARTUPINFOA();
	WIN32_FIND_DATAA* find_data = new WIN32_FIND_DATAA();
	char FolderPath[200] = "Y:\Dynamic\\*.exe";
	char FullFilePath[100] = "Y:\Dynamic\\";
	FindFirstFileA(FolderPath, find_data);
	GetFinalPathNameByHandleA(find_data->cFileName, FullFilePath, 100, FILE_NAME_NORMALIZED);
	std::string FullPath = FullFilePath;
	FullPath += std::string(find_data->cFileName);

	BOOL result = CreateProcessA(FullPath.c_str(), NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, startupinfo, info);
	HANDLE hProcess = info->hProcess;


	PVOID addrLoadLibrary = (PVOID)GetProcAddress(GetModuleHandleA((LPCSTR)"Kernel32.dll"), "LoadLibraryA");
	DWORD pathLen = GetFullPathNameA("../Debug/DynamicAnalysis.dll", MAX_PATH, path, NULL);

	PVOID memAddr = (PVOID)VirtualAllocEx(hProcess, NULL, pathLen + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (NULL == memAddr) {
		int err = GetLastError();
		std::cout << "Error with intalizing memory: " << err << std::endl;
		return 0;
	}
	// Write DLL name to remote process memory
	BOOL check = WriteProcessMemory(hProcess, memAddr, path, pathLen + 1, 0);
	if (0 == check) {
		int err = GetLastError();
		std::cout << "Error with writing to memory: " << err << std::endl;
		return 0;
	}
	// Open remote thread, while executing LoadLibrary
	// with parameter DLL name, will trigger DLLMain
	DWORD id;
	HANDLE hRemote = CreateRemoteThread(hProcess, NULL, 0, LPTHREAD_START_ROUTINE(addrLoadLibrary), memAddr, 0, &id);
	if (NULL == hRemote) {
		int err = GetLastError();
		std::cout << "Error with creating thread: " << err << std::endl;
		return 0;
	}
	else
	{
		std::cout << "Opened thread " << id << " to run the load library" << std::endl;
	}

	for (int i = 0; i < 6; i++) {
		handleStack(hProcess,id);
		Sleep(10000);
	}

	return 0;
}

