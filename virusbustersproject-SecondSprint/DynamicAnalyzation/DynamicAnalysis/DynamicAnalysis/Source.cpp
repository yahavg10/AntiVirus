#define DLL_EXPORT
#include "LeechDLL.h"
#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"
#include <string>
#include <nlohmann/json.hpp>
#include <fstream>

FileHandle* currentFileHandle = NULL;
FileHandle* firstFileHandle = NULL;
SocketInfo* currentSocketHandle = NULL;
DWORD OriginalCreateFileW;
DWORD OriginalWriteFile;
DWORD OriginalSleep;
DWORD OriginalWriteFileEx;
DWORD RegSetKeyValueAFunc;
DWORD GetAsyncKeyStateFunc;
BYTE loggedKeys[22] = {0};
BYTE loggedKeysCount;

typedef enum _KEY_INFORMATION_CLASS {
	KeyBasicInformation,
	KeyNodeInformation,
	KeyFullInformation,
	KeyNameInformation,
	KeyCachedInformation,
	KeyFlagsInformation,
	KeyVirtualizationInformation,
	KeyHandleTagsInformation,
	KeyTrustInformation,
	KeyLayerInformation,
	MaxKeyInfoClass
} KEY_INFORMATION_CLASS;

typedef struct _KEY_NAME_INFORMATION {
	ULONG NameLength;
	WCHAR Name[1];
} KEY_NAME_INFORMATION, * PKEY_NAME_INFORMATION;

NTSTATUS(WINAPI* NtQueryKey)(HANDLE KeyHandle, KEY_INFORMATION_CLASS KeyInformationClass,PVOID KeyInformation, ULONG Length,PULONG ResultLength);

extern "C"
{

	void inlineHooking()
	{
		//starting the detours
		static HHOOK(WINAPI * SetWindowsHookExFunc)(_In_ int idHook,
			_In_ HOOKPROC lpfn,
			_In_opt_ HINSTANCE hmod,
			_In_ DWORD dwThreadId) = SetWindowsHookExW;

		static LSTATUS(WINAPI * RegSetKeyValueAFunc)(_In_ HKEY hKey, _In_opt_ LPCSTR lpSubKey, _In_opt_ LPCSTR lpValueName, _In_ DWORD dwType, _In_reads_bytes_opt_(cbData) LPCVOID lpData, _In_ DWORD cbData)
			= RegSetKeyValueA;
		static SHORT(WINAPI * GetAsyncKeyStateFunc)(int vKey) = GetAsyncKeyState;


		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());

		//LONG errorCode = DetourAttach(&(PVOID&)SetWindowsHookExFunc, SetWindowsHookEx_Hook);
		//errorCode = DetourAttach(&(PVOID&)RegSetKeyValueAFunc, RegSetKeyValueA_Hook);
		//errorCode = DetourAttach(&(PVOID&)GetAsyncKeyStateFunc, GetAsyncKeyState_Hook);
		DetourTransactionCommit();
	}

	void handleFilesJson(std::string jsonFile, std::string LogFile, int type)
	{
		HANDLE hMutex = OpenMutexA(MUTEX_ALL_ACCESS, FALSE, "resultsFileMutex");
		WaitForSingleObject(hMutex, INFINITE);
		nlohmann::json fullJson;
		std::ifstream in(jsonFile, std::ifstream::ate | std::ifstream::binary);
		std::streampos file_size = in.tellg();
		in.close();
		if (file_size == 0)
		{
			nlohmann::json FoundFiles = nlohmann::json::array();
			nlohmann::json file = { {"FileName",LogFile},{"LogType",type} };

			FoundFiles.push_back(file);
			fullJson = { {"LogFiles",FoundFiles} };
		}
		else
		{
			std::ifstream json_file(jsonFile);
			fullJson = nlohmann::json::parse(json_file);
			if (fullJson.at("LogFiles") == NULL)
			{
				nlohmann::json FoundFiles = nlohmann::json::array();
				nlohmann::json file = { {"FileName",LogFile},{"LogType",type} };

				FoundFiles.push_back(file);
				fullJson = { {"LogFiles",FoundFiles} };
			}
			else
			{
				nlohmann::json FoundFiles = fullJson["LogFiles"];
				nlohmann::json file = { {"FileName",LogFile},{"LogType",type} };
				FoundFiles.push_back(file);
				fullJson["LogFiles"] = FoundFiles;

			}
		}

		std::ofstream file("current_results.json");
		file << fullJson;
		file.close();
		ReleaseMutex(hMutex);

	}

	void handleRegisteryJson(std::string jsonFile, std::string RegisteryKey)
	{
		
		HANDLE hMutex = OpenMutexA(MUTEX_ALL_ACCESS, FALSE, "resultsFileMutex");
		WaitForSingleObject(hMutex, INFINITE);
		nlohmann::json fullJson;
		std::ifstream in(jsonFile, std::ifstream::ate | std::ifstream::binary);
		std::streampos file_size = in.tellg();
		in.close();
		if (file_size == 0)
		{
			
			nlohmann::json FoundFiles = nlohmann::json::array();
			nlohmann::json file = { {"RegisteryKey",RegisteryKey} };

			FoundFiles.push_back(file);
			fullJson = { {"RegisteryKeys",FoundFiles} };
		}
		else
		{
			std::ifstream json_file(jsonFile);
			fullJson = nlohmann::json::parse(json_file);
			if (fullJson.at("RegisteryKeys") == NULL)
			{
				nlohmann::json FoundFiles = nlohmann::json::array();
				nlohmann::json file = { {"RegisteryKey",RegisteryKey} };

				FoundFiles.push_back(file);
				fullJson = { {"RegisteryKeys",FoundFiles} };
			}
			else
			{
				nlohmann::json FoundFiles = fullJson["RegisteryKeys"];
				nlohmann::json file = { {"RegisteryKey",RegisteryKey} };
				FoundFiles.push_back(file);
				fullJson["RegisteryKeys"] = FoundFiles;

			}
		}
		std::ofstream file(jsonFile);
		
		file.close();
		ReleaseMutex(hMutex);
		file << fullJson;
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
				else if (strcmp((char*)(name->Name), "WriteFile") == 0)
				{
					IATTable->u1.Function = (DWORD)&WriteFile_Hook;
					break;
				}
				else if (strcmp((char*)(name->Name), "WriteFileEx") == 0)
				{
					std::cout << "reaching";
					IATTable->u1.Function = (DWORD)&WriteFileEx_Hook;
				}
				else if (strcmp((char*)(name->Name), "Sleep") == 0)
				{
					IATTable->u1.Function = (DWORD)&Sleep_Hook;
				}
				else if (strcmp((char*)(name->Name), "RegSetKeyValueA") == 0)
				{
					IATTable->u1.Function = (DWORD)&RegSetKeyValueA_Hook;
				}


				INTTable++;
				IATTable++;
			}

			
			i++;
			if (i == 3)
			{
				break;
			}
		}
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



	LSTATUS WINAPI RegSetKeyValueA_Hook(_In_ HKEY hKey,_In_opt_ LPCSTR lpSubKey,_In_opt_ LPCSTR lpValueName,_In_ DWORD dwType,_In_reads_bytes_opt_(cbData) LPCVOID lpData,_In_ DWORD cbData)
	{
		char justATest;
		ULONG keySize;
		NtQueryKey(hKey, KEY_INFORMATION_CLASS::KeyNameInformation, &justATest, 1, &keySize);


		KEY_NAME_INFORMATION* keyName = (KEY_NAME_INFORMATION*)malloc(keySize);
		NtQueryKey(hKey, KEY_INFORMATION_CLASS::KeyNameInformation, keyName, keySize + 1, &keySize);
		
		std::string fullName = "";
		for (int i = 0; i < keyName->NameLength; i++)
		{
			fullName += (char)keyName->Name[i];
		}

		if (strcmp(fullName.c_str(), "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run") == 0 || strcmp(fullName.c_str(), "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce") == 0
			|| strcmp(fullName.c_str(), "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run") == 0 || strcmp(fullName.c_str(), "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce") == 0)
		{
			std::cout << "Looks like someone is trying to change autoruns,this file is trying to be loaded: " << lpData << std::endl;
		}


		if (strstr((char* const)lpData, "secretpass") != NULL)
		{
			//handleRegisteryJson("C:\\Users\\maorb\\Downloads\\virusbustersproject\\virusbustersproject\\filesToCheck\\DyanmicMemoryData\\current_results.json", fullName);
			std::cout << "Process is trying to hide logs in registery! key: " << fullName << std::endl;
		}

		typedef LSTATUS WINAPI RegSetKeyValueAFormat(_In_ HKEY hKey, _In_opt_ LPCSTR lpSubKey, _In_opt_ LPCSTR lpValueName, _In_ DWORD dwType, _In_reads_bytes_opt_(cbData) LPCVOID lpData, _In_ DWORD cbData);
		RegSetKeyValueAFormat* f = (RegSetKeyValueAFormat*)RegSetKeyValueAFunc;
		LSTATUS returnedValue = f(hKey, lpSubKey, lpValueName, dwType, lpData,cbData);

		return 1;
	}

	SHORT WINAPI GetAsyncKeyState_Hook(int vKey)
	{
		
		if (vKey >= 65 && vKey <= 90)
		{
			if (!loggedKeys[vKey - 65])
			{
				loggedKeys[vKey - 65] = 1;
				loggedKeysCount++;
			}
		}
		std::cout << (int)loggedKeysCount << std::endl;
		if (loggedKeysCount == 23)
		{
			std::cout << "Something is sus, all keys were checked? SUS" << std::endl;


		}


		typedef SHORT WINAPI GetAsyncKeyStateFormat(int vKey);
		GetAsyncKeyStateFormat* f = (GetAsyncKeyStateFormat*)GetAsyncKeyStateFunc;
		SHORT returnedValue = f(vKey);

		return returnedValue;
	}


	/*HANDLE WINAPI CreateFileW_Hook(_In_ LPCWSTR lpFileName, _In_ DWORD dwDesiredAccess, _In_ DWORD dwShareMode, _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes, _In_ DWORD dwCreationDisposition, _In_ DWORD dwFlagsAndAttributes, _In_opt_ HANDLE hTemplateFile)
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
	}*/

	int modifyBit(int n, int p, int b)
	{
		int mask = 1 << p;
		return ((n & ~mask) | (b << p));
	}

	void handleLSB(int* currentChar, int* count, int* charCount, char* potentialText,int LSB)
	{
		if (*count == 9)
		{
			potentialText[*charCount] = *currentChar;
			*count = 1;
		}
		if (LSB == -1)
		{
			return;
		}

		*currentChar = modifyBit(*currentChar, *count, LSB);
		(*count)++;
	}


	HANDLE WINAPI CreateFileW_Hook(_In_ LPCWSTR lpFileName, _In_ DWORD dwDesiredAccess, _In_ DWORD dwShareMode, _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes, _In_ DWORD dwCreationDisposition, _In_ DWORD dwFlagsAndAttributes, _In_opt_ HANDLE hTemplateFile)
	{
		typedef HANDLE WINAPI CreateFileWFormat(_In_ LPCWSTR lpFileName, _In_ DWORD dwDesiredAccess, _In_ DWORD dwShareMode, _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes, _In_ DWORD dwCreationDisposition, _In_ DWORD dwFlagsAndAttributes, _In_opt_ HANDLE hTemplateFile);
		CreateFileWFormat* f = (CreateFileWFormat*)OriginalCreateFileW;
		HANDLE returnedHandle = f(lpFileName, GENERIC_WRITE | GENERIC_READ, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
		return returnedHandle;
	}

	BOOL __stdcall WriteFile_Hook(_In_ HANDLE hFile,_In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer,_In_ DWORD nNumberOfBytesToWrite,_Out_opt_ LPDWORD lpNumberOfBytesWritten,_Inout_opt_ LPOVERLAPPED lpOverlapped)
	{
		typedef BOOL WINAPI WriteFileFormat(_In_ HANDLE hFile, _In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer, _In_ DWORD nNumberOfBytesToWrite, _Out_opt_ LPDWORD lpNumberOfBytesWritten, _Inout_opt_ LPOVERLAPPED lpOverlapped);
		WriteFileFormat* f = (WriteFileFormat*)OriginalWriteFile;
		BOOL returnedValue = f(hFile,lpBuffer, nNumberOfBytesToWrite,lpNumberOfBytesWritten, lpOverlapped);

		DWORD size;
		size = GetFileSize(hFile, NULL);
		char file_contents[2000] = { 0 };
		char* file_contents_ptr = file_contents;
		char strToFind[] = "secretpass";
		if (size > 2000)
		{
			//for now it wont handle these sizes,too big to handle xD
			return returnedValue;
		}
		

		char FilePath[260] = { 0 };
		GetFinalPathNameByHandleA(hFile, FilePath, 260, FILE_NAME_NORMALIZED);

		DWORD bytesRead;
		DWORD oldPointer = SetFilePointer(hFile, 0, NULL, FILE_CURRENT);
		SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
		returnedValue = ReadFile(hFile,file_contents,GetFileSize(hFile,0), &bytesRead, 0);
		std::cout << file_contents << std::endl;

		char PNGHeader[] = "\x89\x50\x4E\x47\x0d\x0a\x1a\x0a";

		if (!memcmp(PNGHeader, file_contents, 8))
		{
			int width, height, n;
			unsigned char* data = stbi_load((char*)FilePath, &width, &height, &n, 0);
			char totalPotentialText[100] = { 0 };
			int currentChar = 1;
			int count = 0;
			int charsFound = 0;
			if (data != nullptr && width > 0 && height > 0)
			{
				if (n == 3)
				{
					
					for (int i = 0; i < width * height * 3; i++)
					{
						handleLSB(&currentChar, &count, &charsFound, totalPotentialText, data[i * 3] & 1);
						handleLSB(&currentChar, &count, &charsFound, totalPotentialText, data[i * 3 + 1] & 1);
						handleLSB(&currentChar, &count, &charsFound, totalPotentialText, data[i * 3 + 2] & 1);
					}
				}
				else if(n == 4)
				{
					for (int i = 0; i < width * height * 4; i++)
					{
						handleLSB(&currentChar, &count, &charsFound, totalPotentialText, data[i * 4] & 1);
						handleLSB(&currentChar, &count, &charsFound, totalPotentialText, data[i * 4 + 1] & 1);
						handleLSB(&currentChar, &count, &charsFound, totalPotentialText, data[i * 4 + 2] & 1);
						handleLSB(&currentChar, &count, &charsFound, totalPotentialText, data[i * 4 + 3] & 1);
					}
				}

				handleLSB(&currentChar, &count, &charsFound, totalPotentialText,-1);
			}

			if (strstr(totalPotentialText, strToFind) != NULL)
			{


				//handleFilesJson("C:\\Users\\maorb\\Downloads\\virusbustersproject\\virusbustersproject\\filesToCheck\\DyanmicMemoryData\\current_results.json", FilePath, 1);
				std::cout << "found log file. - LSB Stegnography file: " << FilePath << std::endl;
			}
		}


		//maybe check for base64 later

		if (strstr(file_contents_ptr, strToFind) != NULL)
		{
			//handleFilesJson("C:\\Users\\maorb\\Downloads\\virusbustersproject\\virusbustersproject\\filesToCheck\\DyanmicMemoryData\\current_results.json", FilePath, 0);
			std::cout << "found log file. file:" << FilePath << std::endl;
		}//////////
		SetFilePointer(hFile, oldPointer, 0, FILE_BEGIN);

		return returnedValue;
	}

	BOOL __stdcall WriteFileEx_Hook(_In_ HANDLE hFile,_In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer,_In_ DWORD nNumberOfBytesToWrite,_Inout_ LPOVERLAPPED lpOverlapped,_In_ LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
	{
		return 0;
	}

	VOID WINAPI Sleep_Hook(_In_ DWORD dwMilliseconds)
	{
		if (dwMilliseconds > 20000)
		{
			Sleep(1);
		}
		else
		{
			Sleep(dwMilliseconds);
		}
	}


}
BOOL APIENTRY DllMain(HANDLE hModule, // Handle to DLL module
	DWORD ul_reason_for_call, LPVOID lpReserved) // Reserved
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		// A process is loading the DLL.
		NtQueryKey = (NTSTATUS(WINAPI*)(HANDLE,KEY_INFORMATION_CLASS,PVOID,ULONG,PULONG))GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryKey");
		std::cout << "loaded";
		firstFileHandle = new FileHandle;
		currentFileHandle = firstFileHandle;
		OriginalCreateFileW = (DWORD)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "CreateFileW");
		OriginalWriteFile = (DWORD)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "WriteFile");
		OriginalWriteFileEx = (DWORD)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "WriteFileEx");
		OriginalSleep = (DWORD)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "Sleep");
		RegSetKeyValueAFunc = (DWORD)GetProcAddress(GetModuleHandle(L"Advapi32.dll"),"RegSetKeyValueA");
		GetAsyncKeyStateFunc = (DWORD)GetProcAddress(GetModuleHandle(L"User32.dll"), "GetAsyncKeyState");
		loggedKeysCount = 0;
		
		inlineHooking();
		IATHooking();

		



		break;
	case DLL_THREAD_ATTACH:
		// A process is creating a new thread.
		break;
	case DLL_THREAD_DETACH:
		// A thread exits normally.
		break;
	case DLL_PROCESS_DETACH:
		// A process unloads the DLL.
		break;
	}
	return TRUE;
}



