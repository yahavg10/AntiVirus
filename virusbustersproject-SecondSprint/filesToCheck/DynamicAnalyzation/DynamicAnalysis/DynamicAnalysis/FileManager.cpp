#include <Windows.h>
#include <iostream>

//undocumented structs,had to find them online.

#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

typedef NTSTATUS NTAPI _NtQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );



typedef NTSTATUS NTAPI _NtDuplicateObject(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG Attributes,
    ULONG Options
    );
typedef NTSTATUS NTAPI _NtQueryObject(
    HANDLE ObjectHandle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
    );



typedef enum _POOL_TYPE
{
    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS
} POOL_TYPE, * PPOOL_TYPE;

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING Name;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccess;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    USHORT MaintainTypeList;
    POOL_TYPE PoolType;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;


typedef struct _SYSTEM_HANDLE
{
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;


PVOID GetLibraryProcAddress(const char* LibraryName,const char* ProcName)
{
    return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}



//void main()
//{
//	//this process follows a process files by following its handle table
//    _NtQuerySystemInformation* NtQuerySystemInformation = (_NtQuerySystemInformation*)(PVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"),"NtQuerySystemInformation");
//    _NtDuplicateObject* NtDuplicateObject = (_NtDuplicateObject*)GetLibraryProcAddress("ntdll.dll", "NtDuplicateObject");
//    _NtQueryObject* NtQueryObject = (_NtQueryObject*)GetLibraryProcAddress("ntdll.dll", "NtQueryObject");
//    NTSTATUS status;
//    PSYSTEM_HANDLE_INFORMATION handleInfo;
//    ULONG handleInfoSize = 0x10000;
//    ULONG pid;
//    HANDLE processHandle;
//    ULONG i;
//
//    handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
//
//    /* NtQuerySystemInformation won't give us the correct buffer size,
//       so we guess by doubling the buffer size. */
//    while ((status = NtQuerySystemInformation(
//        SystemHandleInformation,
//        handleInfo,
//        handleInfoSize,
//        NULL
//    )) == STATUS_INFO_LENGTH_MISMATCH)
//        handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);
//    HANDLE desiredProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, 15424);
//    for (int i = 0; i < handleInfo->HandleCount; i++)
//    {
//        if (handleInfo->Handles[i].ProcessId != 15424)
//        {
//            continue;
//        }
//
//        handleInfo->Handles[i].Handle;
//        HANDLE newHandle;
//        NtDuplicateObject(desiredProcess, (HANDLE)(handleInfo->Handles[i].Handle), GetCurrentProcess(), &newHandle, 0, 0, 0);
//        POBJECT_TYPE_INFORMATION objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
//        ULONG returnLength;
//        NtQueryObject(newHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, &returnLength);
//        if (wcscmp(objectTypeInfo->Name.Buffer, L"File") == 0)
//        {
//            std::cout << "hi";
//        }
//        std::cout << objectTypeInfo->Name.Buffer;
//        free(objectTypeInfo);
//    }
//
//}


