#pragma once
#include <stdio.h>
#include <windows.h>
#include <iostream>
#include <string>

#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#define SystemProcessInformation 5
#define ThreadBasicInformation 0

// max stack size - 1mb
#define MAX_STACK_SIZE ((1024 * 1024) / sizeof(DWORD))

// max stack string value size - 1kb
#define MAX_STACK_VALUE_SIZE 1024


struct CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
};

struct THREAD_BASIC_INFORMATION
{
	DWORD ExitStatus;
	PVOID TebBaseAddress;
	CLIENT_ID ClientId;
	PVOID AffinityMask;
	DWORD Priority;
	DWORD BasePriority;
};

struct UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
};

struct OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	UNICODE_STRING* ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
};

struct SYSTEM_PROCESS_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	BYTE Reserved1[48];
	UNICODE_STRING ImageName;
	DWORD BasePriority;
	HANDLE UniqueProcessId;
	PVOID Reserved2;
	ULONG HandleCount;
	ULONG SessionId;
	PVOID Reserved3;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG Reserved4;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	PVOID Reserved5;
	SIZE_T QuotaPagedPoolUsage;
	PVOID Reserved6;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved7[6];
};

struct SYSTEM_THREAD_INFORMATION
{
	LARGE_INTEGER Reserved1[3];
	ULONG Reserved2;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	DWORD Priority;
	LONG BasePriority;
	ULONG Reserved3;
	ULONG ThreadState;
	ULONG WaitReason;
};