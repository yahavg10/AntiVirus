#include <stdio.h>
#include <conio.h>

#include <iostream>
#include <Packet32.h>
#include <ntddndis.h>
#include <string>
#include <algorithm>
#include <nlohmann/json.hpp>
#include <fstream>

#define Max_Num_Adapter 10

#include <tchar.h>
BOOL LoadNpcapDlls()
{
	TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, TEXT("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}
	return TRUE;
}
// Prototypes

void PrintPackets(LPPACKET lpPacket);

char        AdapterList[Max_Num_Adapter][1024];

int main()
{
	//define a pointer to an ADAPTER structure

	LPADAPTER  lpAdapter = 0;

	//define a pointer to a PACKET structure

	LPPACKET   lpPacket;

	int        i;
	DWORD      dwErrorCode;

	//ascii strings
	char		AdapterName[8192]; // string that contains a list of the network adapters
	char* temp, * temp1;


	int			AdapterNum = 0, Open;
	ULONG		AdapterLength;

	char buffer[256000];  // buffer to hold the data coming from the driver

	struct bpf_stat stat;

	/* Load Npcap and its functions. */
	//if (!LoadNpcapDlls())
	//{
	//	fprintf(stderr, "Couldn't load Npcap\n");
	//	exit(1);
	//}

	//
	// Obtain the name of the adapters installed on this machine
	//
	printf("Packet.dll test application. Library version:%s\n", PacketGetVersion());

	printf("Adapters installed:\n");
	i = 0;




	AdapterLength = sizeof(AdapterName);

	if (PacketGetAdapterNames(AdapterName, &AdapterLength) == FALSE) {
		printf("Unable to retrieve the list of the adapters!\n");
		return -1;
	}
	temp = AdapterName;
	temp1 = AdapterName;

	while ((*temp != '\0') || (*(temp - 1) != '\0'))
	{
		if (*temp == '\0')
		{
			memcpy(AdapterList[i], temp1, temp - temp1);
			temp1 = temp + 1;
			i++;
		}
		temp++;
	}

	AdapterNum = i;
	for (i = 0; i < AdapterNum; i++)
		printf("\n%d- %s\n", i + 1, AdapterList[i]);
	printf("\n");




	//7
	lpAdapter = PacketOpenAdapter(AdapterList[0]);

	if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE))
	{
		dwErrorCode = GetLastError();
		printf("Unable to open the adapter, Error Code : %lx\n", dwErrorCode);

		return -1;
	}

	// set the network adapter in promiscuous mode

	if (PacketSetHwFilter(lpAdapter, NDIS_PACKET_TYPE_PROMISCUOUS) == FALSE) {
		printf("Warning: unable to set promiscuous mode!\n");
	}

	// set a 512K buffer in the driver
	if (PacketSetBuff(lpAdapter, 512000) == FALSE) {
		printf("Unable to set the kernel buffer!\n");
		return -1;
	}

	// set a 1 second read timeout
	if (PacketSetReadTimeout(lpAdapter, 1000) == FALSE) {
		printf("Warning: unable to set the read tiemout!\n");
	}

	//allocate and initialize a packet structure that will be used to
	//receive the packets.
	if ((lpPacket = PacketAllocatePacket()) == NULL) {
		printf("\nError: failed to allocate the LPPACKET structure.");
		return (-1);
	}
	PacketInitPacket(lpPacket, (char*)buffer, 256000);

	//main capture loop
	while (!_kbhit())
	{
		// capture the packets
		if (PacketReceivePacket(lpAdapter, lpPacket, TRUE) == FALSE) {
			printf("Error: PacketReceivePacket failed");
			return (-1);
		}

		PrintPackets(lpPacket);
	}


	//print the capture statistics
	if (PacketGetStats(lpAdapter, &stat) == FALSE) {
		printf("Warning: unable to get stats from the kernel!\n");
	}
	else
		printf("\n\n%d packets received.\n%d Packets lost", stat.bs_recv, stat.bs_drop);

	PacketFreePacket(lpPacket);

	// close the adapter and exit

	PacketCloseAdapter(lpAdapter);
	return (0);
}

// this function prints the content of a block of packets received from the driver


int handleIp(char* startOfIp,std::string& DstIp)
{
	int version = *(startOfIp) >> 4;
	unsigned char srcIPNormalForm[4] = { 0 };
	for (int i = 0; i < 4; i++)
	{
		srcIPNormalForm[i] = *(startOfIp + 12 + i);
	}
	std::string srcIPUserForm = std::to_string((int)srcIPNormalForm[0]) + "." + std::to_string((int)srcIPNormalForm[1]) + "." + std::to_string((int)srcIPNormalForm[2]) + "." + std::to_string((int)srcIPNormalForm[3]);

	unsigned char dstIPNormalForm[4] = { 0 };

	for (int i = 0; i < 4; i++)
	{
		dstIPNormalForm[i] = *(startOfIp + 16 + i);
	}
	DstIp = std::to_string((int)dstIPNormalForm[0]) +  "." + std::to_string((int)dstIPNormalForm[1]) + "." + std::to_string((int)dstIPNormalForm[2]) + "." + std::to_string((int)dstIPNormalForm[3]);

	return (int)(unsigned char)*(startOfIp + 8);
}




void handlePorts(char* startOfPort,int& DstPort)
{
	unsigned char srcPortNormalForm[2] = { 0 };
	for (int i = 0; i < 2; i++)
	{
		srcPortNormalForm[i] = *(startOfPort + i);
	}
	int srcPort = (int)srcPortNormalForm[0] << 8 | (int)srcPortNormalForm[1];
	
	std::string srcPortUserForm = std::to_string(srcPort);

	unsigned char dstPortNormalForm[2] = { 0 };

	for (int i = 0; i < 2; i++)
	{
		dstPortNormalForm[i] = *(startOfPort + 2 + i);
	}
	DstPort = (int)dstPortNormalForm[0] << 8 | (int)dstPortNormalForm[1];
	std::string dstPortUserForm = std::to_string(DstPort);
}

void* memmem(const void* haystack_start, size_t haystack_len, const void* needle_start, size_t needle_len)
{

	const unsigned char* haystack = (const unsigned char*)haystack_start;
	const unsigned char* needle = (const unsigned char*)needle_start;
	const unsigned char* h = NULL;
	const unsigned char* n = NULL;
	size_t x = needle_len;

	/* The first occurrence of the empty string is deemed to occur at
	the beginning of the string.  */
	if (needle_len == 0)
		return (void*)haystack_start;

	/* Sanity check, otherwise the loop might search through the whole
		memory.  */
	if (haystack_len < needle_len)
		return NULL;

	for (; *haystack && haystack_len--; haystack++) {

		x = needle_len;
		n = needle;
		h = haystack;

		if (haystack_len < needle_len)
			break;

		if ((*haystack != *needle) || (*haystack + needle_len != *needle + needle_len))
			continue;

		for (; x; h++, n++) {
			x--;

			if (*h != *n)
				break;

			if (x == 0)
				return (void*)haystack;
		}
	}

	return NULL;
}

void handleNetworksJson(std::string jsonFile, std::string dstIp, int dstPort, int type)
{
	HANDLE hMutex = OpenMutexA(MUTEX_ALL_ACCESS, FALSE, "resultsFileMutex");
	WaitForSingleObject(hMutex, INFINITE);
	nlohmann::json fullJson;
	std::ifstream in(jsonFile, std::ifstream::ate | std::ifstream::binary);
	std::streampos file_size = in.tellg();
	in.close();
	if (file_size == 0)
	{
		nlohmann::json FoundIPS = nlohmann::json::array();
		nlohmann::json ip = { {"dstIp",dstIp},{"dstPort",dstPort},{"type",type} };

		FoundIPS.push_back(ip);
		fullJson = { {"Suspicous_IPS",FoundIPS} };
	}
	else
	{
		std::ifstream json_file(jsonFile);
		fullJson = nlohmann::json::parse(json_file);
		if (fullJson.at("RegisteryKeys") == NULL)
		{
			nlohmann::json FoundIPS = nlohmann::json::array();
			nlohmann::json ip = { {"dstIp",dstIp},{"dstPort",dstPort},{"type",type} };

			FoundIPS.push_back(ip);
			fullJson = { {"Suspicous_IPS",FoundIPS} };
		}
		else
		{
			nlohmann::json FoundIPS = fullJson["Suspicous_IPS"];
			nlohmann::json ip = { {"dstIp",dstIp},{"dstPort",dstPort},{"type",type} };
			FoundIPS.push_back(ip);
			fullJson["FoundIPS"] = FoundIPS;

		}
	}

	std::ofstream file("current_results.json");
	file << fullJson;
	file.close();
	ReleaseMutex(hMutex);
}


void PrintPackets(LPPACKET lpPacket)
{
	ULONG	i, j, ulLines, ulen, ulBytesReceived;
	char* pChar, * pLine, * base;
	char* buf;
	u_int off = 0;
	u_int tlen, tlen1;
	struct bpf_hdr* hdr;

	ulBytesReceived = lpPacket->ulBytesReceived;


	buf = (char*)lpPacket->Buffer;

	off = 0;

	while (off < ulBytesReceived) {
		if (_kbhit())return;
		hdr = (struct bpf_hdr*)(buf + off);
		tlen1 = hdr->bh_datalen;
		tlen = hdr->bh_caplen;
		off += hdr->bh_hdrlen;
		ulLines = (tlen + 15) / 16;
		pChar = (char*)(buf + off);
		base = pChar;
		off = Packet_WORDALIGN(off + tlen);

		std::string DstIp;
		int protocol = handleIp(pChar + 14, DstIp);
		unsigned char word_to_find[10] = { 's','e','c','r','e','t','p','a','s','s' };


		int ipSize = *(pChar + 14) << 4;

		int DstPort;
		handlePorts(pChar + 14 + ipSize / 2, DstPort);


		for (DWORD i = 0; i < tlen1; i++)
		{
			// ignore if the current value is null
			if (*pChar == 0x00)
			{
				pChar++;
				continue;
			}
			if (memcmp(pChar, word_to_find, 10) == 0)
			{
				if (protocol == 1)
				{
					//handleNetworksJson("C:\\Users\\maorb\\Downloads\\virusbustersproject\\virusbustersproject\\filesToCheck\\DyanmicMemoryData\\current_results.json", DstIp, DstPort, 1);
					std::cout << "Looks like an ICMP Tunneling" << std::endl;
					system("pause");
				}
				else
				{
					//handleNetworksJson("C:\\Users\\maorb\\Downloads\\virusbustersproject\\virusbustersproject\\filesToCheck\\DyanmicMemoryData\\current_results.json", DstIp, DstPort, 0);
					std::cout << "Looks like keylogger sends data on the network.";
					system("pause");
				}
			}
			pChar++;
		}

		for (i = 0; i < ulLines; i++)
		{

			pLine = pChar;

			printf("%p : ", (void*)(pChar - base));

			ulen = tlen;
			ulen = (ulen > 16) ? 16 : ulen;
			tlen -= ulen;

			for (j = 0; j < ulen; j++)
				printf("%02x ", *(BYTE*)pChar++);

			if (ulen < 16)
				printf("%*s", (16 - ulen) * 3, " ");

			pChar = pLine;

			for (j = 0; j < ulen; j++, pChar++)
				printf("%c", isprint((unsigned char)*pChar) ? *pChar : '.');

			printf("\n");
		}

		printf("\n");

	}
}


