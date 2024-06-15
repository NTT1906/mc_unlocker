#include <windows.h>
#include <tlHelp32.h>
#include <psapi.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#define UNLOCK_AOB "0F B6 81 ? ? ? ? C3 CC CC CC CC CC CC CC CC 48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 41 8B D8 48 8B FA 4C 8B C2" // Array of bytes - Hex pattern
#define MINECRAFT_MODULE_BASENAME "Minecraft.Windows.exe"

// #define ANCHOR_ADDRESS_OFFSET 	0xFF8BA0 				//1.20.60
#define ANCHOR_ADDRESS_OFFSET       0xFD1B77                //1.21.0
#define NO_TRIAL_DEFAULT            14091921563716681912    //1.20.60

DWORD GetProcessIDFromName(const char *processName) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot) return 0;

	PROCESSENTRY32 pe = {.dwSize = sizeof(PROCESSENTRY32)};

	BOOL hResult = Process32First(hSnapshot, &pe);
	DWORD pid = 0;
	while (hResult) {
		if (strcmp(processName, pe.szExeFile) == 0) {
			pid = pe.th32ProcessID;
			break;
		}
		hResult = Process32Next(hSnapshot, &pe);
	}

	CloseHandle(hSnapshot);
	return pid;
}

// Source: https://github.com/PierreCiholas/GetBaseAddress
uint64_t GetBaseAddress(const HANDLE process) {
	if (process == NULL) {
		return 0; // No access to the process
	}
	HMODULE lphModule[1024];
	DWORD lpcbNeeded = 0;

	if (!EnumProcessModules(process, lphModule, sizeof(lphModule), &lpcbNeeded)) {
		printf("ERROR: EnumProcessModules failed: %lu\n", GetLastError());
		return 0; // Impossible to read modules
	}

	TCHAR szModName[MAX_PATH];
	if (!GetModuleFileNameEx(process, lphModule[0], szModName, sizeof(szModName) / sizeof(TCHAR))) {
		printf("ERROR: GetModuleInformation failed: %lu\n", GetLastError());
		return 0; // Impossible to get module info
	}

	return (uint64_t) lphModule[0]; // Module 0 is apparently always the EXE itself, returning its address
}

#define IN_RANGE(x, a, b) (x >= a && x <= b)
#define GET_BITS(x) (IN_RANGE((x & (~0x20)), 'A', 'F') ? ((x & (~0x20)) - 'A' + 0xa) : (IN_RANGE(x, '0', '9') ? x - '0' : 0))
#define GET_BYTE(x) (GET_BITS(x[0]) << 4 | GET_BITS(x[1]))

uint64_t FindSignature(HANDLE *process, const char *szSignature, const uint64_t offset) {
	const char *pattern = szSignature;
	uint64_t firstMatch = 0;
	uint64_t rangeStart = GetBaseAddress(process);
	if (rangeStart == 0) {
		printf("ERROR: %lu\n", GetLastError());
		return 0;
	}
	MODULEINFO miModInfo;
	GetModuleInformation(process, (HMODULE) rangeStart, &miModInfo, sizeof(MODULEINFO));

	const uint64_t rangeEnd = rangeStart + miModInfo.SizeOfImage;
	printf("Anchor Address Offset: %d\n", ANCHOR_ADDRESS_OFFSET);
	printf("Base Address: %lld - 0x%llx\n", rangeStart, rangeStart);
	rangeStart += offset;
	printf("Range Start : %lld - 0x%llx\nRange End   : %lld - 0x%llx\n", rangeStart, rangeStart, rangeEnd, rangeEnd);
	BYTE patByte = GET_BYTE(pattern);
	const char *oldPat = pattern;
	printf("Range: %lu\n", miModInfo.SizeOfImage);

	uint64_t ramPat;
	SIZE_T bytesRead;
	const int byte = 1;

	while (rangeStart < rangeEnd) {
		if (!*pattern) {
			return firstMatch;
		}

		while (*pattern == ' ') {// Skip space
			pattern++;
		}

		if (!*pattern) {
			return firstMatch;
		}

		if (oldPat != pattern) {
			oldPat = pattern;
			if (*pattern != '?') {
				patByte = GET_BYTE(pattern);
			}
		}

		if (!ReadProcessMemory(process, (void*) rangeStart, &ramPat, sizeof(ramPat), &bytesRead)) {
			DWORD errorN = 0;
			if (GetExitCodeProcess(process, &errorN)) {
				if (errorN != STILL_ACTIVE) {
					printf("Status: DED\n");
					return 0;
				}
			}
			printf("Status: IDK\n");
			return 0;
		}
		if (*pattern == '?' || (BYTE) ramPat == patByte) {
			if (!firstMatch)
				firstMatch = rangeStart;

			if (!pattern[2] || !pattern[1]) {
				return firstMatch;
			}
			pattern += 2;
		} else {
			pattern = szSignature;
			firstMatch = 0;
		}
		rangeStart += byte;
		printf("SEARCHING   : %lld - 0x%llx\r", rangeStart, rangeStart);
	}
	return 0;
}

bool patch(DWORD pid) {
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	uint64_t address = FindSignature(process, UNLOCK_AOB, ANCHOR_ADDRESS_OFFSET - 8);
	if (address == 0) {
		printf("Failed to search with anchor, brute-forcing the search...\n");
		address = FindSignature(process, UNLOCK_AOB, 0);
	}
	size_t bytesWritten;
	const uint64_t noTrial = NO_TRIAL_DEFAULT;
	if (address != 0) {
		printf("Succeed to find the address (%lld). ", address);
		if (WriteProcessMemory(process, (void*) address, &noTrial, sizeof(noTrial), &bytesWritten)) {
			printf("Injection: Succeed!\n");
		} else {
			printf("Injection: Failed!\n");
		}
	} else {
		printf("Failed to find the address!\n");
		CloseHandle(process);
		return false;
	}
	CloseHandle(process);
	return true;
}

void GetAllProcessIDFromName(char *processName, DWORD *pid, size_t *size) {
	DWORD aProcesses[1024], cbNeeded;
	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
		pid = NULL;
		*size = 0;
		return;
	}
	size_t pSize = cbNeeded / sizeof(DWORD);
	char szProcessName[1024];
	*size = 0;
	HMODULE hMod = NULL;
	for (size_t i = 0; i < pSize; i++) {
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,false, aProcesses[i]);
		if (hProcess != NULL) {
			if (EnumProcessModules(hProcess, &hMod, sizeof(HMODULE),&cbNeeded)) {
				GetModuleBaseName(hProcess, hMod, szProcessName,sizeof(szProcessName));
				if (strcmp(processName, szProcessName) == 0) {
					pid[(*size)++] = aProcesses[i];
				}
			}
			CloseHandle(hProcess);
		}
	}
}

struct Version{
	uint16_t ms_f;
	uint16_t ms_l;
	uint16_t ls_f;
	uint16_t ls_l;
};

bool getFileVersion(const char *fileName, struct Version *ver) {
	if (ver == NULL) {
		printf("Input version struct is NULL.\n");
		return false;
	}
	DWORD handle = 0;
	DWORD size = GetFileVersionInfoSize(fileName, &handle);
	if (size == 0) {
		printf("Failed to get version size. Error: %lu\n", GetLastError());
		return false;
	}

	void *versionInfo = malloc(size);
	if (!GetFileVersionInfo(fileName, handle, size, versionInfo)) {
		printf("Failed to get version info. Error: %lu\n", GetLastError());
		free(versionInfo);
		return false;
	}

	VS_FIXEDFILEINFO *fileInfo;
	UINT fileInfoSize;
	if (!VerQueryValue(versionInfo, "\\", (void**)&fileInfo, &fileInfoSize)) { //(void**)&fileInfo wtf
		printf("Failed to query version info. Error: %lu\n", GetLastError());
		free(versionInfo);
		return false;
	}

	ver->ms_f = (fileInfo->dwFileVersionMS >> 16) & 0xffff;
	ver->ms_l = (fileInfo->dwFileVersionMS >> 0) & 0xffff;
	ver->ls_f = (fileInfo->dwFileVersionLS >> 16) & 0xffff;
	ver->ls_l = (fileInfo->dwFileVersionLS >> 0) & 0xffff;
	free(versionInfo);
	return true;
}

int vercmp(struct Version *first, struct Version *second) {
	if (first == NULL || second == NULL) {
		return 0;
	}
	if (first->ms_f > second->ms_f) {
		return 1;
	}
	if (first->ms_f < second->ms_f) {
		return -1;
	}
	if (first->ms_l > second->ms_l) {
		return 1;
	}
	if (first->ms_l < second->ms_l) {
		return -1;
	}
	if (first->ls_f > second->ls_f) {
		return 1;
	}
	if (first->ls_f < second->ls_f) {
		return -1;
	}
	if (first->ls_l > second->ls_l) {
		return 1;
	}
	if (first->ls_l < second->ls_l) {
		return -1;
	}
	return 0;
}

int ver2str(struct Version *ver, char *str) {
	if (ver == NULL) {
		return -1;
	}
	sprintf(str, "%d.%d.%d.%d", ver->ms_f, ver->ms_l, ver->ls_f, ver->ls_l);
	return 0;
}

void str2ver(char *str, struct Version *ver) {
	if (ver == NULL) {
		return;
	}
	char *tok = strtok(str, (const char *) '.');
	ver->ms_f = tok == NULL ? strtol(tok, NULL, 10) : 0;
	ver->ms_l = tok == NULL ? strtol(tok, NULL, 10) : 0;
	ver->ls_f = tok == NULL ? strtol(tok, NULL, 10) : 0;
	ver->ls_l = tok == NULL ? strtol(tok, NULL, 10) : 0;
}

int main(int argc, char** argv) {
//	struct Version v;
//	getFileVersion("C:\\Program Files\\WindowsApps\\Microsoft.MinecraftUWP_1.21.3.0_x64__8wekyb3d8bbwe\\Minecraft.Windows.exe", &v);
//	char vStr[15];
//	ver2str(&v, vStr);
//	printf("Version: %s\n", vStr);
	if (argc == 1) {
		DWORD pid = GetProcessIDFromName(MINECRAFT_MODULE_BASENAME);
		if (pid == 0) {
			printf("Minecraft not found! Launching Minecraft...\n");
			system("start minecraft://");
			pid = GetProcessIDFromName(MINECRAFT_MODULE_BASENAME);
		}
		patch(pid);
		system("pause");
		return 0;
	}
	if (strcmp(argv[1], "-m") == 0) {
		DWORD pid[20];
		size_t size;
		GetAllProcessIDFromName(MINECRAFT_MODULE_BASENAME, pid, &size);
		for (int i = 0; i < size; i++) {
			printf("Patching Minecraft... PID: %lu\n", pid[i]);
			patch(pid[i]);
			printf("\n");
		}
	} else if (strcmp(argv[1], "-p") == 0) {
		if (argc < 3) {
			printf("No PID was input! Cancelling...\n");
			return 0;
		}
		DWORD pid = strtol(argv[2], NULL, 10);
		char processName[1024];
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,false, pid);
		HMODULE hMod = NULL;
		GetModuleBaseName(hProcess, hMod, processName,sizeof(processName));
		if (strcmp(processName, MINECRAFT_MODULE_BASENAME) != 0) {
			printf("The input PID (%lu) is not a minecraft instance!\n", pid);
			return 0;
		}
		printf("Patching Minecraft... PID: %lu\n", pid);
		patch(pid);
	}
	system("pause");
	return 0;
}
