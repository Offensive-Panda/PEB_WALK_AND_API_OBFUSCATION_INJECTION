# PEB_WALK_AND_API_OBFUSCATION_INJECTION
This exploit use PEB walk technique to resolve API calls dynamically and obfuscate all API calls to perform process injection. These technqies will help to bypass static analysis of AV/EDR solutions.

## PEB walk
To outline the process, the PEB walk for resolving the addresses of LoadLibraryA and GetProcAddress is as follows:

* Obtain and access the PEB structure of the current process.
* Navigate to the PEB_LDR_DATA structure using the Ldr member of the PEB.
* Iterate through the InLoadOrderModuleList to locate the LDR_DATA_TABLE_ENTRY for kernel32.dll.
* Once the entry for kernel32.dll is found, extract its base address.
* Manually parse the export table of kernel32.dll to resolve the addresses of LoadLibraryA and GetProcAddress.

## Injection

1) Get the handle of process using OpenProcess.
2) Allocate RWX memory region in remote process using VirtuaAllocEX
3) Write shellcode into allocated region using WriteProcessMemory
4) Create a thread to execute shellcode using CreateRemoteThread.

# Only for eductional Purposes
