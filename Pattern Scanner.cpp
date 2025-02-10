#include <iostream>
#include <Windows.h>
#include <vector>
#include <TlHelp32.h>

uintptr_t GetModuleBaseAddress(DWORD procId, const wchar_t* modName)
{
    uintptr_t modBaseAddr = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32 modEntry;
        modEntry.dwSize = sizeof(modEntry);
        if (Module32First(hSnap, &modEntry))
        {
            do
            {
                if (!_wcsicmp(modEntry.szModule, modName))
                {
                    modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
                    break;
                }
            } while (Module32Next(hSnap, &modEntry));
        }
    }
    CloseHandle(hSnap);
    return modBaseAddr;
}

int findMyProc(const wchar_t* procname) {
    HANDLE hSnapshot;
    PROCESSENTRY32W pe;
    int pid = 0;
    BOOL hResult;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot) {
        std::cerr << "[Erreur] Impossible de créer un snapshot des processus !" << std::endl;
        return 0;
    }

    pe.dwSize = sizeof(PROCESSENTRY32W);
    hResult = Process32FirstW(hSnapshot, &pe);

    while (hResult) {
        if (wcscmp(procname, pe.szExeFile) == 0) {
            pid = pe.th32ProcessID;
            break;
        }
        hResult = Process32NextW(hSnapshot, &pe);
    }

    CloseHandle(hSnapshot);
    if (pid == 0) {
        std::cerr << "[Erreur] Processus non trouvé : " << procname << std::endl;
    }
    else {
        std::cout << "[Info] Processus trouvé : avec PID = " << pid << std::endl;
    }
    return pid;
}

int main() {
    DWORD pid = findMyProc(L"ac_client.exe");
	

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        std::cerr << "Impossible d'ouvrir le processus!" << std::endl;
        return 1;
    }
    uintptr_t moduleBase = GetModuleBaseAddress(pid, L"ac_client.exe");
    if (moduleBase == 0) {
        std::cerr << "Impossible de trouver l'adresse de base du module!" << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    std::cout << "Adresse de base du module = 0x" << std::hex << moduleBase << std::endl;

    unsigned char *buffer = (unsigned char*)calloc(1, MODULEENTRY32.modBaseSize);
    DWORD bytes_read = 0;

    ReadProcessMemory(hProcess, (void*)moduleBase, buffer, MODULEENTRY32.modBaseSize, &bytes_read);

    unsigned char bytes[] = { 0x29, 0x42, 0x04 };

    for (unsigned int i = 0; i < MODULEENTRY32.modBaseSize - sizeof(bytes); i++) {
      for (int j = 0; j < sizeof(bytes); j++) {
        if (bytes[j] != buffer[i + j]) {
          break;
        }

       if (j + 1 == sizeof(bytes)) {
          printf("%x\n", i + (DWORD)MODULEENTRY32.modBaseAddr);
         }
       }
     }


    free(buffer);


    CloseHandle(hProcess);
}
