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
bool ReadMemory(HANDLE hProcess, LPCVOID address, void* buffer, SIZE_T size) {
    SIZE_T bytesRead;
    return ReadProcessMemory(hProcess, address, buffer, size, &bytesRead) && bytesRead == size;
}

// Fonction pour écrire dans la mémoire d'un processus
bool WriteMemory(HANDLE hProcess, LPVOID address, const void* buffer, SIZE_T size) {
    SIZE_T bytesWritten;
    return WriteProcessMemory(hProcess, address, buffer, size, &bytesWritten) && bytesWritten == size;
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


    uintptr_t dynamicPtrBaseAddr = moduleBase + 0x0017e0a8;
    uintptr_t pointedAddress = 0;
    if (!ReadMemory(hProcess, (LPCVOID)dynamicPtrBaseAddr, &pointedAddress, sizeof(pointedAddress))) {
        OutputDebugStringA("failed to read pointed address!"); // Corrected function name
        CloseHandle(hProcess);
    }

    uintptr_t ammoAddr = pointedAddress + 0x140;
    int newValue = 10000;
    if (WriteMemory(hProcess, (LPVOID)ammoAddr, &newValue, sizeof(newValue))) { 
        OutputDebugStringA("value modified successfully!");
    }
    else {
        OutputDebugStringA("failed to modify value!"); 
    }

    CloseHandle(hProcess);
}
