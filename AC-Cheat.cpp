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

bool ReadMemory(HANDLE hProcess, LPCVOID address, void* buffer, SIZE_T size) {
    SIZE_T bytesRead;
    return ReadProcessMemory(hProcess, address, buffer, size, &bytesRead) && bytesRead == size;
}

// Fonction pour écrire dans la mémoire d'un processus
bool WriteMemory(HANDLE hProcess, LPVOID address, const void* buffer, SIZE_T size) {
    SIZE_T bytesWritten;
    return WriteProcessMemory(hProcess, address, buffer, size, &bytesWritten) && bytesWritten == size;
}

// Fonction pour résoudre les adresses des pointeurs DMA
uintptr_t FindDMAAddy(HANDLE hProc, uintptr_t ptr, std::vector<unsigned int> offsets) {
    uintptr_t addr = ptr;
    for (unsigned int i = 0; i < offsets.size(); ++i) {
        if (!ReadMemory(hProc, (BYTE*)addr, &addr, sizeof(addr))) {
            std::cerr << "Erreur lors de la lecture de la mémoire!" << std::endl;
            return 0;
        }
        addr += offsets[i];
    }
    return addr;
}

int main() {
    DWORD pid;
    std::cout << "Entrez le PID du processus: ";
    std::cin >> pid;  // Demander à l'utilisateur d'entrer le PID du processus

    // Ouvrir le processus
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        std::cerr << "Impossible d'ouvrir le processus!" << std::endl;
        return 1;
    }

    // Résoudre l'adresse de base du module (par exemple "ac_client.exe")
    uintptr_t moduleBase = GetModuleBaseAddress(pid, L"ac_client.exe");
    if (moduleBase == 0) {
        std::cerr << "Impossible de trouver l'adresse de base du module!" << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    std::cout << "Adresse de base du module = 0x" << std::hex << moduleBase << std::endl;

    // Adresse de base du pointeur dynamique (exemple avec 0x10f4f4)
    uintptr_t dynamicPtrBaseAddr = moduleBase + 0x0017E0A8;
    std::cout << "Dynamic Addr = 0x" << std::hex << dynamicPtrBaseAddr << std::endl;

    // Lecture de l'adresse contenue à cette adresse
    uintptr_t pointedAddress = 0;
    uintptr_t newPointedAddress = 0;
    if (ReadMemory(hProcess, (LPCVOID)dynamicPtrBaseAddr, &pointedAddress, sizeof(pointedAddress))) {
        // Affichage de la valeur de pointedAddress avant la modification
        std::cout << "Adresse pointée par dynamicPtrBaseAddr avant la réduction à 32 bits : 0x"
            << std::hex << pointedAddress << std::endl;

        // Appliquer le masque pour réduire pointedAddress à 32 bits (4 octets)
        pointedAddress = pointedAddress & 0xFFFFFFFF; // Garder uniquement les 32 premiers bits

        // Affichage de l'adresse après réduction à 32 bits (sur 4 octets)
        std::cout << "Adresse pointée après réduction à 32 bits : 0x"
            << std::hex << pointedAddress << std::endl;

        // Deuxième lecture de la mémoire à l'adresse modifiée (réduite à 32 bits)

        if (ReadMemory(hProcess, (LPCVOID)pointedAddress, &newPointedAddress, sizeof(newPointedAddress))) {
            std::cout << "Valeur lue à l'adresse pointée après réduction (nouvelle adresse) : 0x"
                << std::hex << newPointedAddress << std::endl;
        }
        else {
            std::cerr << "Échec de la lecture de la mémoire à la nouvelle adresse pointée!" << std::endl;
            CloseHandle(hProcess);
            return 1;
        }
        newPointedAddress = newPointedAddress & 0xFFFFFFFF;
    }
    else {
        std::cerr << "Échec de la lecture de l'adresse pointée!" << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    // Exemple d'utilisation avec l'adresse ammo (sur 8 octets)
    uintptr_t ammoAddr = newPointedAddress + 0x140;
    std::cout << "Adresse de ammo = 0x" << std::hex << ammoAddr << std::endl;

    // Demander la nouvelle valeur à écrire dans l'adresse mémoire trouvée
    int newValue;
    std::cout << "Entrez la nouvelle valeur (int) à modifier: ";
    std::cin >> newValue;

    // Écrire la nouvelle valeur à l'adresse de "ammo"
    if (WriteMemory(hProcess, (LPVOID)ammoAddr, &newValue, sizeof(newValue))) {
        std::cout << "La valeur a été modifiée avec succès!" << std::endl;
    }
    else {
        std::cerr << "Échec de la modification de la valeur!" << std::endl;
    }

    // Fermeture du handle du processus
    CloseHandle(hProcess);
    return 0;
}
