#include <Windows.h>
#include <iostream>

using namespace std;

int main() {
    DWORD pid = 0; // The process ID of our target process
    cout << "PID: ";
    cin >> dec >> pid; // Prompting user for PID

    // Open the target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) { // Failed to get a handle
        cout << "OpenProcess failed. GetLastError = " << dec << GetLastError() << endl;
        system("pause");
        return EXIT_FAILURE;
    }

    // Prompting user for memory address to overwrite
    uintptr_t memoryAddress = 0x0;
    cout << "Memory address of the memory to overwrite (in hexadecimal): 0x";
    cin >> hex >> memoryAddress;

    // Prompting user for the integer to write to the memory
    int intWrite = 0;
    cout << "Int to write: ";
    cin >> intWrite;

    // Writing the integer into the memory
    BOOL wpmReturn = WriteProcessMemory(hProcess, (LPVOID)memoryAddress, &intWrite, sizeof(int), NULL);
    if (wpmReturn == FALSE) {
        cout << "WriteProcessMemory failed. GetLastError = " << dec << GetLastError() << endl;
        system("pause");
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    cout << "Memory overwritten successfully!" << endl;

    // Clean up
    cout << "Press ENTER to quit." << endl;
    system("pause > nul");

    CloseHandle(hProcess);

    return EXIT_SUCCESS;
}
