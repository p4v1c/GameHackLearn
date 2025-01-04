#include <iostream>
#include <Windows.h>
#define size 128

int main()
{
    int varInt = 123456;
    std::string varString = "DefaultString";
    char arrChar[size] = "Long char array right there ->";
    int *ptr2int = &varInt;
    int **ptr2ptr = &ptr2int;
    int ***ptr2ptr2 = &ptr2ptr;

    while (true) {

        std::cout << "Process ID: " << GetCurrentProcessId() << "`\n" << std::endl;

        std::cout << "varInt " << "(0x" << &varInt << ")" << " = " << varInt << "\n" << std::endl;
        std::cout << "varString " << "(0x" << &varString << ")" << " = "  << varString << "\n" << std::endl;
        std::cout << "arrChar " << "(0x" << &arrChar << ")" << " = " << arrChar << "\n" << std::endl;

        std::cout << "ptr2int " << "(0x" << &ptr2int << ")" << " = " << std::showbase << std::hex << (uintptr_t) ptr2int << "\n" << std::endl;
        std::cout << "ptr2ptr " << "(0x" << &ptr2ptr << ")" << " = " << std::showbase << std::hex << (uintptr_t) ptr2ptr  << "\n" << std::endl;
        std::cout << "ptr2ptr2 " << "(0x" << &ptr2ptr2 << ")" << " = " << std::showbase << std::hex << (uintptr_t) ptr2ptr2  << "\n" << std::endl;

        std::cout << "Press ENTER to print again.";
        std::cin.ignore();
        std::cout << "--------------------------------------\n\n";

        
    }
    return 0;
}

