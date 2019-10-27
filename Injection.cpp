#include <cstdlib>
#include "Injection.h"

void* PayloadPath = (void *) "/home/kourosh/CLionProjects/ProcessInjectorLinux/Payload.so";

int main() {

    void* libdlAddr = nullptr;
    void* localLibdlAddress = nullptr;
    void* remoteLibdlAddress = nullptr;
    void* localDlopenAddress = nullptr;
    void* remoteDlopenAddress = nullptr;

    pid_t PID = 2591;

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

int Inject(int PID, void* dlopenAddr){

    struct user_regs_struct OldRegs{}, regs{};
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

    int oldCodesSize = 8192;
    auto* oldCodes = (unsigned char*)malloc(oldCodesSize);

    void* freeAddress = FindExecutableSpace(PID);

//    int ReadSuccess = ReadFromTargetMemory(PID, (unsigned long long)dlopenAddr, oldCodes, oldCodesSize);



    printf("[+] Detaching target process\n");

    if( ptrace(PTRACE_DETACH, PID, NULL, NULL) < 0){
        perror("ptrace(DETACH)");
        return -1;
    }
//    system("PAUSE");
    printf("%d\n", getpid());
    sleep(2000);

    return 0;
}

int ReadFromTargetMemory(pid_t PID, unsigned long long addr, void* data, int len){

    char* ptr = (char*) data;
    long word;

    for (int i = 0; i < len; i += sizeof(word), word=0){
        if ((word = ptrace(PTRACE_PEEKTEXT, PID, addr + i, NULL)) == -1){
            printf("Error reading from addr %p\n", (void*)(addr+i) );
            ptrace(PTRACE_DETACH, PID, NULL, NULL);
            return -1;
        }

        ptr[i] = word;

    }

    return 0;

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

    printf("address : %p\n", (void*)address);
    return address;

}