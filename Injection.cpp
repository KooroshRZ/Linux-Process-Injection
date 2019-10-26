#include <cstdlib>
#include "Injection.h"

void* PayloadPath = (void *) "/home/kourosh/CLionProjects/ProcessInjectorLinux/Payload.so";

int main() {

    void* libdlAddr = NULL;
    void* localLibdlAddress = NULL;
    void* remoteLibdlAddress = NULL;
    void* localDlopenAddress = NULL;
    void* remoteDlopenAddress = NULL;

    pid_t PID = 2591;

    // Load libdl-2.27 in out process
    libdlAddr = dlopen("libdl-2.27.so", RTLD_LAZY);
    if (!libdlAddr){
        printf("Error opening libdl-2.27\n");
        return -1;
    }
    printf("[+] libdl-2.27.so loaded at %p\n", (void*)libdlAddr);

    // Find address of dlopen()
    localDlopenAddress = dlsym((void*)(libdlAddr), "dlopen");
    if (!localDlopenAddress){
        printf("Error retrieving address of dlopen!\n");
        return -1;
    }
    printf("[+] dlopen() found at address %p\n", (void*)localDlopenAddress);

    // WTF ?? localLibdlAddress and libdlAddr are not equal !!!
    localLibdlAddress = FindLibraryAddress(-1, "libdl-2.27.so");
    printf("[+] libdl-2.27.so located at %p with maps file\n", localLibdlAddress);

    // Find libdl-2.27.so address in target process
    remoteLibdlAddress = FindLibraryAddress(PID, "libdl-2.27.so");
    printf("[+] libdl-2.27.so located in process %d at address %p\n", PID, remoteLibdlAddress);

    remoteDlopenAddress = (void*)(
            (unsigned long long)remoteLibdlAddress
                +(unsigned long long)(
                    (unsigned long long)localDlopenAddress - (unsigned long long)localLibdlAddress
                )
            );

    printf("[+] dlopen() offset in libdl found to be %p\n", (void*)((unsigned long long)libdlAddr - (unsigned long long)localLibdlAddress));
    printf("[+] dlopen() in target process at address %p\n", remoteDlopenAddress);

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

int Inject(int pid, void* dlopenAddr){
    pid_t PID = 2591;
    struct user_regs_struct OldRegs;

//    scanf("%p", PID);

    printf("[+] Tracing process with PID: %d\n", PID);
//    sleep(2);

    if(ptrace(PTRACE_ATTACH, PID, NULL, NULL) < 0){
        perror("ptrace(ATTACH):");
        return -1;
    }

    printf("[+] Getting Registers\n");
//    sleep(2);

    if(ptrace(PTRACE_GETREGS, PID, NULL, &OldRegs) < 0){
        perror("ptrace(GETREGS):");
        return -1;
    }

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