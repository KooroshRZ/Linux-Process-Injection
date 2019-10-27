//
// Created by kourosh on 10/25/19.
//

#ifndef PROCESSINJECTORLINUX_INJECTION_H
#define PROCESSINJECTORLINUX_INJECTION_H

#endif //PROCESSINJECTORLINUX_INJECTION_H

#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>
#include <cstring>

#include <sys/types.h>
#include <sys/ptrace.h>

#include <sys/user.h>
#include <sys/reg.h>


int Inject(int pid, void* dlopenAddr);
void* FindLibraryAddress(pid_t PID, const char* LibraryName);
int ReadFromTargetMemory(pid_t PID, unsigned long long addr, void* data, int len);
void* FindExecutableSpace(pid_t PID);