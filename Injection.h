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
#include <cstdlib>
#include <wait.h>

#include <sys/types.h>
#include <sys/ptrace.h>

#include <sys/user.h>
#include <sys/reg.h>


bool Inject(pid_t pid, void* dlopenAddr);
void* FindLibraryAddress(pid_t PID, const char* LibraryName);
bool ReadFromTargetMemory(pid_t PID, unsigned long long addr, void* data, int len);
bool WriteToMemory(pid_t PID, unsigned long long addr, void* data, int len);
void* FindExecutableSpace(pid_t PID);
void injectme(void);