/************************************************************
  FileName: ptraceInject.h
  Description:       ptrace注入      
***********************************************************/
#ifndef _PTRACE_INJECT_H_
#define _PTRACE_INJECT_H_

#include <stdio.h>    
#include <stdlib.h>       
#include <unistd.h>    

#define  MAX_PATH 0x100

int inject_remote_process(pid_t pid, char *LibPath, char *FunctionName, long *FuncParameter, long NumParameter);   // 通过ptrace远程调用dlopen/dlsym方式注入模块到远程进程
int inject_remote_process_shellcode(pid_t pid, char *LibPath, char *FunctionName, long *FuncParameter, long NumParameter); // 通过shellcode方式注入模块到远程进程


#endif