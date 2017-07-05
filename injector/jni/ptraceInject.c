/************************************************************
  FileName: ptraceInject.c
  Description:       ptrace注入      
***********************************************************/


#include <stdio.h>    
#include <stdlib.h>    
#include <asm/user.h>    
#include <asm/ptrace.h>    
#include <sys/ptrace.h>    
#include <sys/wait.h>    
#include <sys/mman.h>    
#include <dlfcn.h>    
#include <dirent.h>    
#include <unistd.h>    
#include <string.h>    
#include <elf.h>    
#include <errno.h>
#include <utils/logger.h> 
#include <ptraceInject.h>

#define CPSR_T_MASK     ( 1u << 5 )

#define REMOTE_ADDR( addr, local_base, remote_base ) ( (uint32_t)(addr) + (uint32_t)(remote_base) - (uint32_t)(local_base) ) 

const char *libc_path = "/system/lib/libc.so";    
const char *linker_path = "/system/bin/linker";   

/*************************************************
  Description:    ptrace使远程进程继续运行
  Input:          pid表示远程进程的ID
  Output:         无
  Return:         返回0表示continue成功，返回-1表示失败
  Others:         无
*************************************************/
int ptrace_continue(pid_t pid)
{
	if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0)
	{
		LOGD("ptrace continue error, pid:%d, error: %s", pid, strerror(errno));
		return -1;
	}
	return 0;
}

/*************************************************
  Description:    使用ptrace Attach到指定进程
  Input:          pid表示远程进程的ID
  Output:         无
  Return:         返回0表示attach成功，返回-1表示失败
  Others:         无
*************************************************/  
int ptrace_attach(pid_t pid)    
{
	int status = 0;
	
    if (ptrace(PTRACE_ATTACH, pid, NULL, 0) < 0) {    
        LOGD("attach process error, pid:%d, error: %s", pid, strerror(errno));    
        return -1;    
    }    
	
 	LOGD("attach process pid:%d", pid);          
    waitpid(pid, &status , WUNTRACED);       	
    
    return 0;    
} 

/*************************************************
  Description:    使用ptrace detach指定进程
  Input:          pid表示远程进程的ID
  Output:         无
  Return:         返回0表示detach成功，返回-1表示失败
  Others:         无
*************************************************/    
int ptrace_detach(pid_t pid)    
{    
    if (ptrace(PTRACE_DETACH, pid, NULL, 0) < 0) {    
        LOGD("detach process error, pid:%d, error: %s", pid, strerror(errno));     
        return -1;    
    }    
    
	LOGD("detach process pid:%d", pid);  
    return 0;    
}

/*************************************************
  Description:    使用ptrace获取远程进程的寄存器值
  Input:          pid表示远程进程的ID，regs为pt_regs结构，存储了寄存器值
  Output:         无
  Return:         返回0表示获取寄存器成功，返回-1表示失败
  Others:         无
*************************************************/ 
int ptrace_getregs(pid_t pid, struct pt_regs *regs)
{
	if (ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0)
	{
		LOGD("Get Regs error, pid:%d", pid);
		return -1;
	}
	
	return 0;
}

/*************************************************
  Description:    使用ptrace设置远程进程的寄存器值
  Input:          pid表示远程进程的ID，regs为pt_regs结构，存储需要修改的寄存器值
  Output:         无
  Return:         返回0表示设置寄存器成功，返回-1表示失败
  Others:         无
*************************************************/ 
int ptrace_setregs(pid_t pid, struct pt_regs *regs)
{
	if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0)
	{
		LOGD("Set Regs error, pid:%d", pid);
		return -1;
	}
	
	return 0;
}

/*************************************************
  Description:    获取返回值，ARM处理器中返回值存放在ARM_r0寄存器中
  Input:          regs存储远程进程当前的寄存器值
  Output:         无
  Return:         在ARM处理器下返回r0寄存器值
  Others:         无
*************************************************/ 
long ptrace_getret(struct pt_regs * regs)    
{       
    return regs->ARM_r0;      
}

/*************************************************
  Description:    获取当前执行代码的地址，ARM处理器下存放在ARM_pc中
  Input:          regs存储远程进程当前的寄存器值
  Output:         无
  Return:         在ARM处理器下返回pc寄存器值
  Others:         无
*************************************************/ 
long ptrace_getpc(struct pt_regs * regs)    
{       
    return regs->ARM_pc;    
} 

/*************************************************
  Description:    使用ptrace从远程进程内存中读取数据
  Input:          pid表示远程进程的ID，pSrcBuf表示从远程进程读取数据的内存地址
				  pDestBuf表示用于存储读取出数据的地址，size表示读取数据的大小
  Output:         无
  Return:         返回0表示读取数据成功
  Others:         无
*************************************************/ 
int ptrace_readdata(pid_t pid, uint8_t *pSrcBuf, uint8_t *pDestBuf, uint32_t size)
{
	uint32_t nReadCount = 0;
	uint32_t nRemainCount = 0;
	uint8_t *pCurSrcBuf = pSrcBuf;
	uint8_t *pCurDestBuf = pDestBuf;
	long lTmpBuf = 0;
	uint32_t i = 0;	
 
	nReadCount = size / sizeof(long);
	nRemainCount = size % sizeof(long);

	for (i = 0; i < nReadCount; i ++ )
	{
		lTmpBuf = ptrace(PTRACE_PEEKTEXT, pid, pCurSrcBuf, 0);
		memcpy(pCurDestBuf, (char *)(&lTmpBuf), sizeof(long));
		pCurSrcBuf += sizeof(long);
		pCurDestBuf += sizeof(long);
	}

	if ( nRemainCount > 0 )
	{
		lTmpBuf = ptrace(PTRACE_PEEKTEXT, pid, pCurSrcBuf, 0);
		memcpy(pCurDestBuf, (char *)(&lTmpBuf), nRemainCount);
	}

	return 0;
}

// 
/*************************************************
  Description:    使用ptrace将数据写入到远程进程空间中
  Input:          pid表示远程进程的ID，pWriteAddr表示写入数据到远程进程的内存地址
				  pWriteData用于存储写入数据的地址，size表示写入数据的大小
  Output:         无
  Return:         返回0表示写入数据成功，返回-1表示写入数据失败
  Others:         无
*************************************************/ 
int ptrace_writedata(pid_t pid, uint8_t *pWriteAddr, uint8_t *pWriteData, uint32_t size)
{
	uint32_t nWriteCount = 0;
	uint32_t nRemainCount = 0;
	uint8_t *pCurSrcBuf = pWriteData;
	uint8_t *pCurDestBuf = pWriteAddr;
	long lTmpBuf = 0;
	uint32_t i = 0;
	
	nWriteCount = size / sizeof(long);
	nRemainCount = size % sizeof(long);

	// 先讲数据以sizeof(long)字节大小为单位写入到远程进程内存空间中
	for (i = 0; i < nWriteCount; i ++)
	{
		memcpy((void *)(&lTmpBuf), pCurSrcBuf, sizeof(long));
		if (ptrace(PTRACE_POKETEXT, pid, pCurDestBuf, lTmpBuf) < 0)  // PTRACE_POKETEXT表示从远程内存空间写入一个sizeof(long)大小的数据
		{
			LOGD("Write Remote Memory error, MemoryAddr:0x%lx", (long)pCurDestBuf);
			return -1;
		}
		pCurSrcBuf += sizeof(long);
		pCurDestBuf += sizeof(long);
	}
	
	// 将剩下的数据写入到远程进程内存空间中
	if (nRemainCount > 0)
	{
		lTmpBuf = ptrace(PTRACE_PEEKTEXT, pid, pCurDestBuf, NULL); //先取出原内存中的数据，然后将要写入的数据以单字节形式填充到低字节处
		memcpy((void *)(&lTmpBuf), pCurSrcBuf, nRemainCount);
		if (ptrace(PTRACE_POKETEXT, pid, pCurDestBuf, lTmpBuf) < 0)
		{
			LOGD("Write Remote Memory error, MemoryAddr:0x%lx", (long)pCurDestBuf);
			return -1;			
		}
	}
	
	return 0;	
}

/*************************************************
  Description:    使用ptrace远程call函数
  Input:          pid表示远程进程的ID，ExecuteAddr为远程进程函数的地址
                  parameters为函数参数的地址，regs为远程进程call函数前的寄存器环境
  Output:         无
  Return:         返回0表示call函数成功，返回-1表示失败
  Others:         无
*************************************************/ 
int ptrace_call(pid_t pid, uint32_t ExecuteAddr, long *parameters, long num_params, struct pt_regs* regs)    
{    
    int i = 0;
	// ARM处理器，函数传递参数，将前四个参数放到r0-r3，剩下的参数压入栈中
    for (i = 0; i < num_params && i < 4; i ++) {    
        regs->uregs[i] = parameters[i];    
    }    
    
    if (i < num_params) {    
        regs->ARM_sp -= (num_params - i) * sizeof(long) ;    // 分配栈空间，栈的方向是从高地址到低地址
        if (ptrace_writedata(pid, (void *)regs->ARM_sp, (uint8_t *)&parameters[i], (num_params - i) * sizeof(long))  == -1)
			return -1;
    }    
    
    regs->ARM_pc = ExecuteAddr;           //设置ARM_pc寄存器为需要调用的函数地址
    // 与BX跳转指令类似，判断跳转的地址位[0]是否为1，如果为1，则将CPST寄存器的标志T置位，解释为Thumb代码
	// 若为0，则将CPSR寄存器的标志T复位，解释为ARM代码
	if (regs->ARM_pc & 1) {    
        /* thumb */    
        regs->ARM_pc &= (~1u);    
        regs->ARM_cpsr |= CPSR_T_MASK;    
    } else {    
        /* arm */    
        regs->ARM_cpsr &= ~CPSR_T_MASK;    
    }    
    
    regs->ARM_lr = 0;        
    
    if (ptrace_setregs(pid, regs) == -1 || ptrace_continue(pid) == -1) {    
        LOGD("ptrace set regs or continue error, pid:%d", pid);  
        return -1;    
    }    
    
    int stat = 0;  
	// 对于使用ptrace_cont运行的子进程，它会在3种情况下进入暂停状态：①下一次系统调用；②子进程退出；③子进程的执行发生错误。
	// 参数WUNTRACED表示当进程进入暂停状态后，立即返回
	// 将ARM_lr（存放返回地址）设置为0，会导致子进程执行发生错误，则子进程进入暂停状态
    waitpid(pid, &stat, WUNTRACED);  
    
	// 判断是否成功执行函数
    LOGD("ptrace call ret status is %d\n", stat); 
    while (stat != 0xb7f) {  
        if (ptrace_continue(pid) == -1) {  
            LOGD("ptrace call error");  
            return -1;  
        }  
        waitpid(pid, &stat, WUNTRACED);  
    }

	// 获取远程进程的寄存器值，方便获取返回值
	if (ptrace_getregs(pid, regs) == -1)
	{
		LOGD("After call getregs error");
		return -1;
	}
    
    return 0;    
}    

/*************************************************
  Description:    在指定进程中搜索对应模块的基址
  Input:          pid表示远程进程的ID，若为-1表示自身进程，ModuleName表示要搜索的模块的名称
  Output:         无
  Return:         返回0表示获取模块基址失败，返回非0为要搜索的模块基址
  Others:         无
*************************************************/ 
void* GetModuleBaseAddr(pid_t pid, const char* ModuleName)    
{
    FILE *fp = NULL;    
    long ModuleBaseAddr = 0; 	
	char *ModulePath, *MapFileLineItem;
    char szFileName[50] = {0};    
    char szMapFileLine[1024] = {0};
	char szProcessInfo[1024] = {0};
    
	// 读取"/proc/pid/maps"可以获得该进程加载的模块
    if (pid < 0) {    
        //  枚举自身进程模块 
        snprintf(szFileName, sizeof(szFileName), "/proc/self/maps");    
    } else {    
        snprintf(szFileName, sizeof(szFileName), "/proc/%d/maps", pid);    
    }    
    
    fp = fopen(szFileName, "r");    
    
    if (fp != NULL) 
	{    
        while (fgets(szMapFileLine, sizeof(szMapFileLine), fp)) {
			if (strstr(szMapFileLine, ModuleName))
			{
				MapFileLineItem = strtok(szMapFileLine, " \t"); // 基址信息
                char *Addr = strtok(szMapFileLine, "-");    
                ModuleBaseAddr = strtoul(Addr, NULL, 16 );    
    
                if (ModuleBaseAddr == 0x8000)    
                    ModuleBaseAddr = 0;    
    
                break;   				
			}
        }    
    
        fclose(fp) ;    
    }    
    
    return (void *)ModuleBaseAddr;       
}    

/*************************************************
  Description:    获取远程进程与本进程都加载的模块中函数的地址
  Input:          pid表示远程进程的ID，ModuleName表示模块名称，LocalFuncAddr表示本地进程中该函数的地址
  Output:         无
  Return:         返回远程进程中对应函数的地址
  Others:         无
*************************************************/ 
void* GetRemoteFuncAddr(pid_t pid, const char *ModuleName, void *LocalFuncAddr)
{
	void *LocalModuleAddr, *RemoteModuleAddr, *RemoteFuncAddr;
	
	LocalModuleAddr = GetModuleBaseAddr(-1, ModuleName);
	RemoteModuleAddr = GetModuleBaseAddr(pid, ModuleName);

	LOGD("====  Base Address of %s: %p", ModuleName, RemoteModuleAddr);
	
	RemoteFuncAddr = (void *)((long)LocalFuncAddr - (long)LocalModuleAddr + (long)RemoteModuleAddr);
	
	return RemoteFuncAddr;
}

/*************************************************
  Description:    通过远程直接调用dlopen\dlsym的方法ptrace注入so模块到远程进程中
  Input:          pid表示远程进程的ID，LibPath为被远程注入的so模块路径，FunctionName为远程注入的模块后调用的函数
				  FuncParameter指向被远程调用函数的参数（若传递字符串，需要先将字符串写入到远程进程空间中），NumParameter为参数的个数
  Output:         无
  Return:         返回0表示注入成功，返回-1表示失败
  Others:         无
*************************************************/ 
int inject_remote_process(pid_t pid, char *LibPath, char *FunctionName, long *FuncParameter, long NumParameter)
{
	int iRet = -1;
	struct pt_regs CurrentRegs, OriginalRegs;  // CurrentRegs表示远程进程中当前的寄存器值，OriginalRegs存储注入前的寄存器值，方便恢复
	void *mmap_addr, *dlopen_addr, *dlsym_addr, *dlclose_addr, *dlerror_addr;   // 远程进程中需要调用函数的地址
	void *RemoteMapMemoryAddr, *RemoteModuleAddr, *RemoteModuleFuncAddr; // RemoteMapMemoryAddr为远程进程空间中映射的内存基址，RemoteModuleAddr为远程注入的so模块加载基址，RemoteModuleFuncAddr为注入模块中需要调用的函数地址
	long parameters[6];  
	
	// Attach远程进程
	if (ptrace_attach(pid) == -1)
		return iRet;
	
	// 获取远程进程的寄存器值
	if (ptrace_getregs(pid, &CurrentRegs) == -1)
	{
		ptrace_detach(pid);
		return iRet;
	}

	LOGD("ARM_r0:0x%lx, ARM_r1:0x%lx, ARM_r2:0x%lx, ARM_r3:0x%lx, ARM_r4:0x%lx, ARM_r5:0x%lx, ARM_r6:0x%lx, ARM_r7:0x%lx, ARM_r8:0x%lx, ARM_r9:0x%lx, ARM_r10:0x%lx, ARM_ip:0x%lx, ARM_sp:0x%lx, ARM_lr:0x%lx, ARM_pc:0x%lx", \
		CurrentRegs.ARM_r0, CurrentRegs.ARM_r1, CurrentRegs.ARM_r2, CurrentRegs.ARM_r3, CurrentRegs.ARM_r4, CurrentRegs.ARM_r5, CurrentRegs.ARM_r6, CurrentRegs.ARM_r7, CurrentRegs.ARM_r8, CurrentRegs.ARM_r9, CurrentRegs.ARM_r10, CurrentRegs.ARM_ip, CurrentRegs.ARM_sp, CurrentRegs.ARM_lr, CurrentRegs.ARM_pc);
	
	// 保存远程进程空间中当前的上下文寄存器环境
	memcpy(&OriginalRegs, &CurrentRegs, sizeof(CurrentRegs)); 
	
	// 获取mmap函数在远程进程中的地址
	mmap_addr = GetRemoteFuncAddr(pid, libc_path, (void *)mmap);
	LOGD("mmap RemoteFuncAddr:0x%lx", (long)mmap_addr);
	
	// 设置mmap的参数
	// void *mmap(void *start, size_t length, int prot, int flags, int fd, off_t offsize);
    parameters[0] = 0;  // 设置为NULL表示让系统自动选择分配内存的地址    
    parameters[1] = 0x1000; // 映射内存的大小    
    parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC;  // 表示映射内存区域可读可写可执行   
    parameters[3] =  MAP_ANONYMOUS | MAP_PRIVATE; // 建立匿名映射    
    parameters[4] = 0; //  若需要映射文件到内存中，则为文件的fd  
    parameters[5] = 0; //文件映射偏移量 	
	
	// 调用远程进程的mmap函数，建立远程进程的内存映射
	if (ptrace_call(pid, (long)mmap_addr, parameters, 6, &CurrentRegs) == -1)
	{
		LOGD("Call Remote mmap Func Failed");
		ptrace_detach(pid);
		return iRet;
	}
	
	// 获取mmap函数执行后的返回值，也就是内存映射的起始地址
	RemoteMapMemoryAddr = (void *)ptrace_getret(&CurrentRegs);
	LOGD("Remote Process Map Memory Addr:0x%lx", (long)RemoteMapMemoryAddr);
	
	// 分别获取dlopen、dlsym、dlclose等函数的地址
	dlopen_addr = GetRemoteFuncAddr(pid, linker_path, (void *)dlopen);
	dlsym_addr = GetRemoteFuncAddr(pid, linker_path, (void *)dlsym);
	dlclose_addr = GetRemoteFuncAddr(pid, linker_path, (void *)dlclose);
	dlerror_addr = GetRemoteFuncAddr(pid, linker_path, (void *)dlerror);
	
	LOGD("dlopen RemoteFuncAddr:0x%lx", (long)dlopen_addr);
	LOGD("dlsym RemoteFuncAddr:0x%lx", (long)dlsym_addr);
	LOGD("dlclose RemoteFuncAddr:0x%lx", (long)dlclose_addr);
	LOGD("dlerror RemoteFuncAddr:0x%lx", (long)dlerror_addr);
	
	// 将要加载的so库路径写入到远程进程内存空间中
	if (ptrace_writedata(pid, RemoteMapMemoryAddr, LibPath, strlen(LibPath) + 1) == -1)
	{
		LOGD("Write LibPath:%s to RemoteProcess error", LibPath);
		ptrace_detach(pid);
		return iRet;
	}
	
	// 设置dlopen的参数,返回值为模块加载的地址
	// void *dlopen(const char *filename, int flag);
	parameters[0] = (long)RemoteMapMemoryAddr;
	parameters[1] = RTLD_NOW| RTLD_GLOBAL;
	
	if (ptrace_call(pid, (long)dlopen_addr, parameters, 2, &CurrentRegs) == -1)
	{
		LOGD("Call Remote dlopen Func Failed");
		ptrace_detach(pid);
		return iRet;
	}

	// RemoteModuleAddr为远程进程加载注入模块的地址
	RemoteModuleAddr = (void *)ptrace_getret(&CurrentRegs);
	LOGD("Remote Process load module Addr:0x%lx", (long)RemoteModuleAddr);
	
	if ((long)RemoteModuleAddr == 0x0)   // dlopen 错误
	{
		LOGD("dlopen error");
		if (ptrace_call(pid, (long)dlerror_addr, parameters, 0, &CurrentRegs) == -1)
		{
			LOGD("Call Remote dlerror Func Failed");
			ptrace_detach(pid);
			return iRet;
		}
		char *Error = (void *)ptrace_getret(&CurrentRegs);
		char LocalErrorInfo[1024] = {0};
		ptrace_readdata(pid, Error, LocalErrorInfo, 1024);
		LOGD("dlopen error:%s", LocalErrorInfo);
		ptrace_detach(pid);
		return iRet;
	}	
	
	// 将so库中需要调用的函数名称写入到远程进程内存空间中
	if (ptrace_writedata(pid, RemoteMapMemoryAddr + strlen(LibPath) + 2, FunctionName, strlen(FunctionName) + 1) == -1)
	{
		LOGD("Write FunctionName:%s to RemoteProcess error", FunctionName);
		ptrace_detach(pid);
		return iRet;
	}
	
	// 设置dlsym的参数，返回值为远程进程内函数的地址
	// void *dlsym(void *handle, const char *symbol);
	parameters[0] = (long)RemoteModuleAddr;
	parameters[1] = (long)(RemoteMapMemoryAddr + strlen(LibPath) + 2);
	
	if (ptrace_call(pid, (long)dlsym_addr, parameters, 2, &CurrentRegs) == -1)
	{
		LOGD("Call Remote dlsym Func Failed");
		ptrace_detach(pid);
		return iRet;
	}	
	
	// RemoteModuleFuncAddr为远程进程空间内获取的函数地址
	RemoteModuleFuncAddr = (void *)ptrace_getret(&CurrentRegs);
	LOGD("Remote Process ModuleFunc Addr:0x%lx", (long)RemoteModuleFuncAddr);
	
	if (ptrace_call(pid, (long)RemoteModuleFuncAddr, FuncParameter, NumParameter, &CurrentRegs) == -1)
	{
		LOGD("Call Remote injected Func Failed");
		ptrace_detach(pid);
		return iRet;
	}	
	
	if (ptrace_setregs(pid, &OriginalRegs) == -1)
	{
		LOGD("Recover reges failed");
		ptrace_detach(pid);
		return iRet;		
	}
	LOGD("Recover Regs Success");
	ptrace_getregs(pid, &CurrentRegs);
	if (memcmp(&OriginalRegs, &CurrentRegs, sizeof(CurrentRegs)) != 0)
	{
		LOGD("Set Regs Error");
	}
	
	//Detach
	if (ptrace_detach(pid) == -1)
	{
		LOGD("ptrace detach failed");
		return iRet;
	}
	
	return 0;
}