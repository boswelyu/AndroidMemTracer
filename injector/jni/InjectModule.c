/************************************************************
  FileName: InjectModule.c
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
#include <ptraceInject.h>
#include <utils/logger.h>

int parse_command_options(int argc, char * argv[]);
int pass_parameters(char * targetso, char * modulefullpath, int maxlen);
pid_t FindPidByProcessName(const char *process_name);

void PrintUsage(char * processName) {
	printf("Usage: %s -p PID -t TargetSoName\n", processName);
	printf("	Note: Need put one copy of your target so file under your memtracer execute path.\n");
}

// Input Options
pid_t pid;
char * targetSoName = NULL;
unsigned int socket_port = 7788;

int main(int argc, char *argv[]) {

	if(parse_command_options(argc, argv) != 0) 
	{
		PrintUsage(argv[0]);
		return -1;
	}

	char RemoteCallFunc[MAX_PATH] = "memtracer_entry";              // 注入模块后调用模块函数名称
	char exec_path[MAX_PATH];
	char InjectModuleName[MAX_PATH]; //= "/data/local/inject/libmemtracer.so";    // 注入模块全路径

	// 获取执行参数，把参数填入共享内存，并把共享内存ID传递给注入进程
	int iRet = pass_parameters(targetSoName, exec_path, MAX_PATH);
	if( iRet < 0) 
	{
		printf("Pass Parameter Failed!\n");
		return -1;
	}

	snprintf(InjectModuleName, MAX_PATH, "%s/libmemtracer.so", exec_path);

	// 当前设备环境判断
	#if defined(__i386__)  
	LOGD("Current Environment x86");
	return -1;
	#elif defined(__arm__)
	LOGD("Current Environment ARM");
	#else     
	LOGD("other Environment");
	return -1;
	#endif
	
	printf("begin inject process, RemoteProcess pid:%d, InjectModuleName:%s, RemoteCallFunc:%s\n", pid, InjectModuleName, RemoteCallFunc);

	iRet = inject_remote_process(pid,  InjectModuleName, RemoteCallFunc,  (long *)&socket_port, 1);
	
	if (iRet == 0)
	{
		printf("Inject Success\n");
	}
	else
	{
		printf("Inject Failed\n");
	}
	printf("end inject,%d\n", pid);
    return 0;  
}  

/*************************************************
  Description:    解析输入参数
  Input:          argc: 参数个数 argv 参数列表
  Output:         无
  Return:         0：成功  -1：失败
  Others:         无
*************************************************/ 
int parse_command_options(int argc, char * argv[])
{
	pid = 0;
	targetSoName = NULL;

	const char * optionstr = "p:t:";
	int ret;
	while((ret = getopt(argc, argv, optionstr)) != -1)
	{
		switch(ret) 
		{
			case 'p':
				pid = (pid_t)atoi(optarg);
				if(pid <= 0) 
				{
					printf("Invalid PID was given: %s\n", optarg);
					return -1;
				}
				break;
			case 't':
				targetSoName = optarg;
				break;
			case '?':
			default:
				break;
		}
	}

	if(pid > 0 && targetSoName != NULL) {
		return 0;
	}

	printf("PID or target not set, PID: %d, target: %s\n", pid, targetSoName);
	return -1;
}

// 给注入模块传递运行时参数，包括目标链接库名字和程序运行路径
// 因为Android不支持IPC的进程间通信方式，这里把参数都写入固定的临时文件
int pass_parameters(char * targetso, char * execpath, int maxlen)
{
	const char temp_file[MAX_PATH] = "/sdcard/tmp/memtracer_temp.swp";
	FILE * fp = fopen(temp_file, "w");
	if(fp == NULL) 
	{
		printf("Create temp file to pass parameter failed, error: %s\n", strerror(errno));
		return -1;
	}

	char * ret = getcwd(execpath, maxlen - 20);
	if(ret == NULL) {
		printf("Get Current Working Path Failed, Error: %s\n", strerror(errno));
		fclose(fp);
		return -1;
	}

	fputs(targetso, fp);
	fputs("\n", fp);
	fputs(execpath, fp);

	fflush(fp);
	fclose(fp);

	return 0;
}

/*************************************************
  Description:    通过进程名称定位到进程的PID
  Input:          process_name为要定位的进程名称
  Output:         无
  Return:         返回定位到的进程PID，若为-1，表示定位失败
  Others:         无
*************************************************/ 
pid_t FindPidByProcessName(const char *process_name)
{
	int ProcessDirID = 0;
	pid_t pid = -1;
	FILE *fp = NULL;
	char filename[MAX_PATH] = {0};
	char cmdline[MAX_PATH] = {0};

	struct dirent * entry = NULL;

	if ( process_name == NULL )
		return -1;

	DIR* dir = opendir( "/proc" );
	if ( dir == NULL )
		return -1;

	while( (entry = readdir(dir)) != NULL )
	{
		ProcessDirID = atoi( entry->d_name );
		if ( ProcessDirID != 0 )
		{
			snprintf(filename, MAX_PATH, "/proc/%d/cmdline", ProcessDirID);
			fp = fopen( filename, "r" );
			if ( fp )
			{
				fgets(cmdline, sizeof(cmdline), fp);
				fclose(fp);

				if (strncmp(process_name, cmdline, strlen(process_name)) == 0)
				{
					pid = ProcessDirID;
					break;
				}
			}
		}
	}

	closedir(dir);
	return pid;
}