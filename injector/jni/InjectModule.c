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
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>    
#include <dirent.h>    
#include <unistd.h>    
#include <string.h>    
#include <elf.h>
#include <pthread.h> 
#include <ptraceInject.h>
#include <utils/logger.h>

typedef struct push_data_struct
{
	char * content;
	int contentLen;
}PushData;

int parse_command_options(int argc, char * argv[]);
pthread_t pass_parameters(char * targetso, char * modulefullpath, int maxlen);
int start_commander();
void *feedback_listener(void * param);
void *push_worker(void * param);

void print_usage(char * processName) {
	printf("Usage: %s -p PID -t TargetSoName\n", processName);
	printf("	Note: Need put one copy of your target so file under your memtracer execute path.\n");
}

// Input Options
pid_t pid;
char * targetSoName = NULL;
const unsigned int push_port = 7878;
const unsigned int socket_port = 7788;

int push_thread_started = 0;

int main(int argc, char *argv[]) {

	if(parse_command_options(argc, argv) != 0) 
	{
		print_usage(argv[0]);
		return -1;
	}

	char RemoteCallFunc[MAX_PATH] = "memtracer_entry";              // 注入模块后调用模块函数名称
	char InjectModuleName[MAX_PATH]; //= "/data/local/inject/libmemtracer.so";    // 注入模块全路径

	char exec_path[MAX_PATH];
	char *ret = getcwd(exec_path, MAX_PATH - 20);
	if(ret == NULL) {
		printf("Get Current Working Path Failed, Error: %s\n", strerror(errno));
		return -1;
	}

	// 获取执行参数，把参数填入共享内存，并把共享内存ID传递给注入进程
	pthread_t push_td = pass_parameters(targetSoName, exec_path, sizeof(exec_path));
	if( push_td == (pthread_t)-1) 
	{
		printf("Create Pass Parameter Thread Failed!\n");
		return -1;
	}

	while(push_thread_started == 0)
	{
		usleep(1000);
	}
	printf("Push thread started success!");

	usleep(3000);

	snprintf(InjectModuleName, MAX_PATH, "%s/libmemtracer.so", exec_path);
	printf("Wait for injected module process\n");

	// 当前设备环境判断
	#if defined(__i386__)  
	LOGI("Current Environment x86\n");
	return -1;
	#elif defined(__arm__)
	LOGI("Current Environment ARM\n");
	#else     
	LOGI("other Environment\n");
	return -1;
	#endif
	
	printf("begin inject process, RemoteProcess pid:%d, InjectModuleName:%s, RemoteCallFunc:%s\n", pid, InjectModuleName, RemoteCallFunc);

	int iRet = inject_remote_process(pid,  InjectModuleName, RemoteCallFunc, (long *)&socket_port, 1);
	
	if (iRet != 0)
	{
		printf("Inject Failed\n");
		return -1;
	}

	pthread_join(push_td, NULL);
	printf("Target has read out the parameters\n");

	printf("Inject Success\n");
	start_commander();

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
pthread_t pass_parameters(char * targetso, char * execpath, int maxlen)
{
	char *content = (char *)malloc(1024);
	int conlen = snprintf(content, 1023, "PATH:%s|LIBS:%s|", execpath, targetso);
	content[conlen] = 0;

	printf("Content Ready: %s, start push thread\n", content);

	pthread_t push_thread;
	PushData * push_data = (PushData *)malloc(sizeof(PushData));
	push_data->content = content;
	push_data->contentLen = conlen;

    LOGI("Start Create Push Thread!");
	pthread_create(&push_thread, NULL, push_worker, (void *)push_data);

	return push_thread;
}

void * push_worker(void * param)
{
	PushData * push_data = (PushData *)param;
	char *content = push_data->content;
	int conlen = push_data->contentLen;

	int push_sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(push_sockfd < 0)
	{
		printf("Create INET socket failed\n");
		return NULL;
	}

	struct sockaddr_in push_addr;
	push_addr.sin_family = AF_INET;
	push_addr.sin_port = htons(push_port);
	push_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

	if(bind(push_sockfd, (struct sockaddr *)&push_addr, sizeof(push_addr)) == -1)
	{
		printf("Bind to network interface failed: %s\n", strerror(errno));
		return NULL;
	}

	printf("Wait for target connect in to read parameters\n");
	push_thread_started = 1;

	if(listen(push_sockfd, 1) == -1) {
		printf("Listen error: %s\n", strerror(errno));
		return NULL;
	}

	struct sockaddr_in client_addr;
	int clientlen = sizeof(client_addr);

	int connfd = accept(push_sockfd, (struct sockaddr *)&client_addr, &clientlen);
	if(connfd < 0)
	{
		printf("Accept failed: %s\n", strerror(errno));
		return NULL;
	}

	// Has one client connected in, push parameters to it
	send(connfd, content, conlen, 0);

	printf("parameters pushed to client: %s\n", content);

	char feedback[128] = {0};
	int readbytes = recv(connfd, feedback, sizeof(feedback), 0);
	feedback[readbytes] = 0;
	printf("Client reply: %s\n", feedback);

	close(connfd);
	close(push_sockfd);

	return NULL;
}

// 打开socket给注入后的memtracer发送控制命令，并接收反馈
int start_commander()
{
	int sock;
    if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
    {
    	printf("Create commander socket failed.\n");
    	return -1;
    }

    const char* SERVERIP = "127.0.0.1";
        
    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(socket_port);
    servaddr.sin_addr.s_addr = inet_addr(SERVERIP);

    // Start a thread to listening the command feedback
    pthread_t recvthread;
	pthread_create(&recvthread, NULL, feedback_listener, &sock);

	printf("Memtracer commander started, available commands are: \n"
		"s[start], e[end], d[dump], c[simple mode switch], b[backtrace switch], r[reset]\n");

    int ret;
    char sendbuf[256] = {0};
    while (fgets(sendbuf, sizeof(sendbuf), stdin) != NULL)
    {
        sendto(sock, sendbuf, strlen(sendbuf), 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
        //ret = recvfrom(sock, recvbuf, sizeof(recvbuf), 0, NULL, NULL);
        //if (ret == -1)
        //{
        //    if (errno == EINTR)
        //        continue;
        //    ERR_EXIT("recvfrom");
        //}
        //printf("Received from server: %s\n",recvbuf);
        memset(sendbuf, 0, sizeof(sendbuf));
    }

    close(sock);
    return 0;
}

void * feedback_listener(void * param)
{
	int servsock = *((int *)param);
	int ret;
	char recvbuff[1024];
	while(1)
	{
		memset(recvbuff, 0, sizeof(recvbuff));
		ret = recvfrom(servsock, recvbuff, sizeof(recvbuff), 0, NULL, NULL);
		if(ret >= 0) {
			printf("%s\n", recvbuff);
		}
		else {
			printf("Receive memtracer feedback failed!\n");
		}
	}
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