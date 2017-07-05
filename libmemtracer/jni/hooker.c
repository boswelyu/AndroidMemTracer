#include <stdio.h>
#include <stdlib.h>
#include <utils/logger.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <unistd.h>
#include <elf.h>
#include <pthread.h>
#include <errno.h>
#include <memtracer.h>

#define MAX_PATH_LEN 256

int read_parameters();
void post_process_str(char * strbuf, int maxlen);
void * command_listener(void * param);

int parse_target_library(const char *targetdir, const char *targetsoname);

int do_got_hook(void *symbol, void *new_function, void **old_function);


char g_target_so[MAX_PATH_LEN];
char g_main_dir[MAX_PATH_LEN];
int  g_socket_port = 7788;
uint32_t g_GotTableStartaddr = 0;
uint32_t g_GotTableSize = 0;
uint32_t g_base = 0;

void * (*orig_malloc)(size_t size);
void * replaced_malloc(size_t size) 
{
	void * ptr = trace_malloc(size, orig_malloc);
	return ptr;
} 

void * (*orig_calloc)(size_t blocks, size_t size);
void * replaced_calloc(size_t blocks, size_t size) 
{
	void * ptr = trace_calloc(blocks, size, orig_calloc, orig_malloc);
	return ptr;
}

void (*orig_free)(void * ptr);
void replaced_free(void * ptr) 
{
	trace_free(ptr, orig_free);
}

void * (*orig_realloc)(void *ptr, size_t size);
void * replaced_realloc(void *addr, size_t size)
{
	void * retptr = trace_realloc(addr, size, orig_realloc, orig_malloc, orig_free);
	return retptr;
}


/* libmemtracer.so注入目标进程后执行的入口函数 */
int memtracer_entry(long * param)
{
	g_socket_port = (int)param;

	LOGD("Start MemTracer Init with port: %d\n", g_socket_port);

	if(read_parameters() != 0) {
		LOGE("MemTracer Read Runtime Parameters Failed!");
		return -1;
	}

	if(memtracer_init(20000) != 0)
	{
		LOGE("MemTracer Init Failed!");
		return -1;
	}

	// Start one thread to listen control command
	pthread_t ptd;
	pthread_create(&ptd, NULL, command_listener, NULL);
	
	int iret;
	iret = parse_target_library(g_main_dir, g_target_so);
	if(iret != 0)
	{
		LOGE("Parse Library File Failed!");
		return -1;
	}

	iret = do_got_hook((void *)calloc, (void *)replaced_calloc, (void **)&orig_calloc);
	if(iret != 0)
	{
		LOGE("MemTracer hook function calloc failed!");
		return -1;
	}

	iret = do_got_hook((void *)malloc, (void *)replaced_malloc, (void **)&orig_malloc);
	if(iret != 0) {
		LOGE("MemTracer hook function malloc failed!");
		return -1;
	}

	iret = do_got_hook((void *)realloc, (void *)replaced_realloc, (void **)&orig_realloc);
	if(iret != 0)
	{
		LOGE("MemTracer hook function realloc failed!");
		return -1;
	}

	iret = do_got_hook((void *)free, (void *)replaced_free, (void **)&orig_free);
	if(iret != 0)
	{
		LOGE("MemTracer hook function free failed!");
		return -1;
	}



	return 0;
}

/* 
 * 从共享内存中读取必要的参数，包括：
 * 1 - 执行hook的目标库文件名
 * 2 - 母程序的执行路径
 */
int read_parameters() {
	
	const char temp_file[MAX_PATH_LEN] = "/sdcard/tmp/memtracer/param_pass.swp";
	FILE * fp = fopen(temp_file, "r");
	if(fp == NULL)
	{
		LOGE("Open %s to read parametes failed, error: %s\n", temp_file, strerror(errno));
		return -1;
	}

	fgets(g_target_so, sizeof(g_target_so), fp);
	post_process_str(g_target_so, sizeof(g_target_so));
	fgets(g_main_dir, sizeof(g_main_dir), fp);
	post_process_str(g_main_dir, sizeof(g_main_dir));

	LOGI("parameters read out, target: %s, exec path: %s\n", g_target_so, g_main_dir);

	fclose(fp);
	return 0;
}

// Listening one socket port for control command
void * command_listener(void * params)
{
	LOGI("MemTracer Command Listener Thread Started!");

	int sockfd = socket(PF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0)
	{
		LOGE("ERROR: Create Local Socket Failed!");
		return NULL;
	}

	struct sockaddr_in servaddr;
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(g_socket_port);

	if(bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
	{
		LOGE("Bind Local Listening socket Failed!");
		return NULL;
	}

	char recvbuff[128];
	char sendbuff[1024];
	struct sockaddr_in peeraddr;
	socklen_t peerlen;
	int n;

	while(1)
	{
		memset(recvbuff, 0, sizeof(recvbuff));
		n = recvfrom(sockfd, recvbuff, sizeof(recvbuff), 0, (struct sockaddr *)&peeraddr, &peerlen);

		if(n > 0) {
			recvbuff[n] = 0;
			LOGI("Received Command: %s\n", recvbuff);
			int retlen = 0;
			switch(recvbuff[0])
			{
				case 's':
					// Start Record Memory Malloc
					retlen = start_memtrace(sendbuff, sizeof(sendbuff));
					break;
				case 'e':
					retlen = stop_memtrace(sendbuff, sizeof(sendbuff));
					break;
				case 'd':
					retlen = dump_leaked_memory(sendbuff, sizeof(sendbuff));
					break;
				case 'c':
					retlen = switch_simple_mode(sendbuff, sizeof(sendbuff));
					break;
				case 'b':
					retlen = switch_backtrace_mode(sendbuff, sizeof(sendbuff));
					break;
				case 'r':
					retlen = reset_memtracer(sendbuff, sizeof(sendbuff));
					break;
				default:
					retlen = sprintf(sendbuff, "Invalid Command: %c, supported commands are:\n"
						" s[start], e[end], d[dump], c[simple mode switch], b[backtrace switch], r[reset]\n", recvbuff[0]);
					break;
			}

			sendto(sockfd, sendbuff, retlen, 0, (struct sockaddr *)&peeraddr, sizeof(peeraddr));
		}
	}

	return NULL;
}

/**
 * @description 对传入的字符串进行后期处理，移除不可见的空白字符
 */
void post_process_str(char * strbuf, int maxlen)
{
	int len = strlen(strbuf);
	int i = 0;
	for(i = 0; i < len && i < maxlen; i++)
	{
		if(strbuf[i] == '\r' || strbuf[i] == '\n' || strbuf[i] == ' ') 
		{
			strbuf[i] = 0;
			return;
		}
	}
	strbuf[i] = 0;
}

/**
 * @description 改变地址的权限为可读可写可执行
 * @param IN 地址 
 * @return 返回0即成功，-1即失败
 */

int change_addr_to_rwx(uint32_t addr)
{
	uint32_t pagesize = sysconf(_SC_PAGESIZE);
	uint32_t pagestart = addr & (~(pagesize-1));
	int nRet = mprotect((void *) pagestart, (pagesize), PROT_READ | PROT_WRITE | PROT_EXEC);
	if(nRet == -1)
    {
        LOGE("[-] mprotect error");
        return -1;
    }
    return 0;
}

/**
 * @description 往给定32位地址写数值
 * @param IN 地址 
 * @param IN 数据
 * @return 返回0即成功，-1即失败
 */

int write_data_to_addr(uint32_t addr, uint32_t value)
{
	LOGI("[+] modify start,addr is %08x,value is %08x", addr, value);
	int nRet = change_addr_to_rwx(addr);
	if(-1 == nRet)
	{
		LOGE("[-] write_data_to_addr error");
		return -1;
	}
    *(uint32_t *)(addr) = value ;
    LOGI("[+] modify completed,addr is %08x,value is %08x", addr, value);
    return 0;
}


/**
 * @description 获取模块基址
 * @param IN pid值，如果为-1，即获取自己的 
 * @param IN 模块名
 * @return 返回模块基址
 */

uint32_t get_module_base(pid_t pid, const char* module_name) 
{
	FILE *fp = NULL;
	uint32_t addr = 0;
	char *pAddrRange = NULL;
	char filename[32] = {0};
	char line[1024] = {0};

	if (pid < 0) 
	{
		snprintf(filename, sizeof(filename), "/proc/self/maps");
	} 
	else 
	{
		snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
	}
	fp = fopen(filename, "r");
	if (fp != NULL) 
	{
		while (fgets(line, sizeof(line), fp)) 
		{
			if (strstr(line, module_name))
			{
				pAddrRange = strtok(line, "-");
				addr = strtoul(pAddrRange, NULL, 16);
				if (addr == 0x8000)
				{
					addr = 0;
				}
				break;
			}
		}
		fclose(fp);
	}
	return addr;
}

/**
 * @param 文件指针
 * @return stringtable的首地址
 */
char *GetElf32StringTabBaseFromfile(FILE *fp)
{
	Elf32_Ehdr Elf32_ElfHeader;
	memset(&Elf32_ElfHeader,0, sizeof(Elf32_ElfHeader));

	Elf32_Shdr Elf32_SectionHeader;
	memset(&Elf32_SectionHeader,0, sizeof(Elf32_SectionHeader));

	int iShstrtabOffset = 0;
	char *pStringTab = NULL;

	//获取ELF头
	fseek(fp, 0, SEEK_SET);
	fread(&Elf32_ElfHeader, sizeof(Elf32_ElfHeader), 1, fp);

	//获取Section中字符串Tab的位置
	iShstrtabOffset = Elf32_ElfHeader.e_shoff + Elf32_ElfHeader.e_shstrndx * Elf32_ElfHeader.e_shentsize;
	fseek(fp, iShstrtabOffset, SEEK_SET);
	fread(&Elf32_SectionHeader, sizeof(Elf32_SectionHeader), 1, fp);

	//获取字符串表的起始地址
	pStringTab = (char *)malloc(Elf32_SectionHeader.sh_size);
	if(NULL == pStringTab)
	{
		LOGE("[-] GetElf32ShdNameByNameOff malloc Elf32_SectionHeader fail.");
		return NULL;
	}
	fseek(fp, Elf32_SectionHeader.sh_offset, SEEK_SET);
	fread(pStringTab, Elf32_SectionHeader.sh_size, 1, fp);
	LOGI("[+] GetElf32StringTabBaseFromfile done, pStringTab is %p",pStringTab);
	return pStringTab;
}

/**
 * @description 获取Got表的首地址和size
 * @param IN 文件指针 
 * @param OUT Got表静态首地址 
 * @param OUT Got表的size
 * @return 错误返回 -1
 */
int GetGotStartAddrAndSize(FILE *fp, uint32_t *GotTableStartaddr, uint32_t *GotTableSize)
{
	const char szGotTableName[] = ".got";

	Elf32_Ehdr Elf32_ElfHeader;
	memset(&Elf32_ElfHeader, 0, sizeof(Elf32_ElfHeader));

	fseek(fp, 0, SEEK_SET);
	fread(&Elf32_ElfHeader, sizeof(Elf32_ElfHeader), 1, fp);

	char *pStringTableStartOff = NULL;
	pStringTableStartOff = GetElf32StringTabBaseFromfile(fp);

	if(NULL == pStringTableStartOff)
	{
		LOGE("[-] GetGotStartAddrAndSize get pStringTableStartOff fail.");
		return -1;
	}

	Elf32_Shdr Elf32_SectionHeader;
	memset(&Elf32_SectionHeader, 0, sizeof(Elf32_SectionHeader));

	fseek(fp, Elf32_ElfHeader.e_shoff, SEEK_SET);

	int i;
	for(i = 0; i < Elf32_ElfHeader.e_shnum; ++i)
	{
		fread(&Elf32_SectionHeader, Elf32_ElfHeader.e_shentsize, 1, fp);

		//LOGI("Section Name Index: %d, Name: %s\n", Elf32_SectionHeader.sh_name, pStringTableStartOff + Elf32_SectionHeader.sh_name);

		if((Elf32_SectionHeader.sh_type == SHT_PROGBITS)&&
			0 == strncmp(szGotTableName, pStringTableStartOff + Elf32_SectionHeader.sh_name, sizeof(szGotTableName)))
		{
			*GotTableStartaddr = Elf32_SectionHeader.sh_addr;
			*GotTableSize = Elf32_SectionHeader.sh_size;
		}
	}
	free(pStringTableStartOff);
	LOGI("[+] GetGotStartAddrAndSize done");

	return 0;
}

//解析要寻找GOT位置的so文件
int parse_target_library(const char *TargetDir, const char *TargetSoName)
{
	if(NULL == TargetDir)
	{
		LOGE("[-] TargetDir is NUll.");
		return -1;
	}

	if(NULL == TargetSoName)
	{
		LOGE("[-] TargetSoName is NUll.");
		return -1;
	}

	char filepath[256] = {0};
	snprintf(filepath, sizeof(filepath), "%s/%s", TargetDir, TargetSoName);

	FILE * file = fopen(filepath, "rb");
	if(NULL == file)
	{
		LOGE("[-] do_got_hook open file fail: %s, error: %s", filepath, strerror(errno));
		return -1;
	}
	int nRet = GetGotStartAddrAndSize(file, &g_GotTableStartaddr, &g_GotTableSize);
	if(-1 == nRet)
	{
		LOGE("[-] GetGotStartAddrAndSize fail.");
		return -1;
	}
	LOGI("[+] uiGotTableStartaddr is %08x\n",g_GotTableStartaddr);
	LOGI("[+] uiGotTableSize is %08x\n",g_GotTableSize);

	g_base = get_module_base(-1, TargetSoName);
	interpret_mmaps();

	fclose(file);
	return 0;
}

/**
 * @description GotHook接口
 * @param IN 目标目录
 * @param IN 模块名字
 * @param IN 要Hook的symbol地址
 * @param IN 新函数地址
 * @param OUT 旧函数存放的地址
 * @return 失败返回 -1
 */
int do_got_hook(void *symbol, void *new_function, void **old_function)
{
	if(symbol == NULL) 
	{
		LOGE("do_got_hook symbol is NULL");
		return -1;
	}

	if(new_function == NULL)
	{
		LOGE("do_got_hook new_function is NULL");
		return -1;
	}

	int bHaveFoundTargetAddr = 0, i;
	for(i = 0; i < g_GotTableSize; i = i + 4)
	{
		if(*(uint32_t *)(g_base + g_GotTableStartaddr + i) == (uint32_t)symbol)
		{
			//保存旧值赋新值
			*old_function = symbol;

			LOGI("[+] the addr of old_function is: %p",symbol);
			LOGI("[+] the addr of new_function is: %p",new_function);
			//修改地址写权限，往地址写值
			write_data_to_addr(g_base + g_GotTableStartaddr + i, (uint32_t)new_function);
			LOGI("[+] modify done. it is point to addr : %08x",
				 *(uint32_t *)(g_base + g_GotTableStartaddr + i));

			bHaveFoundTargetAddr = 1;
			break;
		}
	}
	if(1 == bHaveFoundTargetAddr)
	{
		LOGI("[+] do_got_hook done");
	}
	else
	{
		LOGE("[-] do_got_hook fail, could not find symbol in got");
	}	

	return 0;
}

