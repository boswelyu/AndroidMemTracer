#include <stdio.h>
#include <stdlib.h>
#include <unwind.h>
#include <errno.h>
#include <utils/logger.h>
#include <memtracer.h>
#include <strings.h>

// Forward declare of internal function
void dump_content(char * content, int dumptofile);
void add_map_element(unsigned int startaddr, unsigned int endaddr, char * libname);
void dump_backtrace(unsigned int addr, char * buffer, int maxlen);
char * find_last(char * str, char ch);

// ========== 记录函数调用序列 ==========
typedef struct backtraceState
{
    void** current;
    void** end;
}BacktraceState;

typedef struct mmap_element
{
    unsigned int startAddr;
    unsigned int endAddr;
    char libName[128];
}MMapDataCell;

static _Unwind_Reason_Code unwind_callback(struct _Unwind_Context* context, void* arg)
{
    BacktraceState* state = (BacktraceState*)arg;
    void * pc = (void *)_Unwind_GetIP(context);
    if (pc) {
        if (state->current == state->end) {
            return _URC_END_OF_STACK;
        } else {
            *state->current++ = pc;
        }
    }
    return _URC_NO_REASON;
}


size_t capture_backtrace(void** buffer)
{
    BacktraceState state = {buffer, buffer + MAX_DEPTH - 1};
    _Unwind_Backtrace(unwind_callback, &state);
    size_t depth = state.current - buffer;

    return depth;
}

// =============================================================================

void ** g_blocks_ptr = NULL;
int     g_block_count = 0;
int     g_block_index = 0;

int     g_traced_count = 0;

// External Control flags
int     g_trace_enabled = 0;
// 简易模式：只记录数值，不记录BT
int     g_simple_mode = 0;
int     g_trace_func_call = 1;

// 存储链接库地址范围
MMapDataCell * g_mmaps_data;
int     g_mmaps_cap = 128;
int     g_mmaps_count = 0;


char dump_file_name[128] = "/sdcard/tmp/memtracer/check_result.txt";
FILE * memtrace_file = NULL;

void * (*original_malloc)(size_t size);

int memtracer_init(int size)
{
    original_malloc = malloc;
    g_blocks_ptr = (void* *)malloc(sizeof(void *) * size);
    if(g_blocks_ptr == NULL) {
        LOGE("Allocate Memory For CtrlBlockState array Failed!");
        return -1;
    }

    memtrace_file = fopen(dump_file_name, "w");
    if(memtrace_file == NULL) {
        LOGE("Create memtrace dump file %s failed, errno: %d, info: %s\n", dump_file_name, errno, strerror(errno));
    }

    memset(g_blocks_ptr, 0, sizeof(void *) * size);

    g_block_count = size;
    g_block_index = 0;

    g_traced_count = 0;

    g_mmaps_data = (MMapDataCell *)malloc(sizeof(MMapDataCell) * g_mmaps_cap);
    memset(g_mmaps_data, 0, sizeof(MMapDataCell) * g_mmaps_cap);
    g_mmaps_count = 0;

    return 0;
}

// 重新开始内存跟踪，清理掉已经跟踪到的内存
int reset_memtracer(char * feedback, int maxlen)
{
    memset(g_blocks_ptr, 0, sizeof(void *) * g_block_count);
    g_block_index= 0;
    g_traced_count = 0;
    return snprintf(feedback, maxlen, "Memtracer Reset Done");
}

// 遍历mmaps，解析并存储每一个动态链接库的地址映射范围和名字，同一个名字可能会存储多次
void interpret_mmaps()
{
    char line[1024];
    char buff[128];
    FILE * fp = fopen("/proc/self/maps", "r");

    extern void post_process_str(char * strbuf, int maxlen);

    if (fp != NULL) 
    {
        while (fgets(line, sizeof(line), fp)) 
        {
            if (strstr(line, ".so"))
            {
                char * fmins = index(line, '-');
                strncpy(buff, line, fmins - line);
                buff[fmins - line] = 0;
                unsigned int startaddr = strtoul(buff, NULL, 16);

                char * fspace = index(line, ' ');
                strncpy(buff, fmins + 1, fspace - fmins - 1);
                buff[fspace - fmins - 1] = 0;
                unsigned int endaddr = strtoul(buff, NULL, 16);

                char * libname = find_last(line, ' ');
                if(libname != NULL) {
                    post_process_str(libname, strlen(libname));
                    add_map_element(startaddr, endaddr, libname);
                }
                else {
                    LOGE("Parse lib name failed: %s", line);
                }
            }
        }
        fclose(fp);
    }
}

int get_control_block()
{
    int curr_index = g_block_index;
    if(g_blocks_ptr[curr_index] == NULL)
    {
        return curr_index;
    }
    else {
        for(curr_index = (curr_index + 1) % g_block_count; curr_index != g_block_index; curr_index = (curr_index + 1) % g_block_count)
        {
            if(g_blocks_ptr[curr_index] == NULL)
            {
                return curr_index;
            }
        }
    }

    // No Available Controll Block Found
    return -1;
}

void * trace_calloc(size_t blocks, size_t size, void * (*orig_calloc)(size_t blocks, size_t size), void * (orig_malloc)(size_t len))
{
    if(g_trace_enabled == 0)
    {
        return orig_calloc(blocks, size);
    }

    if(g_simple_mode == 1)
    {
        g_traced_count++;
        return orig_calloc(blocks, size);
    }

    void * ptr = trace_malloc(blocks * size, orig_malloc);
    memset(ptr, 0, blocks * size);

    return ptr;
}

// 跟踪所有已经分配的内存
void * trace_malloc(size_t size, void * (*orig_malloc)(size_t len))
{
    if(g_trace_enabled == 0)
    {
        // Record Not started Yet
        return orig_malloc(size);
    }

    if(g_simple_mode == 1) {
        // 简易模式，只记录数值，不增加跟踪控制块
        g_traced_count++;
        return orig_malloc(size);
    }

    void * buffer[MAX_DEPTH];
    int bt_depth = 0;
    if(g_trace_func_call != 0) {
        bt_depth = capture_backtrace(buffer);
    }

    int free_block_index = get_control_block();
    if(free_block_index < 0) {
        // No Free block could be used
        LOGW("======= No Free Block Available =========");
        return orig_malloc(size);
    }

    size_t newsize = size + sizeof(MemControlBlock);
    void * addr = orig_malloc(newsize);

    // 填充COntrolBlock信息
    MemControlBlock * ctrlBlock = (MemControlBlock *)addr;
    ctrlBlock->preholder = 0;
    ctrlBlock->block_index = free_block_index;
    ctrlBlock->size = size;
    ctrlBlock->magic_num1 = MAGIC_NUM;
    ctrlBlock->magic_num2 = MAGIC_NUM;
    ctrlBlock->postholder = 0;

    // 填充ControlBlock的信息
    if(g_trace_func_call != 0) {
        memcpy(ctrlBlock->backtrace, buffer + 2, (bt_depth - 2) * sizeof(void *));
        ctrlBlock->bt_depth = bt_depth - 2;

        // LOGI("-- Allocate %d(%d) bytes, btdepth: %d", newsize, size, bt_depth);
        // int i = 0;
        // for(i = 0; i < bt_depth; i++)
        // {
        //     LOGI("      BT: %p", buffer[i]);
        // }
    }
    
    char * retaddr = (char *)addr + sizeof(MemControlBlock);
    g_blocks_ptr[free_block_index] = retaddr;

    g_traced_count++;

    //LOGI("Memory Traced, Return Address: %p, Actual Malloced: %p", retaddr, addr);

    return (void *)retaddr;
}



void * trace_realloc(void *ptr, size_t size, void *(*orig_realloc)(void * ptr, size_t size), 
    void *(*orig_malloc)(size_t len), void (*orig_free)(void * addr))
{
    if(ptr == NULL)
    {
        return trace_malloc(size, orig_malloc);
    }

    if(size == 0)
    {
        trace_free(ptr, orig_free);
        return NULL;
    }

    void * realaddr = (void *)((char *)ptr - sizeof(MemControlBlock));
    MemControlBlock * ctrl_ptr = (MemControlBlock *)(realaddr);
    if(ctrl_ptr->magic_num1 != MAGIC_NUM || ctrl_ptr->magic_num2 != MAGIC_NUM)
    {
        // Not trace malloc or calloc allocated memory
        return orig_realloc(ptr, size);
    }

    void * newaddr = orig_realloc(realaddr, size + sizeof(MemControlBlock));

    if(newaddr == NULL)
    {
        LOGE("Reallocate Failed With size: %d + %d", size, sizeof(MemControlBlock));
    }
    else
    {
        MemControlBlock * ctrl_block = (MemControlBlock *)newaddr;
        ctrl_block->size = size;

        if(newaddr != realaddr)
        {
            int block_index = ctrl_block->block_index;

            if(block_index >= 0 && block_index < g_block_count)
            {
                if(g_blocks_ptr[block_index] == realaddr)
                {
                    g_blocks_ptr[block_index] = newaddr;
                    LOGI("New Reallocated address: %p", newaddr);
                }
                else
                {
                    LOGE("Address error in realloc, block index: %d, recoreded address: %p, real address: %p",
                        block_index, g_blocks_ptr[block_index], realaddr);
                }
            }
            else 
            {
                LOGE("Invalid block index in realloc: %d", block_index);
            }
        }
    }
    void * retaddr = (void *)((char *)newaddr + sizeof(MemControlBlock));
    return retaddr;
}

int is_valid_address(void * addr)
{
    if((unsigned int)addr >= 0x10000000)
    {
        return 1;
    }
    return 0;
}

// 记录已经释放的内存
void trace_free(void * ptr, void (*orig_free)(void * addr))
{
    // TODO: Check if address is valid
    char * trace_addr = (char *)ptr - sizeof(MemControlBlock);
    MemControlBlock * ctrl_block = (MemControlBlock *)trace_addr;

	if( ctrl_block->magic_num1 != MAGIC_NUM || ctrl_block->magic_num2 != MAGIC_NUM ) 
    {
        if(g_simple_mode == 1) {
            g_traced_count--;
        }
        orig_free(ptr);
    }
    else
    {
        if(ctrl_block->preholder != 0) {
            LOGE("+++++++++++++ Memory overflow detected +++++++++++");
        }
        if(ctrl_block->postholder != 0) {
            LOGE("+++++++++++++ This block of memory has overflow +++++++++++");
        }

        int block_index = ctrl_block->block_index;
        if(block_index >= 0 && block_index < g_block_count) {
            if(g_blocks_ptr[block_index] == ptr) {
                g_blocks_ptr[block_index] = NULL;
                g_traced_count--;
            }
        }
        else {
            LOGE("ERROR: Invalid Control Block Index: %d", block_index);
        }
        
        if(is_valid_address((void *)trace_addr)) {
            orig_free((void *)trace_addr);
        }
    }

}

int start_memtrace(char * feedback, int maxlen)
{
    g_trace_enabled = 1;
    return snprintf(feedback, maxlen, "Memory Trace Started");
}

int stop_memtrace(char * feedback, int maxlen)
{
    g_trace_enabled = 0;
    return snprintf(feedback, maxlen, "Memory Trace Ended");
}

int switch_simple_mode(char * feedback, int maxlen)
{
    if(g_simple_mode == 0) {
        g_simple_mode = 1;
        return snprintf(feedback, maxlen, "Simple Mode Enabled");
    }
    else {
        g_simple_mode = 0;
        return snprintf(feedback, maxlen, "Simple Mode Disabled");
    }
}

int switch_backtrace_mode(char * feedback, int maxlen)
{
    if(g_trace_func_call == 1) {
        g_trace_func_call = 0;
        return snprintf(feedback, maxlen, "Backtrace will NOT be recorded");
    }
    else {
        g_trace_func_call = 1;
        return snprintf(feedback, maxlen, "Backtrace Record Enabled");
    }
}

int dump_leaked_memory(char * feedback, int maxlen)
{
    char formatbuffer[256];
    
    if(g_blocks_ptr == NULL || g_block_count == 0) {
        return snprintf(feedback, maxlen, "Memory Tracer Not Inited or inited with 0 size");
    }

    int dumptofile = 1;
    if(memtrace_file == NULL) {
        dumptofile = 0;
    }


    if(g_traced_count == 0) {
        return snprintf(feedback, maxlen, "Good! No Memory Leak!");
    }

    if(g_simple_mode == 1) {
        return snprintf(feedback, maxlen, "Simple Mode Enabled, %d blocks of memory leak recorded\n", g_traced_count);
    }

    sprintf(formatbuffer, "==== %d blocks of memory leak detected ======\n", g_traced_count);
    dump_content(formatbuffer, dumptofile);
    int i, j, counter = 0;
    for(i = 0; i < g_block_count; i++) 
    {
        if(g_blocks_ptr[i] != NULL) {

            MemControlBlock * ctrlBlock = (MemControlBlock *)((char *)g_blocks_ptr[i] - sizeof(MemControlBlock));
            sprintf(formatbuffer, "    Memory Leaked at:%p, leaked size:%d, bt depth: %d\n", 
                g_blocks_ptr[i], ctrlBlock->size, ctrlBlock->bt_depth);
            dump_content(formatbuffer, dumptofile);

            if(ctrlBlock->postholder != 0)
            {
                sprintf(formatbuffer, "************** Memory Underflowed **************");
                dump_content(formatbuffer, dumptofile);
            }

            if(ctrlBlock->preholder != 0)
            {
                sprintf(formatbuffer, "************** Detected other Memory Overflow **************");
                dump_content(formatbuffer, dumptofile);
            }

            if(ctrlBlock->bt_depth > MAX_DEPTH) 
            {
                sprintf(formatbuffer, "************* Memory Control Block Destroied ***************");
                dump_content(formatbuffer, dumptofile);
            }
            for(j = 0; j < ctrlBlock->bt_depth && j < MAX_DEPTH; j++)
            {
                dump_backtrace((unsigned int)ctrlBlock->backtrace[j], formatbuffer, sizeof(formatbuffer));
                dump_content(formatbuffer, dumptofile);
            }
            counter++;
        }
    }

    LOGI("Recorded Counter: %d, Looped Counter: %d\n", g_traced_count, counter);

    if(dumptofile) {
        fflush(memtrace_file);

        return snprintf(feedback, maxlen, ">> %d blocks of memory leak detected, details dumped to file %s", g_traced_count, dump_file_name);
    }

    return snprintf(feedback, maxlen, ">> %d blocks of memory leak detected, details dumped to logcat.", g_traced_count);
}

void dump_content(char * content, int dumptofile)
{
    if(dumptofile == 1) {
        fputs(content, memtrace_file);
    }
    else {
        LOGI("%s", content);
    }
}

void add_map_element(unsigned int startaddr, unsigned int endaddr, char * libname)
{
    int i = 0;
    for(i = 0; i < g_mmaps_count; i++)
    {
        MMapDataCell * cellptr = g_mmaps_data + i;
        if(strcmp(cellptr->libName, libname) == 0) {
            if(startaddr < cellptr->startAddr) {
                cellptr->startAddr = startaddr;
            }
            if(endaddr > cellptr->endAddr) {
                cellptr->endAddr = endaddr;
            }
            return;
        }
    }

    if(g_mmaps_count >= g_mmaps_cap) 
    {
        // Increase the cap of mmaps
        MMapDataCell * newptr = (MMapDataCell *)original_malloc(sizeof(MMapDataCell) * (g_mmaps_cap + 128));
        if(newptr == NULL)
        {
            LOGE("Allocate memory to increase MMapCell size failed\n");
            return;
        }

        memcpy(newptr, g_mmaps_data, sizeof(MMapDataCell) * g_mmaps_count);
        free(g_mmaps_data);
        g_mmaps_data = newptr;
        g_mmaps_cap += 128;
    }

    MMapDataCell * cellptr = g_mmaps_data + g_mmaps_count;
    cellptr->startAddr = startaddr;
    cellptr->endAddr = endaddr;
    strncpy(cellptr->libName, libname, 128);
    g_mmaps_count++;
}

// Check which library the given address comes from
void dump_backtrace(unsigned int addr, char * buffer, int maxlen)
{
    int i = 0;
    for(i = 0; i < g_mmaps_count; i++) {
        MMapDataCell * cellptr = g_mmaps_data + i;

        if(addr >= cellptr->startAddr && addr <= cellptr->endAddr)
        {
            snprintf(buffer, maxlen, "        %p   %s\n", (void *)(addr - cellptr->startAddr), cellptr->libName);
            return;
        }
    }

    snprintf(buffer, maxlen, "      %p  Unknown\n", (void *)addr);
}

char * find_last(char * str, char ch)
{
    int len = strlen(str);
    int index;
    for(index = len - 1; index >= 0; index--)
    {
        if(str[index] == ch) {
            return &str[index + 1];
        }
    }
    return NULL;
}