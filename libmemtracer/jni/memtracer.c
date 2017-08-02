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
void record_valid_address(unsigned int startaddr, unsigned endaddr);
void dump_backtrace(unsigned int addr, char * buffer, int maxlen);
char * find_last(char * str, char ch);
void record_min_address(void *addr);
int get_free_index();

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

MemControlBlock * g_blocks_ptr = NULL;
unsigned int * g_free_ptrs = NULL;
int     g_block_count = 0;
int     g_block_index = 0;
int     g_traced_count = 0;

int     g_freed_index = 0;

// External Control flags
int     g_trace_enabled = 0;
// 简易模式：只记录数值，不记录BT
int     g_simple_mode = 0;
// 快速记录模式，记录所有的分配和释放，需要依靠线下工具分析泄露的内存块
int     g_qrecord_mode = 0;

int     g_trace_func_call = 1;

// 存储链接库地址范围
MMapDataCell * g_mmaps_data;
int     g_mmaps_cap = 128;
int     g_mmaps_count = 0;

// 有效地址范围
unsigned int g_lower_address = 0;
unsigned int g_upper_address = 0;

unsigned int g_min_addr = 0xFFFFFFFF;


char dump_file_name[128] = "/sdcard/tmp/memtracer/check_result.txt";
FILE * memtrace_file = NULL;

void * (*original_malloc)(size_t size);

int memtracer_init(int size)
{
    original_malloc = malloc;
    g_blocks_ptr = (MemControlBlock *)malloc(sizeof(MemControlBlock) * size);
    if(g_blocks_ptr == NULL) {
        LOGE("Allocate Memory For CtrlBlockState array Failed!");
        return -1;
    }
    memset(g_blocks_ptr, 0, sizeof(MemControlBlock) * size);

    g_free_ptrs = (unsigned int *)malloc(sizeof(unsigned int) * size);
    if(g_free_ptrs == NULL)
    {
        LOGE("Allocate Memory for Free Ptr array failed!");
        return -1;
    }
    memset(g_free_ptrs, 0, sizeof(unsigned int) * size);

    memtrace_file = fopen(dump_file_name, "w");
    if(memtrace_file == NULL) {
        LOGE("Create memtrace dump file %s failed, errno: %d, info: %s\n", dump_file_name, errno, strerror(errno));
    }

    g_block_count = size;
    g_block_index = 0;

    g_traced_count = 0;

    g_freed_index = 0;

    g_mmaps_data = (MMapDataCell *)malloc(sizeof(MMapDataCell) * g_mmaps_cap);
    memset(g_mmaps_data, 0, sizeof(MMapDataCell) * g_mmaps_cap);
    g_mmaps_count = 0;

    return 0;
}

// 重新开始内存跟踪，清理掉已经跟踪到的内存
int reset_memtracer(char * feedback, int maxlen)
{
    memset(g_blocks_ptr, 0, sizeof(MemControlBlock) * g_block_count);
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
            char * fmins = index(line, '-');
            strncpy(buff, line, fmins - line);
            buff[fmins - line] = 0;
            unsigned int startaddr = strtoul(buff, NULL, 16);

            char * fspace = index(line, ' ');
            strncpy(buff, fmins + 1, fspace - fmins - 1);
            buff[fspace - fmins - 1] = 0;
            unsigned int endaddr = strtoul(buff, NULL, 16);

            record_valid_address(startaddr, endaddr);
            if(strstr(line, ".so"))
            {
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
    if(g_blocks_ptr[curr_index].addr_ptr == NULL)
    {
        return curr_index;
    }
    else {
        for(curr_index = (curr_index + 1) % g_block_count; curr_index != g_block_index; curr_index = (curr_index + 1) % g_block_count)
        {
            if(g_blocks_ptr[curr_index].addr_ptr == NULL)
            {
                return curr_index;
            }
        }
    }

    // No Available Controll Block Found
    return -1;
}

int get_free_index()
{
    if(g_freed_index < g_block_count)
    {
        return g_freed_index;
    }
    return -1;
}

void * trace_calloc(size_t blocks, size_t size, void * (*orig_calloc)(size_t blocks, size_t size), void * (orig_malloc)(size_t len))
{
    void * retaddr;
    if(g_trace_enabled == 0)
    {
        retaddr = orig_calloc(blocks, size);
        record_min_address(retaddr);
        return retaddr;
    }

    if(g_simple_mode == 1)
    {
        g_traced_count++;
        retaddr = orig_calloc(blocks, size);
        record_min_address(retaddr);
        return retaddr;
    }

    void * ptr = trace_malloc(blocks * size, orig_malloc);
    memset(ptr, 0, blocks * size);

    return ptr;
}

// 跟踪所有已经分配的内存
void * trace_malloc(size_t size, void * (*orig_malloc)(size_t len))
{
    void * retaddr;
    if(g_trace_enabled == 0)
    {
        // Record Not started Yet
        retaddr = orig_malloc(size);
        record_min_address(retaddr);
        return retaddr;
    }

    if(g_simple_mode == 1) {
        // 简易模式，只记录数值，不增加跟踪控制块
        g_traced_count++;
        retaddr = orig_malloc(size);
        record_min_address(retaddr);
        return retaddr;
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

    void * addr = NULL;

    if(g_qrecord_mode == 0)
    {
        addr = orig_malloc(size + 4);
        if(addr == NULL)
        {
            LOGE("Allocate memory failed with size: %d\n", size);
            return NULL;
        }
        *(int *)addr = free_block_index;
        retaddr = (void *)((char *)addr + 4);
        record_min_address(addr);
    }
    else
    {
        // quick record mode, don't change memory layout, just record the allocated memory
        addr = orig_malloc(size);
        if(addr == NULL)
        {
            LOGE("Allocate memory failed in quick record mode with size: %d\n", size);
            return NULL;
        }
        retaddr = addr;
    }

    MemControlBlock * ctrlBlock = &g_blocks_ptr[free_block_index];
    ctrlBlock->addr_ptr = retaddr;
    ctrlBlock->size = size;
    ctrlBlock->bt_depth = 0;

    // 填充ControlBlock的信息
    if(g_trace_func_call != 0) {
        memcpy(ctrlBlock->backtrace, buffer + 2, (bt_depth - 2) * sizeof(void *));
        ctrlBlock->bt_depth = bt_depth - 2;
    }

    g_traced_count++;

    //LOGI("Memory Traced, Return Address: %p, Actual Malloced: %p", retaddr, addr);

    return retaddr;
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
        //trace_free(ptr, orig_free);
        return NULL;
    }

    void * retaddr;
    if(g_trace_enabled == 0)
    {
        retaddr = orig_realloc(ptr, size);
        record_min_address(retaddr);
        return retaddr;
    }

    if(g_qrecord_mode == 0)
    {
        if(address_within_range((void *)((char *)ptr - 4)) == 0)
        {
            retaddr = orig_realloc(ptr, size);
            record_min_address(retaddr);
            return retaddr;
        }

        int ctrlBlockIndex = *(int *)((char *)ptr - 4);
        if(ctrlBlockIndex < 0 || ctrlBlockIndex >= g_block_count)
        {
            retaddr = orig_realloc(ptr, size);
            record_min_address(retaddr);
            return retaddr;
        }

        MemControlBlock * ctrl_ptr = &g_blocks_ptr[ctrlBlockIndex];
        if(ctrl_ptr->addr_ptr != ptr)
        {
            // Not trace malloc or calloc allocated memory
            retaddr = orig_realloc(ptr, size);
            record_min_address(retaddr);
            return retaddr;
        }

        void * realaddr = (void *)((char *)ptr - 4);
        void * newaddr = orig_realloc(realaddr, size + 4);

        if(newaddr == NULL)
        {
            LOGE("Reallocate Failed With size: %d + 4", size);
        }
        else
        {
            record_min_address(newaddr);
            *(int *)((char *)newaddr) = ctrlBlockIndex;
            ctrl_ptr->addr_ptr = (void *)((char *)newaddr + 4);
            ctrl_ptr->size = size;
        }
        return (void *)((char *)newaddr + 4);
    }
    else
    {
        // quick record mode, if the reallocated memory different with original one, record one extra free
        void * buffer[MAX_DEPTH];
        retaddr = orig_realloc(ptr, size);
        int bt_depth = 0;

        if(retaddr != ptr)
        {
            if(g_trace_func_call != 0) {
                bt_depth = capture_backtrace(buffer);
            }
        }
        int free_block_index = get_control_block();
        if(free_block_index >= 0)
        {
            // Still have space to record malloc blocks
            MemControlBlock * ctrlBlock = &g_blocks_ptr[free_block_index];
            ctrlBlock->addr_ptr = retaddr;
            ctrlBlock->size = size;
            ctrlBlock->bt_depth = 0;

            // 填充ControlBlock的信息
            if(g_trace_func_call != 0) {
                memcpy(ctrlBlock->backtrace, buffer + 2, (bt_depth - 2) * sizeof(void *));
                ctrlBlock->bt_depth = bt_depth - 2;
            }

            // add one free record for old address
            int freed_index = get_free_index();
            if(freed_index < 0)
            {
                LOGE("No Space left to record freed memory address");
            }
            else
            {
                g_free_ptrs[freed_index] = (unsigned int)ptr;
                g_freed_index++;
            }
        }

        return retaddr;
    }
}

// 记录已经释放的内存
void trace_free(void * ptr, void (*orig_free)(void * addr))
{
    if(is_valid_address(ptr) != 1)
    {
        LOGE("Invalid Address to Free: %p\n", ptr);
        return;
    }

    if(address_within_range((void *)((char *)ptr - 4)) == 1)
    {
        int ctrlBlockIndex = *(int *)((char *)ptr - 4);
        if(ctrlBlockIndex < 0 || ctrlBlockIndex >= g_block_count)
        {
            if(g_simple_mode == 1) {
                g_traced_count--;
            }
            orig_free(ptr);
        }
        else
        {
            MemControlBlock * ctrl_block = &g_blocks_ptr[ctrlBlockIndex];
            if(ctrl_block->addr_ptr == ptr) {
                g_traced_count--;
                memset(ctrl_block, 0, sizeof(MemControlBlock));

                void * realaddr = (void *)((char *)ptr - 4);
                orig_free(realaddr);
            }
            else
            {
                if(g_simple_mode == 1)
                {
                    g_traced_count--;
                }
                orig_free(ptr);
            }
        }
    }
    else
    {
        if(g_simple_mode == 1) {
            g_traced_count--;
        }
        orig_free(ptr);
    }
}

int is_valid_address(void * addr)
{
    if(g_lower_address == 0 || g_upper_address == 0)
    {
        LOGE("Address Bound Not Set Correct");
        return 1;
    }

    if(g_min_addr != 0xFFFFFFFF)
    {
        if((unsigned int)addr >= g_min_addr && (unsigned int)addr <= g_upper_address)
        {
            return 1;
        }
    }
    else {
        if((unsigned int)addr >= 0x10000000 && (unsigned int)addr <= g_upper_address)
        {
            return 1;
        }
    }
    return 0;
}

int address_within_range(void * addr)
{
    if(g_min_addr == 0xFFFFFFFF)
    {
        return 1;
    }

    return (unsigned int)addr >= g_min_addr ? 1 : 0;
}

void record_min_address(void *addr)
{
    if((unsigned int)addr < g_min_addr)
    {
        g_min_addr = (unsigned int)addr;
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
        MemControlBlock * ctrlBlock = &g_blocks_ptr[i];        
        if(ctrlBlock->addr_ptr != NULL) {

            sprintf(formatbuffer, "    Memory Leaked at:%p, leaked size:%d, bt depth: %d\n", 
                ctrlBlock->addr_ptr, ctrlBlock->size, ctrlBlock->bt_depth);
            dump_content(formatbuffer, dumptofile);

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

void record_valid_address(unsigned int startaddr, unsigned endaddr)
{
    if(g_lower_address == 0)
    {
        g_lower_address = startaddr;
    }
    else
    {
        if(startaddr < g_lower_address)
        {
            g_lower_address = startaddr;
        }
    }

    if(g_upper_address == 0)
    {
        g_upper_address = endaddr;
    }
    else
    {
        if(endaddr > g_upper_address)
        {
            g_upper_address = endaddr;
        }
    }
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