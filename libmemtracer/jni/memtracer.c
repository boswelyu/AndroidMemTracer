#include <stdio.h>
#include <stdlib.h>
#include <unwind.h>
#include <errno.h>
#include <utils/logger.h>
#include <memtracer.h>

// Forward declare of internal function
void dump_content(char * content, int dumptofile);

// ========== 记录函数调用序列 ==========
typedef struct backtraceState
{
    void** current;
    void** end;
}BacktraceState;

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
    BacktraceState state = {buffer, buffer + MAX_DEPTH};
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
int     g_trace_func_call = 1;

uint32_t g_base_addr;

char dump_file_name[128] = "/sdcard/tmp/memtracer/check_result.txt";
FILE * memtrace_file = NULL;

int memtracer_init(int size)
{
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

    g_base_addr = 0;

    return 0;
}

// 重新开始内存跟踪，清理掉已经跟踪到的内存
void reset_memtracer()
{
    memset(g_blocks_ptr, 0, sizeof(void *) * g_block_count);
    g_block_index= 0;
    g_traced_count = 0;
}

void memtracer_set_base(uint32_t addr)
{
    g_base_addr = addr;
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

// 跟踪所有已经分配的内存
void * trace_malloc(size_t size, void * (*orig_malloc)(size_t len))
{
    if(g_trace_enabled == 0)
    {
        // Record Not started Yet
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
    ctrlBlock->block_index = free_block_index;
    ctrlBlock->size = size;
    ctrlBlock->fix_magic_num = MAGIC_NUM;

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

// 记录已经释放的内存
void trace_free(void * ptr, void (*orig_free)(void * addr))
{
    // TODO: Check if address is valid
	if(*(unsigned int *)((char *)ptr - sizeof(unsigned int)) != MAGIC_NUM) 
    {
        // LOGI("Not Traced Memory, Use Original Free");
        orig_free(ptr);
    }
    else
    {
        char * trace_addr = (char *)ptr - sizeof(MemControlBlock);
        MemControlBlock * ctrl_block = (MemControlBlock *)trace_addr;
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
        
        orig_free((void *)trace_addr);
    }

}

int start_memtrace(char * feedback, int maxlen)
{
    reset_memtracer();
    g_trace_enabled = 1;

    return snprintf(feedback, maxlen, "Memory Trace Started");
}

int stop_memtrace(char * feedback, int maxlen)
{
    g_trace_enabled = 0;
    return snprintf(feedback, maxlen, "Memory Trace Ended");
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

            for(j = 0; j < ctrlBlock->bt_depth; j++)
            {
                sprintf(formatbuffer, "          %p\n", ctrlBlock->backtrace[j] - g_base_addr);
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