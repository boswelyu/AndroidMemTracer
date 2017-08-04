#ifndef _MEM_TRACER_H_
#define _MEM_TRACER_H_

#define MAX_DEPTH 13
#define MAGIC_NUM 0xEFBACD89

typedef struct memCtrlBlock
{
    void * addr_ptr;
    int size;
    int bt_depth;
    void * backtrace[MAX_DEPTH];
}MemControlBlock;

int memtracer_init(int size);

// 使用传入的分配函数分配内存，并跟踪
void * trace_malloc(size_t size, void*(*orig_malloc)(size_t s));

void * trace_calloc(size_t blocks, size_t size, void * (*orig_calloc)(size_t blocks, size_t size), void * (*orig_malloc)(size_t len));

// 使用传入的释放函数释放内存
void trace_free(void * ptr, void (*orig_free)(void * addr));

void * trace_realloc(void *ptr, size_t size, 
	void *(*orig_realloc)(void * ptr, size_t size), void * (*orig_malloc)(size_t len), void (*orig_free)(void *addr));

void interpret_mmaps();

int reset_memtracer(char * feedback, int maxlen);

int start_memtrace(char * feedback, int maxlen);

int stop_memtrace(char * feedback, int maxlen);

int switch_simple_mode(char * feedback, int maxlen);

int switch_qrecord_mode(char * feedback, int maxlen);

int switch_backtrace_mode(char * feedback, int maxlen);

int dump_leaked_memory(char * feedback, int maxlen);

int is_valid_address(void * addr);

int address_within_range(void * addr);


#endif