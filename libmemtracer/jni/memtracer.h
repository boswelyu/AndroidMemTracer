#ifndef _MEM_TRACER_H_
#define _MEM_TRACER_H_

#define MAX_DEPTH 16
#define MAGIC_NUM 0xABEFFEBA

typedef struct memCtrlBlock
{
    int block_index;
    int size;
    int bt_depth;
    int flag;
    void * backtrace[MAX_DEPTH];
    unsigned int fix_magic_num;
}MemControlBlock;

int memtracer_init(int size);

// 使用传入的分配函数分配内存，并跟踪
void * trace_malloc(size_t size, void*(*orig_malloc)(size_t s));


// 使用传入的释放函数释放内存
void trace_free(void * ptr, void (*orig_free)(void * addr));

void memtracer_set_base(uint32_t addr);

int start_memtrace();

int stop_memtrace();

int dump_leaked_memory();

#endif