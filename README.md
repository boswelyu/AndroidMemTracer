# AndroidMemTracer
One tool which can help find out memory leaks on any dynamics library of your android application, without any change or re-complie on your application.

The initial purpose of this tool is help find out memory leaks from Games which made by Unity (enabled il2cpp feature). But it also can be used for cocos2d games, which has all the game logic in libcocos2dcpp.so, or any application used dynamic library.

On Unity, the game logic is write by C#, Unity engine will translate the C# code to cpp via il2cpp technology, and complier the cpp code into libil2cpp.so. Since C# uses automatic GC collect to manage it's memory, in theory, C# developer don't need to worry about memroy leak at all, since all the garbage should be collected automatically, and Unity should release all memory when switch scenes.

But unfortunately, we still observed the memory usage keep increase during game play, each time we switched between battle scene and main UI scene, there are always something could not be released. 

To find out where the leaked memory comes from, I made this tool. it will trace blocks of leaked momory on the generated CPP code level. so it should be accurate to find all of them out.

    Ihis tool uses ptrace inject technology to replace the malloc, calloc, realloc and free functions by the replaced one, in which we trace all the memory allocate and free actions. One commander tool is used to control the time of start and stop collection of memory usage. 
    The general procedure of using this tool will be:
    1. start up the application you want to tested, and find out the PID of the application (by top or ps command);
    2. Go to memtracer path, put one copy of your target dynamic library file to the root directory of memtracer (/data/local/memtracer) 
    3. start up memtrace with target PID and target library name (./memtrace -p PID -t libxxxx.so)
    4. According to the hint, press commands: s[start], e[end], d[dump], c[simple mode switch], b[backtrace switch], r[reset]
    4. run your test cases;
    5. press e to end memory collection
    6. press d to dump the memory trace result;
    7. check your logcat or memory trace output file to find out leaked memory blocks
    8. use addr2line or other tools to figure out where the leaked memory comes from.
    
    
Known Issues:
    1. Each time the memtracer just started, the first command can not got the feedback from target process, still debuging
    2. Originally, the parameter pass from injector to libmemtracer used temp file, but I found for some application, access to the temp file may be denied. will change the parameter pass method to avoid permission issue.