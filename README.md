# vita-core-dump
PlayStation Vita core dump analyser

Core dump files are generated by the PlayStation Vita OS when a program crashes. They are stored in the `ux0:/data/` directory.
This tool can be used to analyse them to understand the cause of the crash once they have been copied to a computer.

## Usage
```sh
vita-core-dump <core-dump-path> <command> [<arguments>]
```
The available commands are:
* `backtrace`: Print a backtrace for one or more threads
* `memory`: Print raw memory
* `modules`: Print the list of loaded modules
* `stack`: Print the stack for one or more threads
* `threads`: Print the list of threads

### The `backtrace` command
```sh
vita-core-dump <core-dump-path> backtrace [--add-elf=<elf-path>[:<hex-load-address>]]
         [--thread=(<thread-index>|all|crashed)] [--show-locals] [--show-registers]
```
Displays a backtrace for one or all of the threads of the process that generated
the core dump. The default is to display only the thread that caused the crash:
```
$ vita-core-dump psp2core-1658050394-0x003179256b-eboot.bin.psp2dmp backtrace \
                                            --add-elf so_loader               \
                                            --add-elf libChowdren.so:98000000
Thread 6: (Running) - Data abort exception at PC 0x8118f47e reading memory at 0x00000008
  0x8114847e      (so_loader): in _free_r+0xc9
  0x81147589      (so_loader): in _fclose_r.part.0+0x5c
  0x001b9f1b (libChowdren.so): in BaseFile::~BaseFile()+0x6
  0x00369a71 (libChowdren.so): in TileMap::load_file()+0x1f0
  0x00245c1f (libChowdren.so): in Frames::event_func_229()+0x1e2
  0x00247597 (libChowdren.so): in Frames::loop_load_0()+0x22
  0x00249a5b (libChowdren.so): in Frames::event_func_309()+0x26
  0x0024a263 (libChowdren.so): in Frames::loop_new_0()+0x46
  0x002aa07b (libChowdren.so): in Frames::event_func_1799()+0x9a
  0x0030eccb (libChowdren.so): in Frames::handle_frame_1_events()+0x7ec
  0x001dc8f9 (libChowdren.so): in Frame::update()+0xc4
  0x001cb7cb (libChowdren.so): in GameManager::update_frame()+0xa6
  0x001cbc2b (libChowdren.so): in GameManager::update()+0x25e
  0x001cbd61 (libChowdren.so): in GameManager::run()+0x8
  0x001cc08d (libChowdren.so): in SDL_main+0xc
  0x8100081f      (so_loader): in game_main+0x43 at main.c:117
  0x810b9e6b      (so_loader): in pte_threadStart+0x33 at pte_threadStart.c:116
  0xe000f039   (SceLibKernel): ??
Unable to unwind: No binary for module SceLibKernel
```

The `backtrace` command uses the Call Frame Information present in the executable to reliably unwind the stack from the stack pointer position.
It can use either Dwarf CFI (`.eh_frame` or `.debug_frame` elf sections) or ARM runtime exception handling CFI (`.ARM.exidx` and `.ARM.extab` elf sections).
Dwarf CFI is produced with debug builds (the `-g` compiler flag). ARM runtime CFI is produced by default when building C++ code with exceptions enabled.
It can otherwise be enabled with `-funwind-tables`.

It is recommended to use debug builds without optimizations so `vita-core-dump` can display richer information such as function names, line numbers and local variables:
`CFLAGS=-Og -g`.

Error conditions:
| Error message | Explanation   |
| ------------- | ------------- |
| Could not find a core dump module named 'my_game' | Prefer loading SCE elf files (often with the `.velf` extension) as they specify their module name. Otherwise, the name of the elf file must match the corresponding module. Use the `modules` command to see the core dump's module table. |
| Unable to unwind: No binary for module 'my_game' | The binary for the module `my_game` was not found. You can load more binaries by using the `--add-elf` argument. At the moment it is not possible to load Sony's `.prx` modules. |
| Failed to unwind: No CFI information at PC 0xnnnnnnnn | The code for this frame was compiled without Call Frame Information. Recompile the game / library with debug information (`-g`). |
| Unable to unwind: No module for PC 0xnnnnnnnn | Execution reached an address that is not described in the core dump's modules table. You can use `--add-elf` with the load address set to declare executable memory areas not known to the Vita OS. |
| Failed to unwind: Failed to read memory at 0xnnnnnnnn | The memory area containing the stack for this thread is not available in the core dump. Computing the backtrace is not possible. |

### The `memory` command
```sh
vita-core-dump <core-dump-path> memory <hex-address> [--length=<bytes-to-print>]
```
Displays a hex dump of the crashed process's memory at the specified address. This is useful to investigate the memory at addresses displayed by
the other commands.
```
$ ./vita-core-dump ../test8/psp2core.bin.psp2dmp memory 812c0ed8 --length=6
812c0ed8: 68 65 6c 6c  6f 00    |hello. |
```

### The `modules` command
```sh
vita-core-dump <core-dump-path> modules
```
Displays a list of all of the crashed process's loaded modules:
```
$ vita-core-dump psp2core-1658050394-0x003179256b-eboot.bin.psp2dmp modules
Module 0: SceLibKernel
  Start address: 0xe000e900
  Size:          116888

...

Module 15: so_loader
  Start address: 0x81047000
  Size:          5579412

```

### The `stack` command
```sh
vita-core-dump <core-dump-path> stack [--add-elf=<elf-path>[:<hex-load-address>]]
         [--thread=(<thread-index>|all|crashed)] [--length=<addresses-to-print>]
```
Displays the values on the stack of one or more thread near the stack pointer:
```
$ vita-core-dump psp2core-1658050394-0x003179256b-eboot.bin.psp2dmp stack     \
                                            --add-elf so_loader               \
                                            --add-elf libChowdren.so:98000000
Thread 6: (Running) - Data abort exception at PC 0x8118f47e reading memory at 0x00000008
      0x8f600de4: 0x8119149d  so_loader in __vita_duplicate_descriptor+0x20
      0x8f600de8: 0x815555d8  so_loader+0x8150e5d8
      0x8f600dec: 0x00000000  
      0x8f600df0: 0x00000000  
      0x8f600df4: 0x8118f3c3  so_loader in _fread_r+0x12e
  SP> 0x8f600df8: 0xa4000000  
      0x8f600dfc: 0x82bc72ac  
      0x8f600e00: 0x00000000  
      0x8f600e04: 0x81555eb0  so_loader+0x8150eeb0
      0x8f600e08: 0x8f600e28  
      0x8f600e0c: 0x8118e58d  so_loader in __vita_scenet_errno_to_errno+0x15c
      0x8f600e10: 0x8f600e48  
      0x8f600e14: 0x00000000  
      0x8f600e18: 0x8b5f23a8  
      0x8f600e1c: 0x981b9f1f  libChowdren.so in BaseFile::~BaseFile()+0xa
      0x8f600e20: 0x8bf3ce78  
      0x8f600e24: 0x8b5f23a8  
      0x8f600e28: 0x8f600e78  
      0x8f600e2c: 0x98369a71  libChowdren.so in TileMap::load_file()+0x1f0
      0x8f600e30: 0x81555634  so_loader+0x8150e634
      0x8f600e34: 0x00000003  
      0x8f600e38: 0x00000003  
      0x8f600e3c: 0x8b5f23ac  
      0x8f600e40: 0x8b5f22d8  
      0x8f600e44: 0x8f600e48  
```

### The `threads` command
```sh
vita-core-dump <core-dump-path> threads [--show-registers]
```
Displays a list of all of the crashed process's threads:
```
$ vita-core-dump psp2core-1658050394-0x003179256b-eboot.bin.psp2dmp threads
Thread 0: GAME (Ready) at PC 0xe0015004

...

Thread 17: SceFiosIO (Waiting) at PC 0xe0014ac4
```

## Acknowledgements
* The Vita core dump file parsing is based on [vita-parse-core](https://github.com/xyzz/vita-parse-core/) by xyz.
* The [elfutils](https://sourceware.org/elfutils/) library is used for Elf and Dwarf parsing.

