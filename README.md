## Compile
1. clone this repository
2. execute command "gcc parsePE.c -o parsePE.exe"

## Usage
- parsePE.exe [PE 64bit executible]

## Sample Output
```
$ ./parsePE.exe test.exe

---------- In NT Header ----------
Signature:                 PE

---------- In File Header ----------
Characteristic:            34
Machine:                   -31132
Number of Sections:        13
Number of Symbols:         203
Pointer to Symbol Table:   0x11a00
Size of Optional Header:   240
Time Date Stamp:           1736426450

---------- In Optional Header ----------
Address of EntryPoint:     0x1350
Base of Code:              0x1000
CheckSum:                  0x0
DataDirectory:             0xIMAGE_DATA_DIRECTORY
DllCharacteristics:        0x8160
File Alignment:            0x200
Image Base:                0x140000000
Loader Flags:              0x0
Magic:                     0x20b
Major Image Version:       0x0
Major Linker Version:      0xe
Major Operating System Version: 0x6
Major Subsystem Version:   0x6
Minor Image Version:       0x0
Minor Linker Version:      0x0
Minor Operating System Version: 0x0
Minor Subsystem Version:   0x0
Number of RVA and Sizes:   0x10
Section Alignment:         0x1000
Size of Code:              0x1800
Size of Headers:           0x400
Size of Heap Commit:       0x1000
Size of Heap Reserve:      0x100000
Size of Image:             0x1a000
Size of Initialized Data:  0xfe00
Size of Stack Commit:      0x1000
Size of Stack Reserve:     0x100000
Size of Uninitialzed Date: 0x0
Subsystem:                 0x3
Win32 Version Value:       0x0

---------- In Section Header ----------

---------- In .text Section ----------
Virtual Address:           0x1000
Virtual Size:              0x1626
Pointer to Raw Data:       0x400
Size of Raw Data:          0x1800
Characteristics:           0x60000020
Number of Line Numbers:    0x0
Number of Relocations:     0x0
Pointer to Line Numbers:   0x0
Pointer to Relocation:     0x0

---------- In .rdata Section ----------
Virtual Address:           0x3000
Virtual Size:              0xc0c
Pointer to Raw Data:       0x1c00
Size of Raw Data:          0xe00
Characteristics:           0x40000040
Number of Line Numbers:    0x0
Number of Relocations:     0x0
Pointer to Line Numbers:   0x0
Pointer to Relocation:     0x0

---------- In .buildid5 Section ----------
Virtual Address:           0x4000
Virtual Size:              0x35
Pointer to Raw Data:       0x2a00
Size of Raw Data:          0x200
Characteristics:           0x40000040
Number of Line Numbers:    0x0
Number of Relocations:     0x0
Pointer to Line Numbers:   0x0
Pointer to Relocation:     0x0

---------- In .data Section ----------
Virtual Address:           0x5000
Virtual Size:              0x11c
Pointer to Raw Data:       0x2c00
Size of Raw Data:          0x200
Characteristics:           0xc0000040
Number of Line Numbers:    0x0
Number of Relocations:     0x0
Pointer to Line Numbers:   0x0
Pointer to Relocation:     0x0

---------- In .pdata Section ----------
Virtual Address:           0x6000
Virtual Size:              0x108
Pointer to Raw Data:       0x2e00
Size of Raw Data:          0x200
Characteristics:           0x40000040
Number of Line Numbers:    0x0
Number of Relocations:     0x0
Pointer to Line Numbers:   0x0
Pointer to Relocation:     0x0

---------- In .tls Section ----------
Virtual Address:           0x7000
Virtual Size:              0x10
Pointer to Raw Data:       0x3000
Size of Raw Data:          0x200
Characteristics:           0xc0000040
Number of Line Numbers:    0x0
Number of Relocations:     0x0
Pointer to Line Numbers:   0x0
Pointer to Relocation:     0x0

---------- In .reloc Section ----------
Virtual Address:           0x8000
Virtual Size:              0x6c
Pointer to Raw Data:       0x3200
Size of Raw Data:          0x200
Characteristics:           0x42000040
Number of Line Numbers:    0x0
Number of Relocations:     0x0
Pointer to Line Numbers:   0x0
Pointer to Relocation:     0x0

---------- In /4 Section ----------
Virtual Address:           0x9000
Virtual Size:              0x15b2
Pointer to Raw Data:       0x3400
Size of Raw Data:          0x1600
Characteristics:           0x42000040
Number of Line Numbers:    0x0
Number of Relocations:     0x0
Pointer to Line Numbers:   0x0
Pointer to Relocation:     0x0

---------- In /18 Section ----------
Virtual Address:           0xb000
Virtual Size:              0x489b
Pointer to Raw Data:       0x4a00
Size of Raw Data:          0x4a00
Characteristics:           0x42000040
Number of Line Numbers:    0x0
Number of Relocations:     0x0
Pointer to Line Numbers:   0x0
Pointer to Relocation:     0x0

---------- In /30 Section ----------
Virtual Address:           0x10000
Virtual Size:              0x2069
Pointer to Raw Data:       0x9400
Size of Raw Data:          0x2200
Characteristics:           0x42000040
Number of Line Numbers:    0x0
Number of Relocations:     0x0
Pointer to Line Numbers:   0x0
Pointer to Relocation:     0x0

---------- In /42 Section ----------
Virtual Address:           0x13000
Virtual Size:              0x1e19
Pointer to Raw Data:       0xb600
Size of Raw Data:          0x2000
Characteristics:           0x42000040
Number of Line Numbers:    0x0
Number of Relocations:     0x0
Pointer to Line Numbers:   0x0
Pointer to Relocation:     0x0

---------- In /53 Section ----------
Virtual Address:           0x15000
Virtual Size:              0x210
Pointer to Raw Data:       0xd600
Size of Raw Data:          0x400
Characteristics:           0x42000040
Number of Line Numbers:    0x0
Number of Relocations:     0x0
Pointer to Line Numbers:   0x0
Pointer to Relocation:     0x0

---------- In /67 Section ----------
Virtual Address:           0x16000
Virtual Size:              0x3ec9
Pointer to Raw Data:       0xda00
Size of Raw Data:          0x4000
Characteristics:           0x42000040
Number of Line Numbers:    0x0
Number of Relocations:     0x0
Pointer to Line Numbers:   0x0
Pointer to Relocation:     0x0

---------- In Data Directory ----------
Export Table
Virtual Address:           0x0
Size:                      0x0

Import Table
Virtual Address:           0x3610
Size:                      0x50

Resource Table
Virtual Address:           0x0
Size:                      0x0

Exception Table
Virtual Address:           0x6000
Size:                      0x108

Certificate Table
Virtual Address:           0x0
Size:                      0x0

Base Relocation Table
Virtual Address:           0x8000
Size:                      0x6c

Debug
Virtual Address:           0x4000
Size:                      0x1c

Architecture
Virtual Address:           0x0
Size:                      0x0

Global Ptr
Virtual Address:           0x0
Size:                      0x0

TLS Table
Virtual Address:           0x30d0
Size:                      0x28

Load Config Table
Virtual Address:           0x3448
Size:                      0x138

Bound Import
Virtual Address:           0x0
Size:                      0x0

IAT
Virtual Address:           0x3790
Size:                      0x130

Delay Import Descriptor
Virtual Address:           0x0
Size:                      0x0

CLR Runtime Header
Virtual Address:           0x0
Size:                      0x0

Reserved
Virtual Address:           0x0
Size:                      0x0


---------- In Tracing Imported Module ----------

---------- In Module msvcrt.dll ----------
Imported function:         __C_specific_handler
Imported function:         __getmainargs
Imported function:         __initenv
Imported function:         __iob_func
Imported function:         __set_app_type
Imported function:         __setusermatherr
Imported function:         _amsg_exit
Imported function:         _cexit
Imported function:         _commode
Imported function:         atexit
Imported function:         _fmode
Imported function:         _initterm
Imported function:         abort
Imported function:         calloc
Imported function:         exit
Imported function:         fprintf
Imported function:         free
Imported function:         fwrite
Imported function:         malloc
Imported function:         memcpy
Imported function:         signal
Imported function:         strlen
Imported function:         strncmp
Imported function:         vfprintf

---------- In Module USER32.dll ----------
Imported function:         MessageBoxA

---------- In Module KERNEL32.dll ----------
Imported function:         DeleteCriticalSection
Imported function:         EnterCriticalSection
Imported function:         GetLastError
Imported function:         InitializeCriticalSection
Imported function:         LeaveCriticalSection
Imported function:         SetUnhandledExceptionFilter
Imported function:         Sleep
Imported function:         TlsGetValue
Imported function:         VirtualProtect
Imported function:         VirtualQuery
```
