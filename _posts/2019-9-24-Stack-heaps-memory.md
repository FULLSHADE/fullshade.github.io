---
layout: single
title: Understanding Windows Memory Data Structures
---

These are a few of the commonly referred to Windows memory management data structures that you'll commonly encounter when performing some aspect of Windows debugging, kernel debugging, or Windows exploit development. The following Windows memory data structures are crucial to understanding if you truly want to exceed at being a security researcher or exploit developer. 

----

**Understanding Windows Heaps**

Windows heaps are fairly seen as “complex” to understand, but basically, the heap is a memory data structure representing dynamic memory that is use dby programs at runtime. When programs you create require chunks of memory to use. You can use the HeapCreate function on Windows to establish and create a private heap for your program, then you can use HeapAlloc to allocate memory on the heap for your program and have that allocated space be assigned to your program, you can also use the HeapFree function to free your allocated space after you are done using it. 

These functions are the same equivalent of using Malloc and Free, outside of Windows programming. You should never reference an already freed piece of memory because after it freed it’s gone into the void, and this can lead to what's known as a “Use after free” vulnerability. You can get rid of a created heap using the HeapDestroy function

Within WinDBG you can view the current processes heaps and dump heap information and data via the `!heap` command.

```
0:004> !heap -s
LFH Key                   : 0x748d6815
Termination on corruption : ENABLED
  Heap     Flags   Reserv  Commit  Virt   Free  List   UCR  Virt  Lock  Fast 
                    (k)     (k)    (k)     (k) length      blocks cont. heap 
-----------------------------------------------------------------------------
002e0000 00000002    1024    196   1024      3     4     1    0      0   LFH
00010000 00008000      64      4     64      2     1     1    0      0      
00180000 00001002      64     12     64      1     1     1    0      0      
005e0000 00001002      64      4     64      2     1     1    0      0      
006e0000 00001002     256     44    256     10     1     1    0      0      
00840000 00001002     256      4    256      1     1     1    0      0      
-----------------------------------------------------------------------------
0:004> dd 002e0000
002e0000  e4d3fb2d 010021f3 ffeeffee 00000000
002e0010  002e00a8 002e00a8 002e0000 002e0000
002e0020  00000100 002e0588 003e0000 000000cf
002e0030  00000001 00000000 00310ff0 00310ff0
002e0040  00000002 00000000 00000000 00100000
002e0050  54d2fb9c 000021f3 08cec71b 00000000
002e0060  0000fe00 eeffeeff 00100000 00002000
002e0070  00000800 00002000 00000196 7ffdefff
```

Using the -s parameter we can dump a lot more information about the heaps, and then you can dump memory from different heaps via the `dd` command.

From the `!heap -s` dump, you can see that the top heap entry is listed as the LFH, or otherwise known as the *Low fragmentation heap*. 

----

**Low fragmentation heaps**

The LFH was introduced in Windows XP SP2 and Windows Server 2003, and the LFH is not used by default unless explicitly configured to run with an application. LFH is more commonly used with Vista and onwards as with Vista and you don’t need to explicitly assign an LFH for when your program is compiled. It will handle that automatically., LFH heaps add more security to the heaps it manages, the LFH adds a 32-bit cookie in the chunk header as an integrity check.

To enable an LFH you can use the GetProcessHeap function to obtain a handle to the default heap of the calling process, or you can use that handle to connect to a private heap that was created by HeapCreate.

----

**Heap fragmentation**

To better understand the Low-fragmentation heap, heap fragmentation is a state when instead of compacting the memory, the memory is broken up into small blocks of memory. When a heap is fragmented, it can lead to memory allocation fails. The Low fragmentation heap helps reduce heap fragmentation.

----

**TIB (Thread Information Block)**

The TIB is a win32 data structure on x86 systems that is responsible for storing information about the current running thread, which is also known as the TEB (Thread Environment Block). The TIB can be used to get a lot of information about the running process without calling the Win32 API, and through the pointer to the PEB, one can gain access to the IAT (Import tables), and many more things. The TIB will hold a table of pointers (examples like FS:[0x00] for the current SEH handler or FS:[0x00] for the Process Environment Block).

In WinDBG you can query information from a processes TEB with the command dt `ntdll!_TEB`, viewing the TEB shows that the entry 0x30 is indeed the ProcessEnvironmentBlock.

```
ntdll!DbgBreakPoint:
77723c2c cc              int     3
0:002> dt ntdll!_TEB
   +0x000 NtTib            : _NT_TIB
   +0x01c EnvironmentPointer : Ptr32 Void
   +0x020 ClientId         : _CLIENT_ID
   +0x028 ActiveRpcHandle  : Ptr32 Void
   +0x02c ThreadLocalStoragePointer : Ptr32 Void
   +0x030 ProcessEnvironmentBlock : Ptr32 _PEB
   +0x034 LastErrorValue   : Uint4B
   +0x038 CountOfOwnedCriticalSections : Uint4B
   +0x03c CsrClientThread  : Ptr32 Void
   +0x040 Win32ThreadInfo  : Ptr32 Void
   +0x044 User32Reserved   : [26] Uint4B
   +0x0ac UserReserved     : [5] Uint4B
   +0x0c0 WOW32Reserved    : Ptr32 Void
   +0x0c4 CurrentLocale    : Uint4B
   +0x0c8 FpSoftwareStatusRegister : Uint4B
   +0x0cc SystemReserved1  : [54] Ptr32 Void
   +0x1a4 ExceptionCode    : Int4B
   +0x1a8 ActivationContextStackPointer : Ptr32 _ACTIVATION_CONTEXT_STACK
   ```
----

**PEB (Process Environment Block)**

The PEB is a data structure within the Windows NT operating system, it has been around since Windows 2000 and it has been improved and change over time. The PEB is located within userland, but the PEB comes from the Kernel Thread Information Block (TEB) and it's responsible for holding a lot of details about each running process, the PEB holds information such as the base address of the module, the start of the heap and information about imported DLLs and more, the pointer to the PEB can be found at FS:[0x30].

Each process has it's own PE and the Windows kernel will have access to every running user-mode process so it can keep track of certain data that is stored within them.

The PEB is also a commonly attacked surface. When writing Windows shellcode, the PEB is commonly attacked since it can hold information about modules like kernel32.dll And if the Shellcode can obtain this information about kernel32.dll, it can also be used to obtain the location of the getprocaddress() function which can then be used to locate any desired functions address which would allow for further exploitation.

The exploitation of the PEB can also consist of parts of the PEB (some of the PEB entries) being changed for the process to mimic another process. It’s been a common occurrence where a malicious rootkit would inject itself into a running process and access the processes PEB, and once it gains access to that PEB, it can locate the loaded modules and remove itself from the list in the PEB, thus making the malware more stealthy and harder to find.

You can dump information from the current PEB in WinDBG using either the command `!peb` which will dump a plethora of information, or you can query and dump the tables of information using the `dt _peb` command. The snippet below shows information within the PEB, you can see information about the base address, and more. If you want to view the information, first use `r $peb` and then overlay the memory pointed at the PEB to see what values this structure is holding. Finally view all of the dumped information with the command `dt _peb @$peb` which now includes addresses and more after it's been populated. 

```
0:004> dt _peb @$peb
ntdll!_PEB
   +0x000 InheritedAddressSpace : 0 ''
   +0x001 ReadImageFileExecOptions : 0 ''
   +0x002 BeingDebugged    : 0x1 ''
   +0x003 BitField         : 0x8 ''
   +0x003 ImageUsesLargePages : 0y0
   +0x003 IsProtectedProcess : 0y0
   +0x003 IsLegacyProcess  : 0y0
   +0x003 IsImageDynamicallyRelocated : 0y1
   +0x003 SkipPatchingUser32Forwarders : 0y0
   +0x003 SpareBits        : 0y000
   +0x004 Mutant           : 0xffffffff Void
   +0x008 ImageBaseAddress : 0x008e0000 Void
   +0x00c Ldr              : 0x777c8880 _PEB_LDR_DATA
   +0x010 ProcessParameters : 0x002e1100 _RTL_USER_PROCESS_PARAMETERS
   +0x014 SubSystemData    : (null) 
   +0x018 ProcessHeap      : 0x002e0000 Void
   +0x01c FastPebLock      : 0x777c8380 _RTL_CRITICAL_SECTION
   +0x020 AtlThunkSListPtr : (null) 
```
----

**PEB Randomization**

Since the PEB is a commonly attacked Windows data structure, prevention (for the same reasons that ASLR is implemented) is to simply randomize the PEB, to thwart attackers from discovering information in the PEB. PEB Randomization was added on Windows XP SP2, before this, the address for the PEB was always located at 0x7FFDF00. Having a static address for the PEB was what made it so common to overwrite parts of the PEB, with PEB randomization, enabled, the PEB won’t be loaded into memory at 0x7FFDF00 always, instead there are 16 possible locations that the PEB can be loaded into memory, ranging from Ox7FFDOOO to Ox7FFDFOO. 

PEB randomization does add some sense of security. But there are some inconsistencies with the randomization which can lead to the PEB being loaded into memory in certain “favorable memory address location”. A Symantec study and a paper presented via BlackHat showed that a single guess of where the PEB was located resulted in a 25% success rate. Rendering PEB randomization not 100% successful making it not a secure method of exploitation prevention. 

----

**Conclusion**

Learning Windows internals can be a daunting and complex task, but learning how Windows works is very important for anyone who want's to be a security researcher or anyone who deals with any sort of exploit-development or advanced debugging. 
