---
layout: single
title: Windows Kernel Memory Pool & Vulnerabilities
---

This article gives insight into what the Windows Kernel pool is, and what are some vulnerabilities that reside inside the pool area. Also, this article will show and explain the analysis of a Windows pool overflow crash via WinDBG.

----

**What is the Windows memory pool?**

The Windows memory manager creates nonpaged and paged pools that the system can use. Memory pools are kernel-mode memory that is used as storage space for Kernel drivers and devices. Memory pools can also be called "fixed-size blocks allocation" and these drivers are using dynamic memory being allocated from these pools.

Handles for kernel objects are stored in paged pools, so when you create kernel handles, that depends on the available memory from the pools.

**Paged pools vs. non-paged pools:** 

Paged pools are referring to the kernel and device driver memory **can** be offloaded from physical RAM. This pagable memory is similar to ordinary virtual memory that can be used by normal processes. Paged memory can be "paged out" .

Nonpaged pools are the amount of Kernel and device driver memory that must stay in physical memory, non-paged pools cannot be offloaded. Nonpaged pools are used to store data that may be used when the system can't handle page faults. 

When the Windows memory manager creates memory pools that the kernel device drivers use to allocate kernel memory, both types of memory pools (paged and non-paged) are located in the virtual address space of the processes. Kernel objects will use paged pools, so when you request handlers with something like the `CreateFileA()` function, that will depend on the available corresponding paged pool memory. 

The nonpaged pool will use virtual memory addresses that are guaranteed in physical memory (as long as the kernel objects that are using it are allocated)

And paged pools are using virtual memory that *can* be mapped in and out of the system.

![page vs nonpaged memory](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/memmange.png)

----

Within Windows, the `ExAllocatePoolWithTag()` function is used to allocate pool memory of the specified type. And the `ExFreePoolWithTag()` function is used to deallocate a block of pool memory with a specified tag. These functions are similar to using heapAlloc(), heapFree(), malloc(), and free() when you are conducting some kind of heap or memory management.

In the Windows heap manager, there are three types of allocators, but two main types, regular pools, and Big pool allocations. The regular pool is used for any type of allocation that would fit within a page of memory, and a page of memory is 4KB in size (and for both virtual and physical memory). Depending on the system architecture, the pages are between 2-4MB in size.  

----

To better understand pools and allocating pool's memory. Within the `ExAllocatePoolWithTag()` function there are three parameters a user needs to set when allocating memory pools. 

```c++
PVOID ExAllocatePoolWithTag(
  __drv_strictTypeMatch(__drv_typeExpr)POOL_TYPE PoolType,
  SIZE_T                                         NumberOfBytes,
  ULONG                                          Tag
);
```
1. The first parameter `PoolType` is referring to the type of pool memory to allocate, the types mentioned above are PagedPools, NonPagedPools, there are many more types which can be found at the [offical Microsoft documentation](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_pool_type). My personal favorite is `DontUseThisType` which is reserved for system use only.
2. The second parameter `NumberOfBytes` refers to the size/amount of bytes that are going to be allocated.
3. The third parameter you need to use the `ExAllocatePoolWithTag()` function is the `Tag` parameter. The tag is a four-byte tag used for setting up the pool for allocating memory, so drivers can request to allocate memory with a tag. This four-byte tag could be something like "cats", "dogs", or anything of the sort. And this four-byte tag is set in reverse order (little-endian format for the CPU) so when the tag is seen in a pool dump, it's going to be seen to us backward. This tag is a unique identifier.

And finally, the `ExAllocatePoolWithTag()` function will respond NULL is there is not enough memory in the free pool to adhere to the requested byte size.

Within the `ExFreePoolWithTag()` function there are two parameters a user needs to set. The [offical Microsoft documentation is here](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exfreepoolwithtag)

```c++
void ExFreePoolWithTag(
  PVOID P,
  ULONG Tag
);
```
1. The first parameter, "P" is referring to the addresses of a memory pool block.
2. The second parameter is referring to the tag mentioned in the `ExAllocatePoolWithTag()` function, this is to identify which pool we are freeing. 

----

**How can the Windows memory pool be attacked?**

![IOCTL connection](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/pool5.jpeg)

Pool corruption/pool overflows usually occur when a Kernel driver suffers from some type of buffer overrun or underrun which causes overwritten data to write out of the buffer and into the allocated kernel-space pool memory that the device driver is using. 

Since pools are in kernel-mode and are designed as memory for Kernel drivers/devices, attacks against the pools are going to result in BSOD and EOP privilege escalation attacks and exploits. Just like any other type of memory exploitation, there are also going to be pool corruption vulnerabilities and DOS crashes occurring, an attacker's goal with Windows Kernel pool exploitation is creating an exploit which results in an EOP attack.

A common method for payload delivery while conducting Windows Kernel pool overflow attacks is called `Pool Feng-Shui` which essentially 

On a Windows 7 system, the NonPagedPool functions are in play when it comes to kernel pool memory usage, which means that pools are executable, which makes pool overflow exploitation a whole lot easier.

After Windows 7, the `NonPagedPoolNx` function was introduced to allow for the usage of pools that are marked as non-executable, this new function basically allows for pools to have NX enabled. And Windows will use it by default now, meaning, if your writing a pool overflow exploit on a Windows 10 system, you would need an information leakage

With pool feng shui you need to spray objects into the kernel pool, through a series of allocations and deallocations, you can put the pool in a deterministic state, where you can create holes in it, and drop your shellcode around.

----

**Finding Kernel bugs & Binary Diffing**

A common approach and method to finding kernel bugs (not purely related to pool overflows), if Binary Diffing, which is a technique of comparing two binary builds, one build that has previously been recorded as having a security/vulnerability flaw in it. And the new and updated patched version, like comparing a new Windows kernel build to a previously patched one, and this patch analysis can show why the previous version was patched and what the vulnerability was. This is a very common method for finding new Kernel exploits/corruption bugs. A popular tool is called BinDiff.

![bindiff](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/pool3.png)

----

**Common / realistic scenarios**

On MITRE ATT&CK's CVE listings, 29 CVE entries list pool overflows, some of the more popular and well-known pool overflows that have been found in common well-known software are:

- `CVE-2017-6008` which was a pool overflow in the HitmanPro standalone tool hitmanpro37.sys driver (a tool for malware removal). 
- `CVE-2014-3434` which was a pool overflow found in the Symantec Endpoint Protection sysplant driver which resulted in EOP attacks.
- `CVE-2013-1300` which was a kernel pool overflow in Win32k which allows local privilege escalation, this widely affected Windows 7 SP1 x86 systems, fixed in the MS13-053 patch by Microsoft.

----

**Analyzing a pool overflow crash with WinDBG**

To create a Pool overflow crash on a Windows system, this demonstration will be using the NotMyFault tool provided by Microsoft which is designed to allow researchers to experience system crashes based on various types of bugs. Some of the crash examples that the NotMyFault tool can create are Buffer Overflows, Double Free, Stack Overflows, and more. This demonstration focuses on the Buffer overflow option which is a Pool overflow.

**Understanding the NotMyFault tool from Sysinternals**

The NotMyFault tool, which is provided from Microsofts Sysinternals package includes two parts, there is the executable titled notmyfault.exe which provides a GUI interface as seen below.

![GUI interface](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/pool1.png)

Apart from the GUI interface, there is a driver named myfault.sys which is loaded when you run the GUI executable, this driver is what will trigger the various types of crashes. This driver is loaded from C:\Windows\System32\drivers\myfault.sys. This can also be shown via the `lmf h` command in WinDBG to display loaded modules. 

```
9ce83000 9ce8a000   myfault  myfault.sys 
```

![IOCTL connection](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/pool2.png)

**Crashing the system**

While this system is hooked up to our host via our kernel debugging environment, clicking the crash will freeze up the system and WinDBG will show the crash. And we have a crash.

```
*** Fatal System Error: 0x00000019
                       (0x00000003,0x8278D970,0x4F4F4F4F,0x4F4F4F4F)

Break instruction exception - code 80000003 (first chance)
nt_8264a000!RtlpBreakWithStatusInstruction:
826b2788 cc              int     3
```

A 0x00000019 error is a Blue screen of death (BSOD), but until we run the VM from WinDBG it will hang to allow us to analyze the crash. And using `!analyze -v` right away WinDBGs bug check shows that this is a pool overflow.

```
*******************************************************************************
*                                                                             *
*                        Bugcheck Analysis                                    *
*                                                                             *
*******************************************************************************

BAD_POOL_HEADER (19)
The pool is already corrupt at the time of the current request.
This may or may not be due to the caller.
The internal pool links must be walked to figure out a possible cause of
the problem, and then special pool applied to the suspect tags or the driver
verifier to a suspect driver.
Arguments:
Arg1: 00000003, the pool freelist is corrupt.
Arg2: 8278d970, the pool entry being checked.
```

Often, pool corruption appears as a stop BAD_POOL_HEADER (19) or BAD_POOL_CALLER, in this case, you can see the (19) appeared. In the analysis you can also see the `FOLLOWUP_IP` being listed, this is a disassembly of what instruction probably caused the error.

```
FOLLOWUP_IP: 
win32k!EngAlphaBlend+239
96dee49c 85c0            test    eax,eax
```

A second time crashing the system reveals a little bit of different results. Now it's stating 

```
DRIVER_CORRUPTED_EXPOOL (c5)
An attempt was made to access a pageable (or completely invalid) address at an
interrupt request level (IRQL) that is too high.  This is
caused by drivers that have corrupted the system pool.  Run the driver
verifier against any new (or suspect) drivers, and if that doesn't turn up
the culprit, then use gflags to enable special pool.
Arguments:
Arg1: 00000004, memory referenced
Arg2: 00000002, IRQL
Arg3: 00000000, value 0 = read operation, 1 = write operation
Arg4: 8273588a, address which referenced memory
```
Which again is referencing a pool corruption/overflow. And this time it give more information about how it's specifically a pool corruption crash.

```
SYMBOL_STACK_INDEX:  4
SYMBOL_NAME:  nt!ExDeferredFreePool+21b
FOLLOWUP_NAME:  Pool_corruption
IMAGE_NAME:  Pool_Corruption
DEBUG_FLR_IMAGE_TIMESTAMP:  0
MODULE_NAME: Pool_Corruption
FAILURE_BUCKET_ID:  0xC5_2_nt!ExDeferredFreePool+21b
BUCKET_ID:  0xC5_2_nt!ExDeferredFreePool+21b
Followup: Pool_corruption
---------
```

----

**EOP Kernel exploit demonstration**

This demonstration is of a 0day that was released by Offensive Security for Symantec Endpoint Protection which was given the ID of CVE-2014-3434.


<iframe title="vimeo-player" src="https://player.vimeo.com/video/101980410" width="800" height="460" frameborder="0" allowfullscreen></iframe>


This video demonstrates the effects of poor programming which lead to a pool overflow vulnerability within the Symantec software, ironically software that protects against malware and is designed to thwart attackers.

**Brief analysis**

By reading the exploit posted on exploit-db by Offsec, you see this specific Kernel EOP pool overflow exploit is targeting the SYSPLANT.sys driver from the Symantec program and it is using a Kernel pool spray to spray IoCompletionReserve objects. And the exploit is using the IOCTL - 0x00222084 to communicate with the Kernel driver device. And as a payload we see a similar token stealing shellcode like the payload we've used to gain NT AUTHORITY / SYSTEM when exploiting the HEVD driver.

----

**Conclusion & sources**

Conclusively, we talked about what a Windows kernel pool is and some of the common ways that attackers may exploit it, also we analyzed it briefly with WinDBG to show what a pool overflow crash would look like, and finally gave a demonstration of a pool overflow leading to an EOP attack.

**Sources:**

https://media.blackhat.com/bh-dc-11/Mandt/BlackHat_DC_2011_Mandt_kernelpool-wp.pdf (genius)

https://www.crowdstrike.com/blog/sheep-year-kernel-heap-fengshui-spraying-big-kids-pool/

https://rootkits.xyz/blog/2017/11/kernel-pool-overflow/

https://blogs.msdn.microsoft.com/ntdebugging/2013/06/14/understanding-pool-corruption-part-1-buffer-overflows/

https://www.osr.com/nt-insider/2014-issue1/windows-pool-manager/
