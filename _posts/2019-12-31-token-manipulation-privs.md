---
layout: single
title: Kernel Opaque Data Structures & Access Tokens
---

Within the world of exploit development, a common technique to gain access on another higher level is through the process of process token theft which leads to an escalation of privileges attack (EOP).

This article aims to cover what access tokens are and how a process uses and stores them, and what security concern one will face when dealing with process access tokens. In the second half of this article, we will cover manual analysis of access tokens through WinDBG, and also demonstrate a manual EOP attack using tokens, and to conclude token theft attacks, we will look at some commonly used and abused access token stealing shellcode payloads that attackers commonly use during exploit development as a means to gain higher privileges.

**Understanding access tokens**

*EPROCESS - Opaque data structure* 

Within the Windows kernel, some data structures are known as "opaque" data structures, within Windows kernel opaque structures there is the EPROCESS data structure which is responsible for serving as the process object for a process. Meaning, the EPROCESS structure is just like the process object, and you can use various functions like you would get a handle to an object (i.g. using a function like NtOpenProcess to create a handle to a process object). What this means in layman's terms, the EPROCESS structure is the kernel's representation of a process object. And since the EPROCESS structure is internal to the kernel, the structure of it widely changes throughout various versions of Windows. 

Each process that is running has its own EPROCESS data structure block that will hold a lot of data, one of the members of the EPROCESS structure that I have covered are members like the PEB (Process Environment Block), the EPROCESS block will hold a pointer to the user-mode PEB, and these members are accessible outside of kernel space, from user mode.

*Acess tokens*

Within every Windows process, each process has an assigned access token which acts determines the ownership of the running process. Access tokens will include the identity and privileges that the running process has. From a security standpoint, this can lead to what's known as a token manipulation/theft attack, where an attacker can impersonate the privileges of a running process to make the process appear like its running as someone else, this concept is widely implemented in privilege escalation shellcode/exploits, where an attack will use some kind of payload to steal a SYSTEM level token and replace their current process's token with the new SYSTEM token (i.g. elevating the process token in a CMD.exe process would give an attack full rein over the system)

The Windows API has a built-in system and set of functions that allow for copying access tokens from another process. There are three methods from leveraging this type of escalation attack.

----

1. Token Impersonation/Theft

An attacker can use the `DuplicateTokenEx()` function to create a new access token that duplicates an existing function,

```C++
BOOL DuplicateTokenEx(
  HANDLE                       hExistingToken,
  DWORD                        dwDesiredAccess,
  LPSECURITY_ATTRIBUTES        lpTokenAttributes,
  SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
  TOKEN_TYPE                   TokenType,
  PHANDLE                      phNewToken
);
```
this function will create a handle to an access token which is opened with TOKEN_DUPLICATE access, then it will request the specified access rights that are provided through the `dwDesiredAccess` parameter.

Combined with this newly created access token, an attacker can use the `ImpersonateLoggedOnUser()` function to allow the calling thread to impersonate another logged-on user.

```C++
BOOL ImpersonateLoggedOnUser(
  HANDLE hToken
);
```

The hToken parameter is the handle to a primary or impersonation access token which is representation of a logged-on user. If hToken is a handle to a primary token, the token must have TOKEN_QUERY and TOKEN_DUPLICATE access. If hToken is a handle to an impersonation token, the token must have TOKEN_QUERY and TOKEN_IMPERSONATE access.

The impersonation will last until he threads exist or until the RevertToSelf function is called. 


```C++
BOOL RevertToSelf();
```

----

**EPROCESS data structure analysis & tokens**

Within kernel-mode debugging, we can view the members and information and values from the EPROCESS data structure.

```C++
0: kd> dt nt!_EPROCESS
   +0x000 Pcb              : _KPROCESS
   +0x098 ProcessLock      : _EX_PUSH_LOCK
   +0x0a0 CreateTime       : _LARGE_INTEGER
   +0x0a8 ExitTime         : _LARGE_INTEGER
   +0x0b0 RundownProtect   : _EX_RUNDOWN_REF
   +0x0b4 UniqueProcessId  : Ptr32 Void
   +0x0b8 ActiveProcessLinks : _LIST_ENTRY
   +0x0c0 ProcessQuotaUsage : [2] Uint4B
   +0x0c8 ProcessQuotaPeak : [2] Uint4B
   +0x0d0 CommitCharge     : Uint4B
   +0x0d4 QuotaBlock       : Ptr32 _EPROCESS_QUOTA_BLOCK
   +0x0d8 CpuQuotaBlock    : Ptr32 _PS_CPU_QUOTA_BLOCK
   +0x0dc PeakVirtualSize  : Uint4B
   +0x0e0 VirtualSize      : Uint4B
   +0x0e4 SessionProcessLinks : _LIST_ENTRY
   +0x0f4 ObjectTable      : Ptr32 _HANDLE_TABLE
   +0x0f8 Token            : _EX_FAST_REF
   +0x0fc WorkingSetPage   : Uint4B
   +0x100 AddressCreationLock : _EX_PUSH_LOCK
```
As you can see, the sffset of the access token is 0x0f8 as you can see is that token member is listed as `+0x0f8 Token     : _EX_FAST_REF`, and we can dump more information using the `dt nt!_EX_FAST_REF` to display the type details.

```C++
0: kd> dt nt!_EX_FAST_REF
   +0x000 Object           : Ptr32 Void
   +0x000 RefCnt           : Pos 0, 3 Bits
   +0x000 Value            : Uint4B
```
RefCnt is referring to the reference counter of the object, and the value is what is important about the token.

To better understand the tokens, we can list all of the running processes on the victim system using the `!dml_proc` command. 

```C++
0: kd> !dml_proc
Address  PID  Image file name
84f6fb90 4    System         
84f164d0 104  smss.exe       
85d32d20 14c  csrss.exe      
85629030 17c  csrss.exe      
85de7360 1fc  lsm.exe        
85e4aa38 264  svchost.exe    
85e60d20 2a0  VBoxService.ex 
85ffd750 5f0  taskhost.exe   
86024620 658  svchost.exe    
8602f760 688  svchost.exe    
85ffcd20 6b0  IPCheckProbe.e 
85ffb470 6b8  taskeng.exe    
85022030 7f8  NMSAccessU.exe 
860f9830 158  wlms.exe      
```

We will use this to view the values of the tokens within a certain running process. We can use the address of a process of your choice combined with the `!process` command, with the syntax of `!process [address of EPROCESS]` to get more details. 

```C++
0: kd> !process 860f9830
PROCESS 860f9830  SessionId: 0  Cid: 0158    Peb: 7ffd9000  ParentCid: 01ec
    DirBase: df665840  ObjectTable: 9c1fb328  HandleCount:  51.
    Image: wlms.exe
    VadRoot 860f9330 Vads 48 Clone 0 Private 136. Modified 1. Locked 0.
    DeviceMap 8cc06978
    Token                             9a9368a0
    ElapsedTime                       00:00:17.209
    UserTime                          00:00:00.000
    KernelTime                        00:00:00.000
    QuotaPoolUsage[PagedPool]         0
    QuotaPoolUsage[NonPagedPool]      0
    Working Set Sizes (now,min,max)  (657, 50, 345) (2628KB, 200KB, 1380KB)
    PeakWorkingSetSize                657
    VirtualSize                       16 Mb
    PeakVirtualSize                   16 Mb
    PageFaultCount                    669
    MemoryPriority                    BACKGROUND
    BasePriority                      8
    CommitCharge                      157
 ```
As you can see, the process I chose to analyze (wlms.exe) has the token value of `9a9368a0`. But to get a similar output like when we used the `dt nt!_EX_FAST_REF` command, we can use that same command but with a provided address of a running process.

`dt nt!_EX_FAST_REF 860f9830 + f8`, the +f8 is adding the offset of the token field.

```C++
0: kd> dt nt!_EX_FAST_REF 860f9830 + f8
   +0x000 Object           : 0x9a9368a7 Void
   +0x000 RefCnt           : 0y111
   +0x000 Value            : 0x9a9368a7
```

----

**Real-world scenarios**

Token access theft & EOP with token manipulation is a very common attack for hackers and exploit developers to utilize, 

**Manual EOP with process token manipulation**

**Understanding token stealing shellcode**

**Conclusion**
