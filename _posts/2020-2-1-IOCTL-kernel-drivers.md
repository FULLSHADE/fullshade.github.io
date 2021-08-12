---
layout: single
title: IOCTL’s for Kernel Driver Exploit Development - Driver IOCTL Dissection and Discovery
---

An introduction to IOCTLS's and utilizing and discovering them while conducting Windows kernel exploit development.

----

**1. Introduction**

Utilizing drivers for local privilege escalation based attacks in a very common attack technique and method used by attackers and hackers alike. Kernel-mode drivers that are susceptible to various types of buffer overflow/vulnerabilities allow for an attacker to obtain a higher level of privilege, this is known as an EOP (escalation of privileges) attack, if an attacker can abuse a kernel-mode driver to write data in kernel mode, they can supply a token-stealing shellcode payload to escalate their privileges to a position like NT\AUTHORITY SYSTEM.

![apt usage](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/apts.png)

**2. Driver communication**

Almost every driver is registered on Windows with a device name and like that allows for user-mode to obtain a handler to the kernel-mode driver. Kernel32.dll includes `CreateFileA` which is a function denoted by Microsofts MSDN docs as a function that allows for handler distribution from kernel-mode to allow for cross communications.

```c
HANDLE CreateFileA(
  LPCSTR                lpFileName,
  DWORD                 dwDesiredAccess,
  DWORD                 dwShareMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD                 dwCreationDisposition,
  DWORD                 dwFlagsAndAttributes,
  HANDLE                hTemplateFile
);
```

CreateFileA creates or opens a file or I/O device and returns a handler that can be used to access the various types of communication to kernel-mode in the sense of kernel-mode drivers. After obtaining a handler to the driver device, we can use the function `DeviceIoControl` which allows a user to send an IOCTL code to a specific device driver.

![filled out functions - python](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/python-dll-funcs.png)

```c
BOOL DeviceIoControl(
  HANDLE       hDevice,
  DWORD        dwIoControlCode,
  LPVOID       lpInBuffer,
  DWORD        nInBufferSize,
  LPVOID       lpOutBuffer,
  DWORD        nOutBufferSize,
  LPDWORD      lpBytesReturned,
  LPOVERLAPPED lpOverlapped
);
```
The `hDevice` field is filled with the device handler, which is provided by the previously used function. `dwIoControlCode` function is filled with a discovered IOCTL code address (which looks likes `0x0022001c`). The IOCTL is used as a request by a user-mode program to call to a kernel-mode action (a syscall).

----

**3. Understanding IOCTL values & permissions**

What is an IOCTL? IOCTLs are used to communicate to a kernel-mode driver from a user-mode application, within drivers, the author will define IOCTLs and data structures that can be used for communication. IOCTLs are a 32bit number. IOCTLs are including in IRP requests (I/O request packet), instead of communicating individual bits of data to a kernel-mode driver, various data is encapsulated in an IRP request. (IOCTLs are included in that)

**Bits 0-1** are defined as **TransferType**. This definition is used to work as the method of communication when transferring data to a kernel-mode driver. Indicating how the system will pass data to the caller of `DeviceIoControl`

`METHOD_OUT_DIRECT, METHOD_IN_DIRECT, METHOD_BUFFERED or METHOD_NEITHER.`

These I/O control codes are contained in IRP_MJ_DEVICE_CONTROL and IRP_MJ_INTERNAL_DEVICE_CONTROL requests. The I/O manager creates these requests as a result of calls to DeviceIoControl

<p align="center">
  <img src="https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/images/3mdlbffr.png">
</p>

* **METHOD_OUT_DIRECT**
  * Specify METHOD_OUT_DIRECT if the caller of DeviceIoControl or IoBuildDeviceIoControlRequest will receive data from the driver.
* **METHOD_IN_DIRECT**
  * Using this I/O control code, you are using the **Direct I/O** access method which locks the application's buffer in memory. This should be used for devices that can transfer large amounts of data at a time. Using this improves driver perormance by reducing the interrupt overhead and eliminating the memory allocation needed. Specify METHOD_IN_DIRECT if the caller of DeviceIoControl or IoBuildDeviceIoControlRequest will pass data to the driver.
* **METHOD_BUFFERED**
  * Using this I/O control code, you are using the **Buffered I/O** access method, which creates a nonpaged system buffer, the I/O manager will copy user data into the system buffer created with METHOD_BUFFERED.
* **METHOD_NEITHER**
  * Using this I/O control code, you are specifiying neither buffer or direct I/O.  

<p align="center">
  <img src="https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/images/ioctl-1.png">
</p>

**Bits 2-12** are defined as **FunctionCode**, this definition is used to determine the user-defined vs. system-defined IOCTLs.

**Bit 13** is defined as a **Custom** and like bit 31 it's defined for representing user-defined values.

**Bits 14-15** are defined as **RequiredAcess** bits, the various types of access a IOCTL can provide is:

` FILE_ANY_ACCESS , FILE_READ_ACCESS, FILE_WRITE_ACCESS , FILE_READ_ACCESS | FILE_WRITE_ACCESS`

* **FILE_ANY_ACCESS**
  * The I/O manager sends the IRP for any caller that has a handle to the object that's representing the target device object.
* **FILE_READ_DATA**
  * The I/O manager sends the IRP for any caller with read permissions only, allowing the device driver to transfer data from the device to system memory.
* **FILE_WRITE_DATA**
  * The I/O manager sends the IRP for any caller with write permissions only, allowing the device driver to transfer data from system memory to the device.
* **FILE_READ_ACCESS + FILE_WRITE_ACCESS**
  * FILE_READ_ACCESS and FILE_WRITE_ACCESS can be ORed together to allow the device driver to have both read and write access from the device and system memory.

This is how the I/O manager can reject IOCTL requests if they are not opened with the correct amount of access. 

**Bits 16-30** are defined as **DeviceType** bits, and this is representing the device type that the IOCTLs are written for. And the last bit, bit 31 represents user-defined values. A full list of device types can be found at [https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/specifying-device-types](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/specifying-device-types)

For defining IOCTLs, there is a system-supplied macro `CTL_CODE` which is defined in Wdm.h and Ntddk.h

```c
#define IOCTL_Device_Function CTL_CODE(DeviceType, Function, Method, Access)
```

For example, within the HEVD vulnerable driver, there is the CTL_CODE IOCTL macro defined as:

`#define HACKSYS_EVD_IOCTL_ARBITRARY_OVERWRITE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS)`

for the Write What Where vulnerabilities IOCTL. This can be be used to calculate the IOCTL via Python command line magic.

![macro python](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/ioctl-macro-py.png)

----

**4. IOCTL discovery** 

**System IRP/System monitoring**

Capturing IRP packets and requests which include IOCTLs is possible through system monitoring. Various tools can be utilized to do this.

- OSR IrpTracker - [https://www.osronline.com/article.cfm%5Earticle=199.htm](https://www.osronline.com/article.cfm%5Earticle=199.htm)

IrpTracker is a tool which allows sniffing Ring3 and Ring0 traffic for communications between user-mode and kernel-mode drivers. This can be used to track IRP requests and IOCTLs which have been used to communicate with a driver.

- IRPMon - [https://github.com/MartinDrab/IRPMon](https://github.com/MartinDrab/IRPMon)

**Fuzzing/Bruteforce**

- IOCTLbf - [https://github.com/koutto/ioctlbf](https://github.com/koutto/ioctlbf)

IOCTLbf is a tool designed for basic kernel driver fuzzing via a provided IOCTL, but once you have a valid IOCTL, you can use IOCTLbf to fuzz for more.

- kDriver-Fuzzer - [https://github.com/k0keoyo/kDriver-Fuzzer/](https://github.com/k0keoyo/kDriver-Fuzzer/)

kDriver-Fuzzer is based on IOCTLbf, and it allows for more kernel driver fuzzing and IOCTL bruteforcing/discovery.

**Static code analysis with IDA Pro**

- win_driver_plugin -  https://github.com/FSecureLABS/win_driver_plugin

We can fully automated IOCTL discovery with the win_driver_plugin from FSecureLABS and the help of Sam Bowne. This plugin automates the discovery of the `DispatchDeviceControl` function / dispatch functions which we can use to obtain many IOCTLs from the driver.

For example with HEVD and win_driver_plugin:

1. Load and install the IDA Pro plugin into the plugin folder
2. Edit > IOCTL > Find Dispatch (CTRL+ALT+S)
3. Right Click > Driver Plugin > Decode all IOCTLs in function

<p align="center">
  <img src="https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/IDA-ioctls-plugin.png">
</p>

----

**5. IOCTL decoder/calculator**

- win_driver_plugin OSR Online IOCTL Decoder  - [https://www.osronline.com/article.cfm%5Earticle=229.htm](https://www.osronline.com/article.cfm%5Earticle=229.htm)

OSR Online IOCTL Decoder is built-in JS and is an online IOCTL decoder that allows you to easily find all of the details about the various IOCTL values as discussed earlier.

- [https://social.technet.microsoft.com/wiki/contents/articles/24653.decoding-io-control-codes-ioctl-fsctl-and-deviceiocodes-with-table-of-known-values.aspx](https://social.technet.microsoft.com/wiki/contents/articles/24653.decoding-io-control-codes-ioctl-fsctl-and-deviceiocodes-with-table-of-known-values.aspx)
