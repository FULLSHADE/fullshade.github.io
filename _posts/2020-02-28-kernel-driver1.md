---
layout: single
title: Writing a Windows Kernel-Mode Driver - Part 1
---

Introduction to writing Windows kernel-mode drivers in the C programming language. This post covers setting up the kernel development enviroment and the basics to get your first kernel driver deployed.

**Introduction**

Windows development can be seen as a difficult task, thus making Kernel-mode driver development an even more difficult task to conduct. To learn proper Windows kernel exploit development, understanding the underlying properties and internals of Windows and especially windows kernel drivers is crucial. This mini-series will give insight to Windows kernel driver development and this series will hopefully give light to some of the more complicated aspects of Windows internals as a whole.

----

**What is a drivers purpose?**

When utilizing a hardware device, the device needs to communicate to the system and any user interacting with the system, and vise-versa. When a user needs to communicate and interact with a device, the driver will act as a middleman in some sort. But, this is not always the exact case, there are various types of drivers. 

----

**Function drivers**

*Function drivers* serve as the middleman between a user (user interacting and a user-mode application). And the driver serves I/O functionality to a device. These types of drivers are provided by companies for audio drivers, graphics drivers, network drivers, and more. Function drivers are the main driver for a device, loading of a Function Driver is handled by the PNP (Plug And Play) manager. 

![functional drivers](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/driverdev/driver1.png)

----

**Filter drivers**

Filter drivers will work with other drivers to handle I/O processing, these drivers won't talk to the devices directly, but they will talk with functional drivers, filter drivers serve the purpose of being able to process, handle, change, and modify the device requests. 

![filter drivers](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/driverdev/driver2.png)

  - Bus Filter Drivers (optional, they can add value to a bus)
  - Lower-Level Filter Drivers (Change and modify the behavior of device hardware)
  - Upper-Level Filter Drivers (Provide added-value features for a device)

----

**Driver execution location**

- **Kernel-Mode Drivers**
  * This series is going to focus on Kernel Drivers, kernel drivers will execute in system kernel mode and they have access to a lot more privileges and internal data.
  
- **User-Mode Drivers**
  * For separation of privilege reasons, if a driver doesn't need to be running in kernel-mode, it can run in userspace, these types of drivers may be filter or function drivers, but if they don't need special levels of access, for security purposes, they run in user-mode.

----

**Driver Security**

Windows Kernel drivers will execute in kernel-mode, which grants them a higher set of privileges, if the driver coder messes up, it can lead to severe consequences, such as privileges escalation bugs, kernel memory corruption, and more. When something goes wrong in kernel-mode, you are very likely the have a system crash which results in a BSOD.

----

**Driver programming resources**


- This will be using Visual Studio 2015 + Windows SDK for Windows 10.0.14393.795

- For driver programming on Windows, use the WDK (1607) (Windows Driver Kit), and drivers will be writing in C/C++.

- For loading the driver into the system, you can use OSR Loader, found [here](https://www.osronline.com/article.cfm%5Earticle=157.htm)

- For debugging the kernel environment you will need WinDBG and you will need to set up a kernel debugging environment with either VirtualBox or VMware.

----

**Programming Introduction**

After setting up your kernel debugging environment, which will include the standard 2x virtual machine hosts + a virtual serial bus connector and WinDBG. You can start writing your new driver in Visual Studio 2015.

----

**Hello Kernel**

To start, open Visual Studio 2015, under `File > New Project > Visual C++ > Legacy > Empty WDM Driver` create a new blank kernel-mode driver.

![create WDM](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/driverdev/driver5.png)

Under Solution Explorer right-click on your project file and select `properties > Configuration Properties > Driver Settings > General` over here you should change and adjust your target platform you want a driver built for. Now you can right-click and add a new C++ file as a new item.

First, you will want to define the ntddk.h header

```c
#include <ntddk.h>
```

When writing a normal C/C++ application you would be used to using `main` or something similar for the entry of your application, with KMDF driver development you will use `DriverEntry`

```c
NTSTATUS DriverEntry(
  _In_ PDRIVER_OBJECT  DriverObject,
  _In_ PUNICODE_STRING RegistryPath
);
```

DriverEntry is the entry for a driver, it's the first suppled routine that is called when a driver is loaded in the system.

- DriverObject - This is a pointer to the DRIVER_OBJECT data structure that can be found in wdm.h.
- RegistryPath - This is a pointer to the UNICODE_STRING data structure that specifies the path to the driver's key in the registry.

We will use `DbgPrint` to send a message to the kernel debugger.

```c
ULONG DbgPrint(
  PCSTR Format,
  ...   
);
```
If a driver routine succeeds, you need to return `STATUS_SUCCESS`, otherwise, it will give out errors.

For a driver unload functionality you need to add the unload function defined as a VOID.

```c
VOID Unload(IN PDRIVER_OBJECT DriverObject)
{
    DbgPrint("Driver Unloaded/r/n");
}
```

This will allow the driver to be unloaded. In your DriverEntry function, you also need to specify it with a pointer. 

`DriverObject->DriverUnload = Unload;`

Now you can build it for release. The full driver code is below.

```c
#include <ntddk.h>


VOID Unload(IN PDRIVER_OBJECT DriverObject)
{
    DbgPrint("Driver Unloaded/r/n");
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
    // Specify the callout driver's Unload function
    DriverObject->DriverUnload = Unload;

    DbgPrint("Hello Kernel!\n"); // printf()
    return STATUS_SUCCESS;
}
```

![driver release](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/driverdev/driver4.png)

It comes with the driver and the symbols which we can use soon in debugging it.

To load our new driver, we can use [OSRLoader](https://www.osronline.com/article.cfm%5Earticle=157.htm).

![osr loader](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/driverdev/driver6.png)

- Within OSR you need to select `Automatic` service start
- Within OSR you need to click Register Server and Start Service

You can confirm the driver is loaded and running by running the `driverquery` command from CMD.

![driver cmd](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/driverdev/driver7.png)


**Debugging our new driver**

In your kernel debugging environment, you can set a break with WinDBG and run the `ed Kd_DEFAULT_MASK 0xF` command to enable the output from our previously provided `DbgPrint` function that was used to print text.

![windows output kdprint](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/driverdev/driver8.png)

----

**Driver analysis in IDA Pro**

![ida 1](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/driverdev/ida2.png)

The main functions that you can see from IDA are the `DriverEntry` function and the `Unload` function which we defined when writing the kernel driver.

*DriverEntry*

```asm
DriverObject= dword ptr  8
RegistryPath= dword ptr  0Ch

push    ebp
mov     ebp, esp
push    offset Format   ; "Hello Kernel!\n"
call    _DbgPrint
mov     eax, [ebp+DriverObject]
pop     ecx
mov     dword ptr [eax+34h], offset _Unload@4 ; Unload(x)
xor     eax, eax
pop     ebp
retn    8
_DriverEntry@8 endp
```

*Unload*


```asm
; void __stdcall Unload(_DRIVER_OBJECT *DriverObject)
_Unload@4 proc near

DriverObject= dword ptr  8

push    offset aDriverUnloaded ; "Driver Unloaded\r\n"
call    _DbgPrint
pop     ecx
retn    4
_Unload@4 endp
```
