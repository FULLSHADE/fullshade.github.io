---
layout: single
title: Leaking Kernel Addresses on Windows 10 1607, 1703, and 1809 - Undocumented Structures to Bypass KASLR
---

Over the years, Microsoft has implemented various security mitigation tactics within the Windows operating system to circumvent and thwart malicious actors from leveraging various types of exploitation techniques to obtain higher levels of privilege than they are supposed to have.

One of the security mitigations that has been implemented is known as **KASLR** (Kernel Address Space Layout/Load Randomization). KASLR makes windows kernel exploitation extremely difficult in the sense that it makes it almost impossible for attackers to obtain the Base address of the Windows kernel. Over the years security researchers and hackers alike have learned to bypass this via developing various types of information leakage vulnerabilities to take advantage of various aspects of the windows kernel to be able to leak the kernel addresses. 

This post will review a few of the various techniques (including POC code) that can be used to leak some windows kernel addresses on a **Windows 10 1607, 1703, and 1809** build.

Said kernel addresses may be combined with various exploitation tactics, this post will only focus on obtaining kernel leakage and not using this for exploitation, if an attacker needs to bypass KASLR, they can use these addresses to calculate other areas addresses or use this 


### Note 

This post will utilize various kernel address leakage vulnerabilities that only require a **low-integrity** level. There is the highly documented and used `NtQuerySystemInformation` API, but it requires at least a **medium-integrity** level to execute. If the execution context is at a low level, or you're within an application sandbox, these few leaks are for you.

This post will only be covering one leak per Windows version, as there are many dozens of different techniques, this post will cover a few favorite leaks.

----

### Windows 10 1607 kernel information leakage

The year is 2020, but let's take a quick journey back to 2016 when Microsoft released the `Creators Update` aka, Windows 1607. This post covers a few different techniques to leak kernel addresses on a Windows 10 (Redstone 1) system using C++ & win32k.sys. This post is also the complement to the Github repository which holds a few information leakage POCs for a few public bugs that I will be covering here.

The final code (POCs) for this can be found here - [https://github.com/FULLSHADE/LEAKYDRIPPER](https://github.com/FULLSHADE/Win10InfoLeaks)

----

Warning! - in 1607 there have been a few new mitigations, patches, and information leaks that have been patched, below are a few.

```
1. Base addresses of Page Tables are now randomized
2. Kernel addresses being leaked from GdiSharedHandleTable have also been removed
```

----

#### DesktopHeap (TEB.Win32ClientInfo) information leakage

To aid in the bypass of KASLR, you will need a to combine an information leakage bug with your exploit in order to obtain kernel addresses so you can locate other various structures (example: turning an arbitrary write into a classic WWW)

This leakage bug takes advantage of a kernel desktop heap that gets mapped into user-mode. It works on Windows 10 1607 and below. It has been patched with the 1703 update.

![windows versions](https://raw.githubusercontent.com/FULLSHADE/LEAKYDRIPPER/master/images/winVersions.png)

The Windows desktop heap is used by win32k.sys to store objects associated with the current given desktop. Every desktop object has a desktop heap associated with it, these desktop heaps store certain objects, including Windows, menus, and also hooks. And when an application requires a user interface to one of these objects, various functions from user32.dll are called to allocate these objects.

**Sources:**
- [1] [https://docs.microsoft.com/en-us/archive/blogs/ntdebugging/desktop-heap-overview](https://docs.microsoft.com/en-us/archive/blogs/ntdebugging/desktop-heap-overview)
- [2] [https://media.blackhat.com/bh-us-11/Mandt/BH_US_11_Mandt_win32k_WP.pdf](https://media.blackhat.com/bh-us-11/Mandt/BH_US_11_Mandt_win32k_WP.pdf)

With the Graphics Stack and win32k.sys, As soon as a GUI call is made, the function `PsConvertToGuiThread` function is used, and this function recognizes this is the first call to something like the Windows manager or GDI, and it's going to promote you with getting access to it. And it will switch you from the address table to the Shadow Address Table, which will give you access to the system calls. Switching it from `KeServiceDescriptorTable` to `KeServiceDescriptorTableShadow`

You might know of these of being familiar with this if you've ever done any kind of Windows hooking, for example, if you’ve ever dealt with hooking the system service dispatch table (SSDT).

**Sources**
- [1] [https://resources.infosecinstitute.com/hooking-system-service-dispatch-table-ssdt/](https://resources.infosecinstitute.com/hooking-system-service-dispatch-table-ssdt/)

#### Critical information

And for each GUI thread, win32k maps the associated desktop heap int the user-mode process, thus creating a bridge into kernel mode. And the information about a desktop heap is stored in the desktop information structure `_DESKTOPINFO`. This `_DESKTOPINFO` structure holds various kernel addresses of the desktop heap which are now accessible from user-mode. 

```
kd> dt win32k!tagDESKTOPINFO
+0x000 pvDesktopBase   :Ptr32 Void
+0x004 pvDesktopLimit  :Ptr32 Void
```

Our goal is to query both of these kernel addresses for our leakage.

#### Putting it all together

For this information leakage proof-of-concept, we will be utilizing the TEB (Thread Environment Block) along with various undocumented Windows structures, such as the `_DESKTOPINFO` structure, and the `_CLIENTINFO` structure to leak kernel addresses from the user-mode mapped desktop heap.

After the GUI conversion (mentioned above) takes place, your TEB (Thread Environment Block) will be populated with the `_DESKTOPINFO` structure, which will now include the kernel desktop heap pointers.

From within the undocumented structure `_DESKTOPINFO`, the desktop heap base kernel pointer is located in the member `pvDesktopBase`. And the desktop heap limit kernel pointer is located in the `pvDesktopLimit` member. The structure definitions for these undocumented structures come from the ReactOS project, below you can see the structures that we will utilize being defined.

```c++
typedef struct _DESKTOPINFO{
    PVOID pvDesktopBase;
    PVOID pvDesktopLimit;
} DESKTOPINFO, *PDESKTOPINFO;
```

- [Important to remember] The `pvDesktopBase` member point to the desktop heap base kernel pointer
- [Important to remember] The `pvDesktopBase` member point to the desktop heap limit kernel pointer

The second important structure member comes from the `_CLIENTINFO` structure, which is the `ulClientDelta` member. This member specifies the offset between a userland image and the kernel address, which can be used to compute the user-mode address of the desktop heap objects.

```c++
typedef struct _CLIENTINFO
{
    ULONG_PTR CI_flags;
    ULONG_PTR cSpins;
    DWORD dwExpWinVer;
    DWORD dwCompatFlags;
    DWORD dwCompatFlags2;
    DWORD dwTIFlags;
    PDESKTOPINFO pDeskInfo;
    ULONG_PTR ulClientDelta;
} CLIENTINFO, *PCLIENTINFO;
```

The Thread Environment Block contains an undocumented member that is called `Win32ClientInfo` ,  which is defined below.

You can use WinDBG to spot this at TEB+800.

![in windbg](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/inWindbg.png)

We can define this structure to include the Win32ClientInfo for future use. The [0x3E] within our structure definition is related to the value within it being a member in the TEB, 3E = 62 in hex, and you can see that in the above WinDBG output image.

```
typedef struct _TEB {
    UCHAR ignored[0x0800];
    ULONG_PTR Win32ClientInfo[0x3E]; // some undocumented stuff , located at TEB + 800
} TEB, *PTEB;
```

This will be used in our calculation formula to aid us in extracting the kernel addresses from the `_DESKTOPINFO` structure. 

**Sources:**
- [1] [https://doxygen.reactos.org/dd/d79/include_2ntuser_8h_source.html](https://doxygen.reactos.org/dd/d79/include_2ntuser_8h_source.html)
- [2] [https://reactos.org/wiki/Techwiki:Win32k/CLIENTINFO](https://reactos.org/wiki/Techwiki:Win32k/CLIENTINFO)
- [3] [https://github.com/55-AA/CVE-2016-3308](https://github.com/55-AA/CVE-2016-3308)

We can calculate the kernel addresses from the user-mode mapping of the desktop heap once you obtain the `ulClientDelta` member, you can then combine it with a simple calculation to extract the various members and obtain the final kernel addresses.

The calculation formula is as follows.

`NtCurrentTeb()->Win32ClientInfo.pDesktopInfo`

You can use the `NtCurrentTeb()` function to pull the current processes TEB, and now create a structure called `clientInfoStruct` which has a pointer to the `Win32ClientInfo` member of the `_TEB` defined structure. 

```c++
    PTEB pTeb = NtCurrentTeb();
    PCLIENTINFO clientInfoStruct = (PCLIENTINFO)pTeb->Win32ClientInfo;
```

This comes from Morten Schenks DEFCON talk

![mortens - talk](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/mortenstalk1.png)

Once you have this set up you can now use the provided formula to calculate out the various kernel addresses.

```c++
    ULONG_PTR ulClientDelta  = clientInfoStruct->ulClientDelta;
    PVOID pvDesktopBase = clientInfoStruct->pDeskInfo->pvDesktopBase;
    PVOID pvDesktopLimit = clientInfoStruct->pDeskInfo->pvDesktopLimit;
```

And now for the finale you can cout them to view the various (now) leaked kernel addresses.

```c++
    std::cout << "\t[>] ulClientDelta                : " << std::hex << "0x" << ulClientDelta << std::endl;
    std::cout << "\t[>] Kernel Desktop base address  : " << pvDesktopBase << std::endl;
    std::cout << "\t[>] Kernel Desktop limit address : " << pvDesktopLimit << std::endl;
```

![leaked](https://raw.githubusercontent.com/FULLSHADE/Win10InfoLeaks/master/images/DesktopHeapLeak.png)

#### Conclusion

We can use the user-mode mapped DesktopHeap combined with a few undocumented aspects of some data structures to leak various kernel addresses, these addresses can now be combined with a w^r primitive to bypass KASLR and locate and calculate kernel addresses (like taking an arbitrary write primitive and using these addresses to calculate the HAL table to create a classic WWW)

**Sources**
- [1] [http://cvr-data.blogspot.com/2016/11/lpe-vulnerabilities-exploitation-on.html](http://cvr-data.blogspot.com/2016/11/lpe-vulnerabilities-exploitation-on.html)
- [2] [https://www.youtube.com/watch?v=PTnuwchEci0](https://www.youtube.com/watch?v=PTnuwchEci0) (The lost video you didn't know existed...)
- [3] [https://www.youtube.com/watch?v=Gu_5kkErQ6Y](https://www.youtube.com/watch?v=Gu_5kkErQ6Y) (Morten Schenk - Taking Windows 10 Kernel Exploitation to the next level)

