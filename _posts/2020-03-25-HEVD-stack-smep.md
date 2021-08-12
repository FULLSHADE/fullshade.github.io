---
layout: single
title: HEVD - Windows 10 1607 64-bit Kernel Stack Overflow with a SMEP bypass - flipping the CR4.SMEP bit
---

This post provides a walkthrough for exploiting the HEVD Windows Kernel Driver via the stack overflow vulnerability, including a full SMEP (Supervisor Mode Execution Prevention) bypass

Up until now all my HEVD Windows Kernel Driver exploitation posts have been covering exploiting HEVD on a 32-bit Windows 7 system without any mitigations. This post will cover porting the HEVD Stack Overflow exploit to Windows 8.1 and also including a full SMEP bypass via utilizing a ROP chain in Kernel-Space to run our shellcode from User-Land.


## What is SMEP

Supervisor Mode Execution Prevention (SMEP) is a hardware mitigation introduced by Intel (Intel has also referred to SMEP as “OS Guard”). SMEP was added to Windows 8 systems in 2011 by Microsoft to act as a hardware based kernel security mitigation technique on both 32 and 64 bit systems. SMEP has been implemented to specifically prevent privilege escalation attacks against the Windows kernel. To prevent attackers from user mode that exploit Kernel Mode areas to gain SYSTEM access.

This mitigation prevents attackers from launching malicious attacks against the kernel via acting as (somewhat) the ring0 version of DEP, where SMEP works to prevent the CPU from executing code that lies in usermode to be executed with Ring-0 privileges. SMEP essentially works to prevent non-privileged code or commands from being executed in locations when they are not supposed to be. If such code is detected, SMEP will throw a PAGE FAULT error, and invokes a BSOD with an error  of 0x000000fc.

## Deep SMEP internals

In the Intel manual in May of 2011, SMEP was documented in manual 3A, sections 2.5, SMEP is referred to as CR4.SMEP (CR4 is referring to the 4th control register (processor register) of the Intel CPUs in this context), Intels proposed idea is a security mitigation to thwart attackers from being able to conduct privilege escalation attacks. After Microsoft's implementation, All attackers that go after Windows 8 and above systems will need to consider bypassing SMEP. 

Intel’s control register CR4 includes 31 bits, bit 20 is the CR4.SMEP bit. This bit state can be set to either 1 or 0 in a binary like fashion. Where if CR4.SMEP holds a value of 1, CPU instructions may not be fetched from any user-mode process or any address that is running is user-mode. 

![smep 1](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/smep/smep1.png)

This is the security mitigation in play, where if SMEP is enabled (and it is implemented and enabled by default on Windows 8+ systems as mentioned above) it will stop attackers from being able to execute exploits which rely on usermode shellcode (commonly within privilege escalation kernel attacks, attacker will prepare and have usermode based shellcode executed from a rin0 privileged point of view, giving them SYSTEM access, this is where attackers have kernel drivers, or the kernel system redirect execution to a user mode prepared shellcode) 

And if the 20th bit is set to 0, SMEP is disabled and the access rights will depend on the paging mode and the value of IA32_EFER.NXE. For 32-bit paging, if IA32_EFER.NXE = 0, instructions may be fetched from any user-mode address. (SMEP disabled.

“CR4.SMEP, SMEP-Enable Bit (bit 20 of CR4) — Enables supervisor-mode execution prevention (SMEP) when set. See Section 4.6, “Access Rights”.”

The determination of access rights is split into either supervisor-mode access, or user-mode access, if the Current Privilege Level (CPL) is under 3 means it includes supervisor-mode access. And accesses that are CPL = 3 are user-mode accesses. The access rights depend on the value of SMEP (CR4.SMEP) as seen above. 

## HEVD on Windows 10

How exactly are we affected? Well, with the addition of SMEP now on our system, we need to add a new section to our HEVD kernel exploit, we need to create our ROP chain which will flip that CR4.SMEP bit. If we can acomplish that, we can get our normal exploitation going.
