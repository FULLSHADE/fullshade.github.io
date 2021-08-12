---
layout: single
title: Basics of Kernel-mode driver (IRPs) & I/O requests 
---

This post aims to give a better understanding of how I/O requests work within Windows internals.

**The Windows I/O model**

Within operating systems, each system has a method for handling I/O data from the system and with devices. Windows I/O supports asynchronous I/O.

The Windows I/O manager is the heart of the systems I/O, the Windows I/O manager provides an interface to kernel-mode drivers and intermediate and low-level system drivers. the Windows I/O manager is responsible for managing communication between applications and kernel-mode drivers. Since drivers don't always have speed that they operating on the same level as the operating system, driver communication is passed through the I/O manager, data that communicates from user-land the kernel-land drivers is done through via IRP requests and IRP packets (Input Output request packets), these are similar to network packets or Message packets. These IRP packets are passed around the operating system and from driver to driver.

When sending drivers IRPs, these must be done in a timely manner since incorrect handling of IRP requests on the kernel level may result in a system crash.

----

**IRP Distpatch  Routines**



----

**Manging and designing IRP requests**

You can use the IoAllocateIrp function for allocating an IRP, for specifying the parameters, the StackSize parameter is responsible for specifying the number of stack locations for the IRP. The `ChargeQuota` parameter can either be sent to `TRUE` or `FALSE`

- TRUE - If the user sents this calue to TRUE, it causes the memory that's allocated for the IRP to be charged against the quoata for the current process.

```c++
PIRP IoAllocateIrp(
  CCHAR   StackSize,
  BOOLEAN ChargeQuota
);
```
