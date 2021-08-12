---
layout: single
title: HEVD - Windows 7 x86 Non-Paged Pool Overflow utilizing Pool Feng-Shui - pool heap grooming
---

This post covers the exploitation of a basic pool overflow vulnerability that resides in a kernel-mode third-party driver, exploitation on a Windows 7 x86 system (executable pool).

## Kernel pool memory

In kernel mode, for memory allocation there are memory pools, which is a kernel object that will allow memory blocks to be dynamically allocated when needed. The memory manager will create memory pools that the system and kernel-mode drivers can use to allocate memory. 

There are two types of memory pools, `NonPaged pools` and `Paged pools`. Both of these memory pool types are located in the address space region that is reserved for system memory allocation.

To learn more about kernel-mode memory pools you can refer to the previously written post linked below.

- https://fullpwnops.com/Windows-pool-and-vulns/

## Kernel pool exploitation

As for the kernel-mode driver HEVD, there is what's known as a kernel pool overflow vulnerability, where it doesn't properly manage user input, and essentially what occurs is a form of an out-of-bounds vulnerability but just within kernel pool memory.

To take advantage of this type of vulnerability we are going to have to spray the kernel pool to groom it in such a manner that we can predictably set it up so we can call our shellcode from a memory location. We are going to have to influence the pool allocator and it's deallocation mechanisms.

This driver's vulnerability allows for a user buffer that's a located in a nonpaged pool, so we will allocate and groom the nonpaged pool with various types of kernel mode allocated objects.

## Windows 7's executable pools

Since this exploitation is taking place on a Windows 7 system, the `NonPagedPool` functions are in play when it comes to kernel pool memory usage, which means that pools are executable, which makes pool overflow exploitation a whole lot easier. 

After Windows 7, the `NonPagedPoolNx` function was introduced to allow for the usage of pools that are marked as non-executable, this new function basically allows for pools to have NX enabled. And Windows will use it by default now, meaning, if your writing a pool overflow exploit on a Windows 10 system, you would need an information leakage 

Again, this exploit is on a Windows 7 system, so we won't need to go down the information leakage path just yet, that may come in a later post where I try to port this pool overflow exploits to Windows 10. More details on Windows 10 pool overflow exploitation and leakage may come at a later time.

## HEVD - Skeleton crash

## HEVD - Pool grooming with event objects

## HEVD - Finalization and a shell

## Microsofts mitigation
