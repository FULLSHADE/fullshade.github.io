---
layout: single
title: Fuzzing drivers, techniques of the trade for discovering brand-new 0days
---

This post covers the needed knowledge to discover brand-new 0days throughout the internet, with this information, you will be able to fuzz and write new exploits for third-party drivers. 

## Introduction

Let's put everything together,  the scope for this kernel driver causing post is going to extend to third-party implemented kernel drivers. We are going to work to download applications that include drivers, discover driver permissions, and then unleash various fuzzing tools to obtain crashes that we will then analyze in WinDBG. 

Fuzzing can be a very  easy method to discover low-hanging fruit within third-party applications, the very Advanced and complex bugs that are commonly found throughout the windows kernel itself, usually take many weeks and even months to discover, reverse, and develop.  The scope of this post is to learn to fuzz third-party drivers to obtain vulnerabilities that we will be able to easily exploit.

Also, we are going to work to replicate crashes, rightful exploits, and learn some proper disclosure techniques when working with software vendors to work with them to provide security patches for their applications. 

This post will assume that you have already completed the majority of my other posts, and or ready come from a vulnerability researcher background with experience developing exploits and you just want to learn some new fuzzing techniques.

## Finding software + drivers to fuzz

For the means of discovering new vulnerabilities, and or your first 0 day in third-party kernel driver.  Utilizing the softpedia website will allow you to find applications and software that can include third-party drivers.  It's important to note that driver  Developers are fairly rare, so a lot of times applications are just copying and pasting code, which is one of the reasons why there's so many vulnerabilities in third-party drivers. 

When searching softpedia (or any site like it), filter by, and search for applications that include features such as graphics card settings, rootkit scanners, malware antivirus scanners, printer software, and any sort of user mode application that would communicate with some hardware aspect of your computer. These applications are likely to include if not many third-party drivers. 

- [https://win.softpedia.com/](https://win.softpedia.com/)

Once you find a Target application,  you can use the DriverView application to see any newly installed drivers on your system.

- [https://www.nirsoft.net/utils/driverview.html](https://www.nirsoft.net/utils/driverview.html)

![fuzz 2](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/fuzzing-drivers/fuzz2.png)

Listed above shows what DriverView looks like.

But make sure to sort by hiding microsoft drivers, since you only want to target third-party installed ones (at this point in time)


## Tools for fuzzing

The majority of our vulnerability discovery will come from generating random input and sending it to IOCTLs via kernel driver communication.  This type of fuzzing will allow us to discover easy to reverse, and easy to exploit vulnerabilities in applications. 

**ioctlfuzzer1.3**

- [https://code.google.com/archive/p/ioctlfuzzer/](https://code.google.com/archive/p/ioctlfuzzer/)

The first fuzzer I will utilize after downloading an application with drivers, is ioctlfuzzer1.3,  this father allows you to mass discover and mass fuzz any IRP requests that are being sent throughout the io of the system.  this Falls are usually allows  for quick and easy vulnerability discovery, usually within 10 to 15 seconds of unleashing this fuzzer upon an applications kernel drivers.

This fuzzer allows you to configure which drivers and IOCTLs  you want to focus on, an  insert of a common configuration that can be used to discover driver can be seen below. When setting the configuration XML file, you need to specify and create a section for allowed drivers.

```xml
  <!--
      IOCTLs "allow" list.
   
      The fuzzer will process (i.e. log and/or fuzz) any IOCTL request 
      containing at least one parameter from the <allow> list.
   
      If the list is empty, each IRP will be processed.
  --> 

  <allow>
    <driver val="example.sys" />
    <driver val="example.sys" />
    <driver val="example.sys" />
    <driver val="example.sys" />
    <driver val="example.sys" />
  </allow>
```
Once your fuzzing victim machine is attached to a host debugger, you can now unleash this fuzzer with any victim drivers you want to target. 

**Important** the entire point of using this fuzzer is to mass fuzz an applications installed drivers, make sure you use and configure the config xml file. 

![fuzz 1](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/fuzzing-drivers/fuzz1.png)

**IOCTLbf**
- https://github.com/koutto/ioctlbf

IOCTLbf is a fairly lightweight and simple fuzzer, this mainly relies on the fact that you already have and know of a pre-existing IOCTL.  This fuzzer will allow you to generate and send random input to any provided IOCTL.

**Practical - demonstration time**

Now that we know which fuzzers we can use to easily discover vulnerabilities in a driver, here's a demonstration.

## Reverse engineering with IDA

After obtaining a crash in a kernel driver, we now want to reverse-engineer the driver  to fully grasp and understand why and how the vulnerability exists.  We will be using Ida Pro for this section of 0 day discovery.

After you obtain a crash from fuzzing, you need to load the driver up in Ida Pro and navigate to wear that IOCTL is located, IOCTLs  can commonly be found within the dispatch function of a kernel driver.  You can use the listed below plugins to easily automate this process of locating IOCTLs  within a kernel driver in Ida Pro.

**win_driver_plugin**

- https://github.com/FSecureLABS/win_driver_plugin

**Driver buddy**

Another IOCTL  Discovery Ida Pro plugin is  the driver buddy plug-in. This plug-in allows you to easily scan a driver for dispatch function, and any ICOTLs  that may reside throughout the driver.

- https://github.com/nccgroup/DriverBuddy


**Practical - demonstration time**

Now that we've discovered a crash in the previously noted driver, let's load it up into Ida Pro and discover exactly why it crashed. 

## Replicating crashes

## Writing full exploits

## Proper disclosure with vendors

Developing a vulnerability disclosure policy is very important when getting into the field of security research, working with software vendors can be a tedious task, but it does have a good payoff.  properly working with a software vendor can result in bug bounties, and or  exposure from the vendor.  The most important (and fun) part of vulnerability research is discovering the vulnerabilities, it can be a hobby, or a job.

My personal CVE designation and vulnerability disclosure policy can be found on my CVE collection page. 

## Conclusion
