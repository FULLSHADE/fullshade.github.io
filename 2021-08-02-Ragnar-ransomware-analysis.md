---
title: RagnarLocker Ransomware Malware Analysis Report
date: 2021-08-02
categories: [Malware, analysis]
tags: [malware analysis]
toc: true
---

# Introduction
RagnarLocker is a Windows based ransomware family that includes the ability to encrypt a systems files with the intention of financially extorting the victim for money. One of the most famous ransomware attacks involving Ragnar was the attack against the Portuguese company, EDP Group. During the attack, the Ragnar actors compromised the company’s network and later deployed the ransomware payload and demanded a payment of 1500+ Bitcoin. During the attack, the actors also exfiltrated around 10TB worth of internal documents from the company, which was used to doubly extort the victim. In order to regain access to their systems and to not have their internal, sensitive documents leaked, EDP Group would need to pay the ransomware actors. The malware sample analyzed in this post is one of the same samples involved in the EDP Group attack. The malware sample includes a EDP Group specific ransom note that can be obtain while decryption the configuration data from within the malware.

# Key Findings
- There is a decryption routine that at runtime will decrypt a list of process names, service names, public key, and ransomware note from the malwares internal encrypted configuration.
- The malware builds a unique hash value based on specific system information data points (username, hostname, etc.) which is later used when created a new event on the system with CreateEvent. This is to ensure the malware is only run once on the system (like how ransomware typically uses mutexes)
- The malware checks a list of hardcoded languages including Russian and Ukrainian, this is to avoid infected systems in those regions


# Overview

According to DIE (Detect It Easy) the sample does not appear to be packed, the sample is matches the signature which detects it as being compiled/linked using Microsoft Visual Studio 2017. While the first stage (main payload) payload isn't packed, that doesn't mean that other aspects of the malware are not. At runtime the malware may unpack and decrypt configurations, or additional, smaller pieces of code.

![68d6ab64dc0f41e6a19ab298c918649e](https://user-images.githubusercontent.com/70239991/127954405-2cda54a0-4548-4f69-ad80-ec1a41c79307.png)

According to other basic static analysis tools, the malware contains various suspicious function API imports, and libraries.The malware imports several API functions from the crypt32.dll cryptography library in addition to importing other suspicious functions. Imports such as:

- OpenProcessToken, SetTokenInformation, and DuplicateTokenEx - these functions are commonly abused by malware for manipulating the security tokens of a process, this is typically used for enabling the SeDebugPrivilege or SeLoadDriverPrivilege if the malware wants to load a rootkit onto the system.
- OpenServierA, OpenSCManagerA, EnumServicesStatusA - these functions all relate to abuse targeting the Windows Service Control Manager (SCM), these types of functions are commonly used for loading services for persistence purposes or for enumerating and terminating certain services by name for evasion purposes
- And many more suspicious function API imports.

According to the section information for the binary, it includes a section called ".keys", this is a good indication that the malware is embedding keys for the purpose of decryption some data such as an embedded configuration file or the public keys used for data encryption (due to this payload being ransomware).

![a0385237d1de498d9ee515980d262baf](https://user-images.githubusercontent.com/70239991/127954449-0b0ea4d3-f83a-4e66-bebd-4aa5ca8d8c64.png)

The malware sample also includes debug information that states the binary was compiled on Monday, April 6th of 2020.

![c9ce39abd7fd4a3ca02ac51048ba2a60](https://user-images.githubusercontent.com/70239991/127954463-7bed10ad-4a09-4e1c-8b39-76cb6a890d20.png)

# Technical Analysis

The samples entry function is responsible for carrying out the majority malicious activity.

On execution the sample first checks the installed languages on the victims system, this is done by calling the checkInstalledLanguages() function which calls the the API functions GetLocaleInfoW and compares the returned languages against a hard-coded array of language values. If a language on the "ignore" list is found, the executing process calls GetCurrentProcess to get a HANDLE to the calling process, and then calls TerminateProcess. This is a very common check performed by ransomware, typically EMEA based malware will ignore systems if they include language packs such as Russian,and others in the geographical region.

This version of the malware checks for:

> Azerbaijani, Armenian, Belarussian, Kazahk, Kyrgyz, Moldavian, Tajik, Russian, Turkmen, Uzbek, and Ukrainian

![6ccda84ae87a4065be6885e15b605aab](https://user-images.githubusercontent.com/70239991/127954809-726f4123-2568-4f79-a964-3f6bd58b911c.png)

After the initial language check occurs, if the victim does not include one of the "ignore" languages on their system, the malware gets the computers hostname, current users username, and queries a set of hard-coded Registry keys and values. The returned values from these queries are concatenated into a single variable which is then passed through a function responsible for generating a hash value.

![0dddcb2bfd524a61b641d629019cdcb4](https://user-images.githubusercontent.com/70239991/127954793-bbf0292e-92ae-46dc-a152-d6c0dd2bd6d7.png)

- The hash contains the systems hostname, the users username, the machines GUID value, and the value of "ProductName" (which includes a value such as "Windows 10 Pro") in the CurrentVersion Registry key.
- Prior to the hash encoding function is called, the unique ID is structured as &lt;GUID&gt;&lt;Product Name&gt;&lt;Username&gt;&lt;Hostname&gt; and turned into a unicode string

![32271f46da7140b998214309d92d82b5](https://user-images.githubusercontent.com/70239991/127954773-29b33805-4c86-4436-b25a-2c0bc7f568ed.png)

The hash generation algorithm is done by taking the string, XORing it against the value 0xab01ff3, and then performing a set of mathematical operations against it, ultimately resulting in a unique identifier being returned back to the program.

1.  The unique set of information is passed into the function as param_1
2.  Memory is allocated to contain the result of the hash calculation using VirtualAlloc
3.  A counter is set to 0 and the length of the input string is set to a local variable
4.  If the string is greater than 0, the input equals the input + the counter value
5.  The counter is incremented and the the input is XOR'ed against the value of 0xab01ff3
6.  The value is multiplied by 0x2000 and rotated 13 places to the right
7.  The final hash is returned back into the allocated memory region via wsprintf in a hex format

![a0920f2d14694db385a42d7af776fda3](https://user-images.githubusercontent.com/70239991/127954757-0dc38ffb-129a-49e6-a327-3946b874c8a9.png)


This unique hash value is later used for creating a new event (by name) on the system using the value.

![deb6dfbbea7540a5a8832a52e3bcff6e](https://user-images.githubusercontent.com/70239991/127954744-4ef39e60-9d93-460c-b67b-e29c6850a51d.png)


![96effe7caa354950ae4936c31df1ef51](https://user-images.githubusercontent.com/70239991/127954735-8ddb3088-1ac4-4437-afa7-231d34692e72.png)
