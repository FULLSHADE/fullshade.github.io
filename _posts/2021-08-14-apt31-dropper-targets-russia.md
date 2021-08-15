---
title: Chinese APT31 Droppers Targeting Russian Government Analysis
date: 2021-08-14
---

The Chinese nation state group APT31 also known as ZIRCONIUM, JUDGMENT PANDA, and BRONZE VINEWOOD carried out offensive cyber operations against targets in Russia, Belarus, and others between January and July of 2021. This attack included malware in the form of droppers that lead to the deployment of backdoors. The droppers rely on DLL-sideloading to load the malicious second stage payload. APT31 is a Chinese backed nation state APT group that provides the Chinese government and state-owned enterprises with information to aid in political, economic, and military advantages. The group has a history of targeting government related organizations.  

# Key Findings

-	The first stage dropper includes two embedded Windows PE files that are written to disk on execution
-	The two dropped files work together to execute the second stage payload (file2 that is dropped) via DLL-sideloading
-	The legitimate file (file1) loads and calls the export function _initterm_e from the malicious DLL library (file2)
-	The second stage payload services the purpose of using the Windows WinInet library to download and execute a third stage payload from an embedded C2 server
-	The dropped payload that get's loaded through DLL sideloading is responsible for performing the following actions:
    * Maintain persistence on the target system via the Windows Registry
    * Download and write a payload to disk from an embedded C2 Server

# Analysis
The dropper analyzed in this post includes two embedded files within it’s .rdata section, these two embedded files are dropped to disk using standard Windows API functions such as CreateFileA and WriteFile. Of the two embedded files, one is a legitimate instance of ssvagent.exe which is an update agent for Java, while the other is a malicious second-stage payload that mimics the legitimate MSVCR100.dll library that ssvagent.exe would normally load when executed.

Looking at the dropper payload in DIE and other static analysis tools indicates that the PE is not packed, the PE file is a Microsoft Visual C/C++ compiled binary, compiled for 32-bit, and was compiled on February 18th, 2021. Based on the original timeline, this payload was compiled and used during the later stages of the offensive operation. The PE file imports four libraries including wtsapi32.dll, kernel32.dll, user32.dll, and shell32.dll. From the function imports there are a few semi-suspicious functions such as WTSGetActiveConsoleSessionId, WTSQueryUserToken, CreateProcessA, GetCurrentProcessId, and ShellExecuteW.

![image](https://user-images.githubusercontent.com/54753063/129459474-68edd396-6a8d-4c90-9c4f-dbedbe2131b6.png)

On execution, the dropper first checks for the existence of the second stage payload on disk, it check for the legitimate application ssvvagent.exe within C:\ProgramData\Apacha\ssvagent.exe using FindFirstFileA. If the file does not exist it them also checks for the directory that the file would be dropped to at C:\ProgramData\Apacha, if either of these don’t exist, it will create them. If the dropped files don’t exist on disk, the dropper uses CreateFileA and WriteFile to locate and write out the embedded files to their respective locations on disk.

![image](https://user-images.githubusercontent.com/54753063/129459479-6c0a79e9-f870-461c-9341-46da53999897.png)

If the files do exist on disk the dropper will execute the second stage payload by calling `CreateProcessA` with the location of the legitimate (dropped) ssvagent.exe file. When this new process is executed it creates a new thread with CreateThread that results in a fake Windows message box popping up stating that there was some kind of installation error. If the new process fails to be created, it calls the `TerminateCurrentProcess` function which gets the current process and then calls `TerminateProcess`.

![image](https://user-images.githubusercontent.com/54753063/129459483-77d32760-0018-4488-8c89-8c7dcecf248f.png)

After all is successful, the current process is terminated. 

![image](https://user-images.githubusercontent.com/54753063/129459486-adbb7d50-1c1d-402a-9c60-ee744438fedf.png)

When WriteFile is called twice, the following “files” are dropped to disk from within the droppers .rdata section. There are two embedded executables (file1 = the legitimate application, file2 = loaded by file1 through DLL-sideloading)

![image](https://user-images.githubusercontent.com/54753063/129459510-400b7a8d-b6cf-4b56-ba5b-e2f4ad8939e4.png)

Searching HXD allows you to locate and then dump out the embedded files without needing to execute or debug the dropper.

![image](https://user-images.githubusercontent.com/54753063/129459514-c813c473-1e47-4172-bb7d-bbece28fdecd.png)

Located at offset `10FCE` is the malicious DLL file that gets dropped to disk

![image](https://user-images.githubusercontent.com/54753063/129459516-fe22ed94-268f-4901-923d-868d2bb88300.png)

Located at offset `13DCE` is the legitimate application that is responsible for loading the malicious second stage payload through DLL-sideloading.

![image](https://user-images.githubusercontent.com/54753063/129459519-63f2ae49-ff9a-489a-8e81-e2bc5cd122b2.png)
 
Debugging the dropped and setting a breakpoint on WriteFile allows you to capture the embedded PE files written to disk.

![image](https://user-images.githubusercontent.com/54753063/129459520-878902a1-1a47-47d0-b648-12e9ff3439fd.png)

Inspecting the application ssvagent.exe that was dropped to disk reveals that within its function imports, it request the `_initterm_a` function from within msvcr100.dll. In this case msvcr100.dll was replaced with a malicious second stage payload. But this gives us the first clue on how to locate the main malicious section of code within msvcr.dll that was dropped along with ssvagent.exe from the dropper payload.

![image](https://user-images.githubusercontent.com/54753063/129460102-05384664-8c0f-4abd-8609-01f38f2d561b.png)

# Second Stage Payload

When setting up malicious DLLs for replacing a legitimate DLL during DLL sideloading you want to set up the proper export functions so the main application that loads it can execute your malicious code. Typically you will see a malicious DLL that includes all of the same export names that the legitimate version would have, but instead of containing the legitimate code in those functions, it replacing the code with calls to `ExitProcess` or similar. In this case the exported function that get's executed first calls what ends up being the malicious payload and then there is a call to `ExitProcess`.

![image](https://user-images.githubusercontent.com/54753063/129460117-8c1b2e70-784a-4477-930a-cc431619f1a3.png)

Through the first function call made (observed above) the main section of the malicious second stage payload is executed. For a seemingly unknown reasons the payload first decides to enumerate all of the running processes using `CreateToolhelp32Snapshot` with `TH32CS_SNAPPROCES` as the first flags parameter. The payload doesn't seem to store or use the information returned from enumerating the running processes on the system.

Next, the payload checks to see if `ssvagent.dll` exists on disk within the same directory that this second stage payload was dropped to. The file `ssvagent.dll` is the main payload that this stager is responsible for downloading from the C2 server. If the file is found on disk the payload continue to create a new mutex with `CreateMutex` called "ssvagent". After this it checks the last error code against the code for `ERROR_ALREADY_EXISTS` to see if it succeeded, if it doesn't then the process exists with `ExistProcess` Then the process will sleep for 60000 milliseconds before maintaining persistence on the system.

![image](https://user-images.githubusercontent.com/54753063/129462447-627cc754-330d-4fba-bf86-5845c35e71a5.png)

Within the `DownloadFromC2Server` function, setting a breakpoint on the first call to `InternetCrackUrlA` reveals the first parameter `pszUrl` which is equal to the C2 server that the payload will attempt to download a file from.

![image](https://user-images.githubusercontent.com/54753063/129462046-55be7a6f-eaf4-4cff-a734-23448668c2ef.png)

![image](https://user-images.githubusercontent.com/54753063/129462699-a38c41ca-7129-47d4-9997-f5269f2a78ff.png)

![image](https://user-images.githubusercontent.com/54753063/129462690-a825d4ce-5b1b-439f-9684-02d2c011196c.png)

![image](https://user-images.githubusercontent.com/54753063/129462685-8e594c57-fa90-40ab-8246-28eac8f26725.png)

# Rules And Indicators

# Resources

- https://www.ptsecurity.com/ww-en/analytics/pt-esc-threat-intelligence/apt31-new-attacks/
- https://therecord.media/finland-pins-parliament-hack-on-chinese-hacking-group-apt31/
