---
layout: single
title: Set up Immunity and WinDBG with Mona.py, set up a kernel debugging environment with WinDBG
---

### Set up Immunity Debugger with Mona.py

Mona.py can be downloaded from the offical corelan github repository, [https://github.com/corelan/mona](https://github.com/corelan/mona).

Immunity Debugger can be downloaded from https://www.immunityinc.com/products/debugger/when downloading it, you need to provide some basic information, your name, company, and so forth. After downloading Immunity Debugger from its host site run the installer. It may need to install Python when you first run it.

![setup1](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/setupdebug/setupImunWin1.png)

Add the mona.py extension for future exploitation simplification, you will need a copy of the Mona.py extension, this extension will help you automate your exploitation further down the road. You can download Mona.py from the official Corelan repository on Github found here. You will need to download the mona.py file and load it into Immunity debugger, this can be done by adding the extension to the `PyCommands` folder where you installed Immunity Debugger. 

By default Immunity should be installed at C:\Program Files\Immunity Inc\Immunity Debugger\PyCommands. If you run into any issue, make sure you click “unblock” on the downloaded mona.py file. Run the mona.py extension Now that you have Immunity Debugger installed, and the mona.py extension loaded up, reloadImmunity Debugger and use the !mona command on the command line on the bottom of the debugger. This will bring up the default mona information on how to use it. 

You can use the help command to get more information about specific commands with the syntax - !mona help<command>, the full mona.py tutorial can be found on the official Corelan website here.

![setup2](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/setupdebug/setupImunWin2.png)

----

### Set up WinDBG with Mona.py

WinDBG is a very powerful debugging tool for Windows, it’s also the debugger that this guide
will utilize the majority of the time. The Windows Debugger (WinDBG) can be used for both
user-land, and kernel-land debugging, which is the main reason that it's the most powerful
debugger one can use. It’s developed and distributed by Microsoft. You will need a copy of the
SDK/WDK toolkit which includes WinDBG, there is another WinDBG option called “WinDBG
Preview” which is available from the Microsoft store, it has a nicer GUI interface, but for this
guide, we will be using the standard WinDBG debugger. For Windows 7 you can download the
SDK kit from here. If you are on any other version of Windows (I.E. Windows XP, or Windows
10) which may end up happening if your debugging an older or newer piece of software, you will
just need to find the proper SDK kit for your Windows version so you can have access to
WinDBG.

When going through the installer, follow all the default options, but you may want to deselect
everything besides “Debugging tools” when you have the option, this will allow you to onlydownload WinDBG and debugging tools.

![setup3](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/setupdebug/setupImunWin3.png)

Installing WinDBG will also require the .Net framework tailored for your Windows version, just
follow all the default popups and installation that it gives you.

Now you can load up WinDBG. Don’t be intimidated by the default blank Window, if it’s not
already loaded, click View > Command, as the majority of our debugging will be purely via the
command line, learning WinDBG and it’s powerful commands will greatly improve your critical
debugging skills! If you want a little bit more “GUI”, you can click view on the top and open up
some other windows, registers, disassembly, call stack, and others which can make WinDBG
look a bit more friendly. You can search online for tutorials on how to make it a pretty interface if
you so desire. You can change up all the colors and customize it if you want.

If you want to load an application, you can either click File > Open Executable, or File > Attach
to a process, this should all be pretty self explanatory. In the instance that you are attaching a
running process to WinDBG, usually the most previous opened program is on the bottom of theselection list. F6 is the shortcut to attach to a running process, in this case we can test attaching
WinDBG to a notepad instance. By default when attaching a program it will automatically set a
breakpoint and pause the new program when loading a new application. You can press Go on
the top bar or F5 to allow the application to run again. You will get used to setting breakpoints
toexamine things throughout your debugging. When the debugger is running, you cannot run new
commands in the command line box on the bottom.

![setup4](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/setupdebug/setupImunWin4.png)

### Add the mona.py extension

Now let’s add mona.py to WinDBG to enable our full exploit-developer potential. In order to do
so, you can visit https://github.com/corelan/windbglib to download “windbglib” which is a
wrapper for pykd.pyd for WinDBG that allows you to utilize mona.py as a Python command
extension. You can follow the installation instructions from the repository.

1. Download pykd.zip from https://github.com/corelan/windbglib/raw/master/pykd/pykd.zip and
save it to a temporary location on your computer
2. Check the properties of the file and "Unblock" the file if necessary.
3. Extract the archive. You should get 2 files: pykd.pyd and vcredist_x86.exe
4. Run vcredist_x86.exe with administrator privileges and accept the default values.
5. Copy pykd.pyd to C:\Program Files (x86)\Windows Kits\8.0\Debuggers\x86\winext or C:\
Program Files (x86)\Windows Kits\10\Debuggers\x86\winext6. Open a command prompt with administrator privileges and run the following commands:
cd "C:\Program Files (x86)\Common Files\Microsoft Shared\VC"
regsvr32 msdia90.dll (You should get a messagebox indicating that the dll was registered
successfully)
7. Download windbglib.py from https://github.com/corelan/windbglib/raw/master/windbglib.py8.
8. Save the file under C:\Program Files (x86)\Windows Kits\8.0\Debuggers\x86 or C:\Program
Files (x86)\Windows Kits\10\Debuggers\x86 ("Unblock" the file if necessary)
9. Download mona.py from https://github.com/corelan/mona/raw/master/mona.py
10. Save the file under C:\Program Files (x86)\Windows Kits\8.0\Debuggers\x86 or C:\Program
Files (x86)\Windows Kits\10\Debuggers\x86 ("Unblock" the file if necessary)

The only issue that you may face with the instructions provided, you may not find the directory
the instructions mentions, but if that’s the case, just use the default \winext folder in your default
WinDBG installation folder. Just click > Open file location on your WinDBG icon and you’ll find
the winext folder. Once you have mona.py loaded into WinDBG after following the steps above,
we can use the !py mona command to run any mona.py commands.

![setup5](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/setupdebug/setupImunWin5.png)

You can now use mona.py within WinDBG just like you would use it with Immunity. The syntax
is just !py mona instead of just !mona.

----

### Set up a kernel debugging enviroment with WinDBG

The download link for Windbg [https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools)

This section is for later on when you get into kernel exploitation, within your kernel debugging environment you will have your host debugger, and the victim debugee. You can set this up by creating a single virtual machine, and then creating a linked clone of it. On the original machine you will have WinDBG. Act as the host debugger. 

![both machines](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/setupdebug/setupdebug1.png)

You can set up a virtual Serial port to connect the machines, the options should be matching as seen below. 

![serial ports](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/setupdebug/setupdebug2.png)

With kernel exploitation, you will run your kernel exploits on the victim machine, and the host debugger machine will have the ability to stop and pause the entire victim operating system. Compared to normal debugging, where you have the ability to pause and set breakpoints in a normal application, you can do that but on an entire system scale.

Once this is set up you start the host debugger machine first, and set the kernel debugging -> COM port in WinDBG, then start your victim machine, on boot you want to select the kernel debugging mode.

![boot mode](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/setupdebug/setupdebug3.png)

Now you can see your victim machine connects to the host WinDBG machine, and your kernel debugging envrioment is set up.

![final image](https://raw.githubusercontent.com/FULLSHADE/FULLSHADE.github.io/master/static/img/_posts/setupdebug/setupdebug4.png)

## Conclusion

Conclusively,  in this post you learned how to implement the mona.py  extension in both immunity debugger and WinDBG.  We  also covered how to set up a basic kernel debugging environment using virtualbox via named pipe Serial ports.
