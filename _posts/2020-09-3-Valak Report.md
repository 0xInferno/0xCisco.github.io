---
layout: post
title:  Valak I Don't wanna die here
date:   2020-09-3 16:03:30 +0300
image:  05.jpg
tag:   Malware Analysis
---

### Introduction 

before that we just consider Valak as loader but it developed to become more than "Inforamtion Stealer" that and in last few months there was many waves of attacks with valak 

I got the malware from malware traffic analysis you Can find the files [here](https://www.malware-traffic-analysis.net/2020/07/01/index.html)

### First Stage : Downloader

###### MD55 : 49B144E57ED80D54533CF9B3C70D3FB4 

like all of nowadays malware it use doc files as a Downloader you can use tools like [Oledump](https://github.com/decalage2/oledump-contrib) or [Viper Monkey](https://github.com/decalage2/oledump-contrib) but I like to do it Manually 

![ExtractMacro](/img/Valak/macro.png)

so it Defines URLDownloadFileA as vY and download the next stage from the url  
hxxp[:]//detayworx[.]com/_vsnpNgyXp84Os8Xh[.]php?x=MDAwMSD7k0uWF2BKCkQGuSvAXqzhVD7pPpu-mirofSGC48QkKx26TywMByaP_nQjE_2EZXGfKy_H-gb2d-aDRgRbUwBi0XgbtTnVlugs38r3vI298UWyMzmQsvid4SyXJOUkCK4dpXj6mXuT7tTBXC3_-w~~

and Store it in c:\programdata\1.dat then run it with Regsvr32 you can get info about it [here](https://attack.mitre.org/techniques/T1218/010/) 



### Pre-Second Stage : Traffic-Analysis

###### Seems like the server is down so we gonna complete with the Pcap File

from the pcap if you open it in wireshark you should take a look to http exported objects you should found what are you looking for MZ Signature

![Pcap](/img/Valak/wireshark.png)



### Second Stage : Dropper

###### MD55 : 938B8214395F3DDE41C1646AF5558DCF 

if we take a look at pestedio we get that dll 

![pestdio](/img/Valak/pestedio.png)

so after looking to the imports , intropy , strings ...etc i would do my routine while try to unpack somefile with x64 
bp VirtualAlloc
bp VirtualAllocEx
bp VirtualProtect
bp VirtualProtectEx
bp CreateProcessInternalW

![lol](/img/Valak/explain.png)

but in our case in the imports IsDebuggerPersent so another break point on it and there is another anti-debugging tech
you will hit VirtualAlloc 3 times 
###### First Block : is a shell code that it will executes
###### Second Block : copied from the main Binary and Decrypted two times with shell code and it is a key to get the third block
###### Third Block : copied from first block and decrypted from shell code with Secoand block then some of it overwrite the Dll
in the third Block you will notice 2 MZ Signature and Some js code in the end you will know what its doing now 


![dump1](/img/Valak/dump.png) 

![dump2](/img/Valak/dump-2.png) 

![dump-js](/img/Valak/dump-js.png) 

at least drop one file the js code you found above and run it with [Wscript](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wscript) with WinExec WINAPI

or you Can just run it and watch the resaults with tool like Process Hacker or [Cmd Watcher](http://www.kahusecurity.com/tools.html) ;)

![Wscript](/img/Valak/wsscript.png)

### Third Stage : Valak ..

when you look at it its completly obfuscated , So good luck with it XD 
kidding I deobfuscated some needed parts of it so it Can be Readable take a look on [Pastebin](https://pastebin.com/HjG4mux8)

###### So in few words 
[-] it tries to connect some C2 server /* all of them is down unfortunately */ 

[-] when any c2 is responding it save it and user info in Registry

[-] get the user info from the ENV variable

[-] create a file in %TEMP%\\XXXX.bin Filenamed based on user inforamtion and writes its data with a WScript Stram 


That's it you can go back to Pcap and filter the packets and see the C2 Connections like that 

![last Stand](/img/Valak/lastStand.png)

### IOCS

| TYPE  | IOC               |
|:------|:------------------|
| Hash  | 49B144E57ED80D54533CF9B3C70D3FB4 |  
| Hash  | 938B8214395F3DDE41C1646AF5558DCF |
| Registry | HKEY_CURRENT_USER\\Software\\ApplicationContainer\\Appsw64\\ |
| Path  | C:\\Users\\Public\\MUIRtcp.xml |
| Path  | C:\\Users\\Public\\MUIJobsParser.js |

















