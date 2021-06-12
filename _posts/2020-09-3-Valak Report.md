---
layout: post
title:  Valak I Don't wanna die here
date:   2020-09-3 16:03:30 +0300
image:  05.jpg
tag:   [Malware Analysis , Valak]
---

### Introduction 

before that we just consider Valak as loader but it developed to become more than **Inforamtion Stealer - outlook** that and in last few months there was many waves of attacks with valak 

I got the malware from malware traffic analysis you Can find the files [here](https://www.malware-traffic-analysis.net/2020/07/01/index.html)

### First Stage : Downloader

###### MD55 : 49B144E57ED80D54533CF9B3C70D3FB4 

like all of nowadays malware it use doc files as a Downloader you can use tools like [Oledump](https://github.com/decalage2/oledump-contrib) or [Viper Monkey](https://github.com/decalage2/oledump-contrib) but I like to do it Manually 

![ExtractMacro](/img/Valak/FirstStage/macro.png)

so it Defines URLDownloadFileA as vY and download the next stage from the url  
hxxp[:]//detayworx[.]com/_vsnpNgyXp84Os8Xh[.]php?x=MDAwMSD7k0uWF2BKCkQGuSvAXqzhVD7pPpu-mirofSGC48QkKx26TywMByaP_nQjE_2EZXGfKy_H-gb2d-aDRgRbUwBi0XgbtTnVlugs38r3vI298UWyMzmQsvid4SyXJOUkCK4dpXj6mXuT7tTBXC3_-w~~

and Store it in c:\programdata\1.dat then run it with Regsvr32 you can get info about it [here](https://attack.mitre.org/techniques/T1218/010/) 



### Pre-Second Stage : Traffic-Analysis

###### Seems like the server is down so we gonna complete with the Pcap File

from the pcap if you open it in wireshark you should take a look to http exported objects you should found what are you looking for MZ Signature

![Pcap](/img/Valak/FirstStage/wireshark.png)



### Second Stage : Dropper

###### MD55 : 938B8214395F3DDE41C1646AF5558DCF 

if we take a look at pestedio we get that dll its Orginal name is **kill.dll**

![pestdio](/img/Valak/FirstStage/pestedio.png)

but we also see that we got some debug information also 

![debuginfo](/img/Valak/FirstStage/debug_path.png)

another thing intersting we found url but it does nothing **hxxps[:]//ladymatch[.]ru**

so after looking to the imports , intropy , strings ...etc i would do my routine while try to unpack somefile with x64 
bp VirtualAlloc , VirtualAllocEx , VirtualProtect , VirtualProtectEx , CreateProcessInternalW
but in our case in the imports IsDebuggerPersent so another break point on it


![lol](/img/Valak/SecondStage/dll.png)


###### Importanat Note ...

you must specify the binary you work with **Regsvr32** then change the cmd to include the dll cause it is hard run it with **rundll32**-I mean you should specify function name or ordinal number - or loaddll from ollydbg try it on any.run [here](https://app.any.run/tasks/fcf8673a-fb77-4403-8a7d-84b436dd62b2) 
the reason of that the dll main function after unpacking is **DllRegisterServer** that better works with regsvr32 binary
Dont get confused i get it after ending the analysis just tell you the reason now ;) or you can just try your luck with ***rundll32 dllname.dll,#1*** 


![cmd](/img/Valak/SecondStage/cmd.png)


so First thing you will hit a Weird three VirtualProtect and one VirtualProtectEx Functions that change the same adress of memory and amount to same mem protection to make it from **RW** to **RWE**


![changeShellCodeProtection](/img/Valak/SecondStage/changeShellCodePrtectionBeforeAllocation.png)


so now its time to execute that shellcode in the Orginal binary and Decrypt itself
this Decryption algo we will met it many times in this Binary i will Call it XOR123 If i met it soon dont be confused from the name
simply this function takes a Value to Start DEcrypt with Stored in edx take first byte of it decrypt 3 bytes with it then modify itself with Some opreation and go again till ecx become 0


![virtual protect 1 Decode](/img/Valak/SecondStage/virtualProtect-1-Decode.png)


after that it still wanna get some imports by passsing two values to the function One for module and the other for function how is that work ?
then first he get all of the modules to file throw PEB when it get the one it wants then get into its export table and search for function names 

![get modules](/img/Valak/SecondStage/get-imports.png)

then how it knwo its the one function or module? it use a function that calculate a value take a string for the module or the function name then compare it with value if its the one he want set eax to 0 

![Calculate string Value](/img/Valak/SecondStage/CalculateStringValueAlgorthim.png)

at least he get some functions **VirtualFree** , **VirtualAlloc** , **VirtualProtect** , **FlsFree** , **GetProcAdress** , **LoadLibraryExA**

i think its a good time to allocate the shell code of course it will be copied from orginal binary and jmp to it 

![First Alloc](/img/Valak/SecondStage/FirstAlloc.png)

so we talked about key of data before its time to allocate it first its data is copied from the orginal file then it decrypt twice 

![Allocation of key](/img/Valak/SecondStage/AllocationOfKey.png)

first Decryption method take a key from shellcode just a few bytes based on that bytes it copies data from one place to another from the same memory first time it do nothing as it is the same start it use the bytes of key once for copy data and the other to do some calc and increase the source of the next time we will face this method once more so i will Call it **Replacement Method**

![Decode Replacing](/img/Valak/SecondStage/decodereplacingtothe3rdAlloc.png)

Second Decryption we Dealt with before i you remmber we called it XOR123 take a look to it up if you forgot it 

now we face the third and the last Call to VirtaulALlloc this time it contains some interesting stuff so 

![third allocation](/img/Valak/SecondStage/virtualAlloc-3.png)


now he allocate the memory then call a function that copy the data from orginal binary with the help of key 
it takes four bytes from key the **first word --> Detrmines the length of buffer copied** and the  **secoand word --> Detrmines how many bytes should be ignored after the last data** of course the address of data in orginal binary  passed to the function as you see in the last pic


![Virtual 3 Decode](/img/Valak/SecondStage/virtual-3-decode.png)


then it frees the key as no need for it anymore and now there is two methods 
** first one is Replacment Method but the funny thing its used with the same key XD **
** Second Method is XOR123 ** so we end it here :)

so if you take a look to this mem you will notice 2 MZ Signature overwrite the Dll file with and Some js code in the end you will know what its doing now 


![dump1](/img/Valak/SecondStage/dump.png) 

![dump2](/img/Valak/SecondStage/dump-2.png) 

![dump-js](/img/Valak/SecondStage/dump-js.png) 


now it change the the protection of orginal file 

![change protection header .text](/img/Valak/SecondStage/changeProtection.png)

and so he must zeroout file header and .text section 

![zero header .text](/img/Valak/SecondStage/zeroOutFileheader.png)

then write data **header and .text** to orginal binary from the second exe file we saw in last mem allocaion 

![write header](/img/Valak/SecondStage/writeDatatoOrginalBinary.png)

rewrite import table with LoadLibraryEx and GetProcAddress

![resolve import table](/img/Valak/SecondStage/resolveimportTable.png)

so now changing the orginal file protection and we done 

![change the protection last](/img/Valak/SecondStage/changeProtectionTofileaftermodifing.png)

so back to the orginal file and now it unpacked so you need to dump it may be with **scylla** , **ollydump** or if you an old school you could use **impREC**

but there is way you might don't know follow me ;)

![unpack](/img/Valak/SecondStage/unpack.gif)

for good Q you Can download the vedio [here](https://drive.google.com/file/d/1KlpmJEOT5Ys9fmJFm0lzTReYgq3PMnX1/view?usp=sharing)


So dump the dll with Process Hacker you will see the imports is invalid so we gonna change the Raw Adress and Raw Size "when i say raw i mean the image on disk" to make it like Virtual "image in Memory" Address is wasy but the Size i calculate it by dividing the start adress of the current Section with the start adress of the next section in the last section ".reloc" make it very big to make it fill the size of file  


so now you will see the time stamp and ther is only export function that called **DllRegisterServer** 
at least drop one file the js code you found above and run it with [Wscript](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wscript) with WinExec WINAPI

![ida](/img/Valak/SecondStage/ida.png)


###### Lazy Like me ?

or you Can just run it and watch the resaults with tool like Process Hacker or [Cmd Watcher](http://www.kahusecurity.com/tools.html) ;)


![Wscript](/img/Valak/SecondStage/wsscript.png)


### Third Stage : Valak [Downloader]..

when you look at it its completly obfuscated , So good luck with it XD 
kidding I deobfuscated some needed parts of it so it Can be Readable take a look on [Pastebin](https://pastebin.com/HjG4mux8)

###### So .....

[-] First thing it tries to checkout the SystemUpTime and compare it with 3000 if it less than that its quit the Script like **Anti-vm** Tech  


![Systemuptime](/img/Valak/ThirdStage/SystemUpTime.png)


[-] then it Attems to Connect many C2 Urls After modifying it for 20 times you see it here /*unfortunately all of them is Down */ 


![c2](/img/Valak/ThirdStage/C2Info.png)


[-] for genrating url params it requires a lot information from Env like user name and Domain name ... etc nad other things like bitness /* get it with looking for a registry value string if */ and systemuptime, then hash it and genrate key based on random number then choose from an array of strings as a key for RC4 Encryption method


![Create PARAMS](/img/Valak/ThirdStage/CreatePramas.png)


[-] so when it get the Response its encrypted with the same algo but it will be decrypted with our script because if you look deebly in the url data you should see the malware send the key in the last of the url after **&cst** so its read response of the request with creating **xmldom object** pass it to **ADODB Stream Object** to define encoding then return the text then Decrypt it write the Url into registry if it connected successfully


![ReadResponse](/img/Valak/ThirdStage/ReadResponse.png)


[-] I know its a liitle bit confusing but in simple way forget about encryption and hash the response split into 2 peices one to create a new JS file **MUIJobsParser.js** and the other is to create .net binary "unkown name --> based on your personal info" /*its downloaded in base64 format*/ and then genrate a new key with length 124 in new XML File , create a new task with schtasks to run new js file


![ReadResponse](/img/Valak/ThirdStage/downloadFiles.png)


### fourth Stage : downloader and launcher

you can use a tool called **imaginaryC2** to unpack pcap or simulate the c2 even if its down but its impossible in our case cause the url is dynmaic based on your data , you Can find it [here](https://github.com/felixweyne/imaginaryC2)

so first thing its doing to get the last **JS** file throw registry and load its objects and functions 

![load functions](/img/Valak/fourthStage/getlastjs.png)

then its now try to connect the same C2 Again but with diffrent url Decypt the response data as it base64 then it scans for two values 

![c2 Connections](/img/Valak/fourthStage/ConnectC2.png)


in the first case it looks for --Task it will find it with 2 values , first it makes a file stream on XML files created last Stage with one value of respond in our case **5e3fb8fe** and the other text is .exe file that is saved to the stream and run after 2 minutes 
you can download the response after decryption [here](https://drive.google.com/file/d/1nWIsph9YUkgAgF-zj3DNsiz6puSt_GQk/view?usp=sharing) 

![first response](/img/Valak/fourthStage/xmlstream.png)

the second is searching for --Plugin-- that time is seaching for an argument to run the .net file that dropped last stage and run it 
you will not find that response in the last tool so i get it from the pcap in wireshark
**--PLUGIN3--**


![Second Response](/img/Valak/fourthStage/getargsandrun.net.png)



![packet](/img/Valak/fourthStage/packet2.png)

so we end that we still have one .net binary and native binary 

### fifth Stage : Credential Stealer

###### PluginHost2.exe
###### MD55 : BD2095893C3FA73141BE729880053E9C 

so now we will deal with .net binary but we will also still dealing with pcap cause it also still connecting to c2 by getting it from regisrty saved but this time download a string as a raw assembly bytes **Dll**, get an object from it and at least get constructor of it 

![get c2 from registry](/img/Valak/Dotnet/exe_getValidC2.png)


![exeloaddll](/img/Valak/Dotnet/exe_loaddll.png)

In genral Cases you Can just debug then dump this data save it as .bin file but now you will do the same thing with **imaginaryC2** or **WireShark** 5292 is the packet number you want its a base64 with null terminated byte remove it decode the file bingo!

![exeloaddll](/img/Valak/Dotnet/dll_dump.png)

###### MangedPlugin.dll
###### MD55 : 444E0C51C6C09DC43E67FECF7F3000FE

So first thing it import CredEnumrate from Advapi32 to get credential of the Current Session

![import advapi32](/img/Valak/Dotnet/dll_getCredentiel.png)

then searching fro Outlook or office if it exssits or not if it  is , it will search in path **C:\Users\User\AppData\Local\Microsoft** for AutoDiscover.xml get the Data from it decode it with base64 then connect to C2 **you will not found that request in pcap may be the infected machine has no outlook on it**

![dll Xml](/img/Valak/Dotnet/dll_autoDiscoverxml.png)

then get the hashed user data saved in **HKEY_CURRENT_USER\Software\ApplicationContainer\Appsw64\SetupServiceKey** with getid() function then send the reqest with data 

![get query](/img/Valak/Dotnet/dll_urlgenrator.png)






### IOCS


| TYPE  | IOC               |
|:------|:------------------|
| Hash  | 49B144E57ED80D54533CF9B3C70D3FB4 |  
| Hash  | 938B8214395F3DDE41C1646AF5558DCF |
| Hash  | BD2095893C3FA73141BE729880053E9C |
| Hash  | 444E0C51C6C09DC43E67FECF7F3000FE |
| Registry | HKEY_CURRENT_USER\\Software\\ApplicationContainer\\Appsw64\\ |
| Path  | C:\\Users\\Public\\MUIRtcp.xml |
| Path  | C:\\Users\\Public\\MUIJobsParser.js |
| C2  | dev.visualwebsiteoptimizer.com |
| C2  | rad.msn.com.nsatc.net |
| C2  | tss-geotrust-crl.thawte.com |
| C2  | delandwinebar.com |
| C2  | yongcan0f.com |
| C2  | 2020aix.com |
| C2  | 31pces-walk.com |
| C2  | 59siwf-farm.com |
| C2  | 61wsov-ring.com |


















