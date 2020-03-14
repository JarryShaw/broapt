rule Unknown_11 : APT
{
    meta:
        ref = ""
    strings:
        $dirver1 = "rpclog.sys" nocase wide
        $dirver2 = "winext32.sys" nocase wide
        $dirver3 = "winip.sys" nocase wide
        $file1 = "SYSPATH\\taskbar.exe" nocase wide
        $file2 = "SYSPATH\\MsgQueue.exe" nocase wide
        $file3 = "SYSPATH\\SndTray.exe" nocase wide
        $file4 = "SYSPATH\\msserv.exe" nocase wide
        $file5 = "SYSPATH\\sed.exe" nocase wide
        $file6 = "SYSPATH\\winip.drv" nocase wide
        $file7 = "SYSPATH\\winext32.dll" nocase wide
        $file8 = "SYSPATH\\rpclog.dll" nocase wide
        $file9 = "SYSPATH\\rpclog.dll" nocase wide
        $file10 = "c:\\applicationdata\\appdata1\\logFile.txt" nocase wide
        $file11 = "%USERPROFILE%\\MyHood\\btmn\\system\\temp\\cnf.txt" nocase wide
        $file12 = "c:\\syslog\\temp\\012tg7\\system\\cnf.txt" nocase wide
        $process1 = "taskbar.exe" nocase wide
        $process2 = "MsgQueue.exe" nocase wide
        $process3 = "SndTray.exe" nocase wide
        $process4 = "msserv.exe" nocase wide
        $reg1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\newval" nocase wide
        $reg2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsFirewallSecurityServ" nocase wide
        $reg3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\slidebar" nocase wide
        $reg4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\MSDeviceDriver" nocase wide
        $service = "Recover" nocase wide
    condition:
        any of them
        //4 of them
}