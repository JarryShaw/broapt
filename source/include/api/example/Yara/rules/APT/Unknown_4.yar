rule Unknown_4 : APT
{
    meta:
        ref1 = "http://telussecuritylabs.com/threats/show/TSL20120120-06"
    strings:
        $reg1 = "Software\\Microsoft\\Windows\\CurrentVersion\\policies\\Explorer\\Run\\ipmontr" nocase wide
        $reg2 = "Software\\Microsoft\\WinKernel\\Explorer\\Run\\ipmontr" nocase wide
        $dirver1 = "ipconfhlp.sys" nocase wide
        $file1 = "SYSPATH\\ipmontr.exe" nocase wide
        $file2 = "SYSPATH\\ipconfhlp.dll" nocase wide
    condition:
        any of them
        //all of them
}
