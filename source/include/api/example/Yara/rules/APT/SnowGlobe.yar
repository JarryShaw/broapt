rule SnowGlobe : APT
{
    meta:
        ref1 = "https://www.welivesecurity.com/2015/06/30/dino-spying-malware-analyzed/"
        ref2 = "https://securelist.com/blog/research/69114/animals-in-the-apt-farm/"
    strings:
        $file1 = "SYSTEMROOT\\svchost00000000-0000-0000-0000-0000-00000000.dat" nocase wide
        $file2 = "PROFILE_PATH\\All Users\\update.msi" nocase wide
        $file3 = "PROFILE_PATH\\All Users\\Application Data\\update.msi" nocase wide
        $file4 = "$(ProgramData)\\MSI\\update.msi" nocase wide
        $file5 = "PROGRAM_FILES\\Common Files\\wusvcd.exe" nocase wide
        $file6 = "PROGRAM_FILES\\Common Files\\wusvcd\\wusvcd.exe" nocase wide
        $file7 = "SYSTEMROOT\\..\\ Documents and Settings\\ *\\Application Data\\Microsoft\\wmimgnt.dll" nocase wide
        $file8 = "SYSTEMROOT\\..\\ Documents and Settings\\ *\\Application Data\\Microsoft\\wmimgnt.exe" nocase wide
        $directory1 = "SYSPATH\\Microsoft\\Windows Management Infrastructure" nocase wide
        $directory2 = "SYSTEMROOT\\Microsoft\\ Windows Management Infrastructure" nocase wide
        $service1 = "WinMI32" nocase wide
        $reg = "Software\\Microsoft\\WinMI" nocase wide
    condition:
        any of them
        //5 of them
}
