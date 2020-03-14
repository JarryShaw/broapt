rule Flame : APT
{
    strings:
        $file1 = "SYSPATH\\indsvc32.ocx" nocase wide
        $file2 = "SYSTEMROOT\\temp\\indsvc32.ocx " nocase wide
    condition:
        any of them
        //all of them
}