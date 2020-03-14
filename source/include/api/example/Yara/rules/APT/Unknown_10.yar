rule Unknown_10 : APT
{
    meta:
        ref1 = "https://www.mcafee.com/threat-intelligence/malware/default.aspx?id=305192"
    strings:
        $file1 = "SYSPATH\\winview.ocs" nocase wide
        $file2 = "SYSPATH\\Mfc42l00.pdb" nocase wide
        $file3 = "SYSPATH\\ISUninst.bin" nocase wide
        $file4 = "SYSPATH\\mswmpdat.tlb" nocase wide
        $file5 = "SYSPATH\\wmmini.swp" nocase wide
        $file6 = "SYSPATH\\wowmgr.exe" nocase wide
        $file7 = "SYSTEMROOT\\winstat.pdr" nocase wide
        $service = "WOWmanager" nocase wide
    condition:
        any of them
        //all of them
}