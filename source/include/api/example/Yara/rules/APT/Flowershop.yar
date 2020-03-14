rule Flowershop : APT
{
    meta:
        ref1 = "https://malware-research.org/prepare-father-of-stuxnet-news-are-coming/"
    strings:
        $file1 = "SYSPATH\\ADWM.DLL" nocase wide
        $file2 = "SYSPATH\\ADWM.DLL" nocase wide
        $file3 = "SYSPATH\\ASFIPC.DLL" nocase wide
        $file4 = "SYSPATH\\BROWUI.DLL" nocase wide
        $file5 = "SYSPATH\\CAPESPN.DLL" nocase wide
        $file6 = "SYSPATH\\CFGKRNL3.DLL" nocase wide
        $file7 = "SYSPATH\\CRYPTKRN.DLL" nocase wide
        $file8 = "SYSPATH\\DESKKRNE.DLL" nocase wide
        $file9 = "SYSPATH\\DSKMGR.DLL" nocase wide
        $file10 = "SYSPATH\\EXPLORED.DLL" nocase wide
        $file11 = "SYSPATH\\FMEM.DLL" nocase wide
        $file12 = "SYSPATH\\HDDBACK4.DLL" nocase wide
        $file13 = "SYSPATH\\HWMAP.DLL" nocase wide
        $file14 = "SYSPATH\\ipnetd.dll" nocase wide
        $file15 = "SYSPATH\\IPNETD.DLL" nocase wide
        $file16 = "SYSPATH\\KNRLADD.DLL" nocase wide
        $file17 = "SYSPATH\\MAILAPIC.DLL" nocase wide
        $file18 = "SYSPATH\\MSGRTHLP.DLL" nocase wide
        $file19 = "SYSPATH\\MSIAXCPL.DLL" nocase wide
        $file20 = "SYSPATH\\MSID32.DLL" nocase wide
        $file21 = "SYSPATH\\MSRECV40.DLL" nocase wide
        $file22 = "SYSPATH\\NCFG.DLL" nocase wide
        $file23 = "SYSPATH\\PARALEUI.DLL" nocase wide
        $file24 = "SYSPATH\\secur16.dll" nocase wide
        $file25 = "SYSPATH\\SECUR16.DLL" nocase wide
        $file26 = "SYSPATH\\SOUNDLOC.DLL" nocase wide
        $file27 = "SYSPATH\\WINF.DLL" nocase wide
        $file28 = "SYSPATH\\WMCRT.DLL" nocase wide
        $file29 = "SYSPATH\\wbem\\logs file" nocase wide
        $file30 = "SYSTEMROOT\\help\\* file" nocase wide
        $file31 = "Program Files\\common widefiles\\system\\msadc" nocase wide
        $reg = "Lnkfile\\shellex\\IconHandler\\OptionFlags" nocase wide
        $dirver1 = "ndisalex.sys" nocase wide
        $dirver2 = "ndisio32.sys" nocase wide
        $dirver3 = "paravdm.sys" nocase wide
    condition:
        any of them
        //5 of them
}

