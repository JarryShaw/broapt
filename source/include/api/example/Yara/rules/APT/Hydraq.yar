rule Hydraq : APT
{
    meta:
        ref1 = "https://www.symantec.com/security_response/writeup.jsp?docid=2010-011114-1830-99&tabid=2"
        ref2 = "https://www.wired.com/2010/03/source-code-hacks/"
        ref3 = "https://www.symantec.com/connect/blogs/trojanhydraq-incident-analysis-aurora-0-day-exploit"
        ref4 = "https://www.symantec.com/connect/blogs/trojanhydraq-incident"
    strings:
        $file1 = "SYSPATH\\drivers\\etc\\network.ics" nocase wide
        $file2 = "SYSPATH\\acelpvc.dll" nocase wide
        $reg1 = "Software\\Sun\\1.1.2\\AppleTlk" nocase wide
        $reg2 = "Software\\Sun\\1.1.2\\IsoTp" nocase wide
        $driver = "acelpvc.sys" nocase wide
    condition:
        any of them
        //all of them
}