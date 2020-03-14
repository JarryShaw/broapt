rule Unknown_5 : APT
{
    meta:
        ref1 = "https://www.sophos.com/en-us/threat-center/threat-analyses/viruses-and-spyware/Troj~Octa-B/detailed-analysis.aspx"
        ref2 = "https://www.symantec.com/security_response/writeup.jsp?docid=2003-040713-2623-99&tabid=2"
        ref3 = ""
    strings:
        $reg1 = "Software\\Microsoft\\Windows\\CurrentVersion\\policies\\Explorer\\Run\\Internet32" nocase wide
        $dirver1 = "internat.sys" nocase wide
        $file1 = "SYSPATH\\internat32.exe" nocase wide
        $file2 = "SYSPATH\\sbool\\msadp32.exe" nocase wide
        $file3 = "SYSPATH\\Internat.dll" nocase wide
    condition:
        any of them
        //all of them
}
