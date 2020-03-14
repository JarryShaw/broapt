rule Unknown_18 : APT
{
    meta:
        ref1 = "https://www.symantec.com/security_response/writeup.jsp?docid=2011-011117-0057-99&tabid=2"
        ref2 = "https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/troj_hidfile.ab"
        ref3 = "https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=%0A%09%09%09%09Trojan:Win32/Rotinom.A%0A%09%09%09%09&ThreatID=%0A%09%09%09%09-2147413137%0A%09%09%09%09"
        ref4 = "https://www.mcafee.com/threat-intelligence/malware/default.aspx?id=253485"
        ref5 = "https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/troj_cmse.a"
    strings:
        // $file1 = "SYSTEMROOT\\..\\ Documents and Settings\\*\\LocalSettings\\Application Data\\S-1-5-31-1286970278978-5713669491-166975984-320" nocase wide
        $file1 = "LocalSettings\\Application Data\\S-1-5-31-1286970278978-5713669491-166975984-320" nocase wide
    condition:
        any of them
        //all of them
}