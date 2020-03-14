rule Unknown_9 : APT
{
    meta:
        ref1 = "https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/troj_dloadr.yq"
        ref2 = "https://home.mcafee.com/virusinfo/virusprofile.aspx?key=1727735#none"
    strings:
        $file = "SYSTEMROOT\\..\\Documents and Settings\\All Users\\Application Data\\Network" nocase wide
        $reg = "Software\\Microsoft\\MSFix" nocase wide
        $dirver = "w3ssl.sys" nocase wide
    condition:
        any of them
        //all of them
}