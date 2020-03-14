rule Unknown_1 : APT
{
    meta:
        ref1 = "https://www.trendmicro.com/vinfo/us/threat-encyclopedia/archive/malware/troj_shipup.ar"
        ref2 = "https://www.mcafee.com/threat-intelligence/malware/default.aspx?id=141194"
    strings:
        $directory1 = "SYSPATH\\driver32\\ldf" nocase wide
    condition:
        any of them
        //all of them
}
