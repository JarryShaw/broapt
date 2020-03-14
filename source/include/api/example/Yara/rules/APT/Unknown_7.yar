rule Unknown_7 : APT
{
    meta:
        ref1 = "https://securelist.com/analysis/publications/68560/miniflame-aka-spe-elvis-and-his-friends/3/ "
        ref2 = "https://www.wired.com/2012/10/miniflame-espionage-tool/"
    strings:
        $file1 = "SYSPATH\\icsvnt32.dll" nocase wide
        $reg1 = "system\\currentcontrolset\\control\\timezoneinformation\\standarddatebias" nocase wide
        $reg2 = "system\\currentcontrolset\\control\\timezoneinformation\\standardtimebias" nocase wide
        $dirver = "icsvnt32.sys" nocase wide
    condition:
        any of them
        //all of them
}
