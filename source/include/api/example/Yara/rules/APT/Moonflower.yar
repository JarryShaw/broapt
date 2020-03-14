rule Moonflower : APT
{
    meta:
        ref = "https://webcache.googleusercontent.com/search?q=cache:8oUmzaCr0zoJ:https://kam.lt/download/48227/assessment%2520of%2520threat%2520to%2520national%2520security%25202015.pdf+&cd=3&hl=en&ct=clnk&gl=hu"
    strings:
        $file1 = "SYSTEMROOT\\..\\Documents and Settings\\All Users\\Application ata\\msncp.exe" nocase wide
        $file2 = "SYSTEMROOT\\..\\Documents and Settings\\All Users\\Application Data\\netsvcs.exe" nocase wide
        $file3 = "SYSPATH\\msprnt.exe" nocase wide
        $file4 = "SYSPATH\\fmem.dll" nocase wide
        $file5 = "SYSTEMROOT\\..\\Program Files\\common files\\microsoft shared\\Triedit\\htmlprsr.exe" nocase wide
        $file6 = "SYSTEMROOT\\..\\Program Files\\common files\\microsoft shared\\Triedit\\dhtmled.dll" nocase wide
        $file7 = "SYSTEMROOT\\..\\Program Files\\common files\\microsoft shared\\Triedit\\TRIEDIT.TLB" nocase wide
        $service1 = "pnppci" nocase wide
        $service2 = "ethio" nocase wide
        $service3 = "ntdos505" nocase wide
        $service4 = "ndisio" nocase wide
        $dirver1 = "dhtmled.sys" nocase wide
        $dirver2 = "ethio.sys" nocase wide
        $dirver3 = "fmem.sys" nocase wide
        $dirver4 = "ntdos505.sys" nocase wide
        $dirver5 = "pnppci.sys" nocase wide
        $dirver6 = "triedit.sys" nocase wide
        $dirver7 = "vgx.sys" nocase wide
    condition:
        any of them
        //5 of them
}