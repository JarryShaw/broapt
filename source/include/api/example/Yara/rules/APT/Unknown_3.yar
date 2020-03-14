rule Unknown_3 : APT
{
    meta:
        ref1 = "https://home.mcafee.com/virusinfo/virusprofile.aspx?key=4367516#non"
    strings:
        $service1 = "systmgmt" nocase wide
        $dirver1 = "syswpsvc.sys" nocase wide
        $reg1 = "system\\currentcontrolset\\services\\systmgmt\\Parameters\\ServiceDll" nocase wide
    condition:
        any of them
        //all of them
}
