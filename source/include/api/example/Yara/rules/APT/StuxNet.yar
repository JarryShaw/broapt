rule StuxNet : APT
{
    strings:
        $file1 = "SYSPATH\\s7otbxsx.dll" nocase wide
        $file2 = "SYSTEMROOT\\inf\\mdmcpq3.pnf" nocase wide
        $service1 = "mrxcls" nocase wide
        $dirver1 = "s7otbxsx.sys" nocase wide
        $dirver2 = "mrxcls.sys" nocase wide
        $dirver3 = "mrxnet.sys" nocase wide
        $dirver4 = "s7otbxdxa.sys" nocase wide
        $dirver5 = "jmidebs.sys" nocase wide
        $directory = "_LPDIR_LOGS\\Get_Files" nocase wide
    condition:
        any of them
        //all of them
}