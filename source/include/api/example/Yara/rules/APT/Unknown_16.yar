rule Unknown_16 : APT
{
    strings:
        $file1 = "SYSPATH\\drivers\\mfc64comm.sys" nocase wide
        $file2 = "SYSPATH\\drivers\\adap64info.sys" nocase wide
        $driver1 = "adap64info.sys" nocase wide
        $driver2 = "mfc64comm.sys" nocase wide
    condition:
        any of them
        //all of them
}