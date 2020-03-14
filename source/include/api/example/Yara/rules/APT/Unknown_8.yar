rule Unknown_8 : APT
{
    meta:
        ref = ""
    strings:
        $process1 = "ups32.exe" nocase wide
        $process2 = "utilman32.exe" nocase wide
        $file1 = "SYSPATH\\ups32.exe" nocase wide
        $file2 = "SYSPATH\\utilman32.exe" nocase wide
        $file3 = "SYSPATH\\utliman32.exe" nocase wide
        $file4 = "SYSPATH\\drivers\\ups.exe" nocase wide
        $file5 = "SYSPATH\\msvcp11.dll" nocase wide
        $file6 = "SYSPATH\\msxml10.dll" nocase wide
    condition:
        any of them
        //all of them
}
