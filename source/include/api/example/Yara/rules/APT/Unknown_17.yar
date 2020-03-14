rule Unknown_17 : APT
{
    strings:
        $reg = "Software\\Adobe\\Fix" nocase wide
        $file1 = "Local Settings\\Temp\\result.dat" nocase wide
        $file2 = "Local Settings\\Temp\\data.dat" nocase wide
        $file3 = "Local Settings\\Temp\\Acrobat.dll" nocase wide
        $file4 = "Local Settings\\Temp\\first.tmp" nocase wide
    condition:
        any of them
        //all of them
}