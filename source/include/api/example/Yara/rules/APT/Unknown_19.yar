rule Unknown_19 : APT
{
    strings:
        $file1 = "SYSPATH\\ieloader.dll" nocase wide
        $file2 = "SYSPATH\\orepst.dll" nocase wide
        $file3 = "SYSPATH\\pstore.dll" nocase wide
    condition:
        any of them
        //all of them
}