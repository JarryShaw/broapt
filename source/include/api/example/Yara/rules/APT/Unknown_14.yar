rule Unknown_14 : APT
{
    strings:
        $file1 = "SYSTEMROOT\\temp\\temp56273.pdf" nocase wide
        // $file2 = "SYSTEMROOT\\..\\Documents and Settings\\*\\Local Settings\\History\\cache\\iecache.dll" nocase wide
        $file2 = "Local Settings\\History\\cache\\iecache.dll" nocase wide
    condition:
        any of them
        //all of them
}