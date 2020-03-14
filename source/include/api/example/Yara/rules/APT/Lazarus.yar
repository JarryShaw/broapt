rule Lazarus : APT
{
    strings:
        $file1 = "SYSTEMROOT\\qtlib.sqt" nocase wide
        $file2 = "SYSTEMROOT\\zl4vq.sqt" nocase wide
        $file3 = "SYSTEMROOT\\dfrgntfs5.sqt" nocase wide
        $file4 = "SYSTEMROOT\\msvcrt58.sqt" nocase wide
    condition:
        any of them
        //all of them
}