rule Unknown_6 : APT
{
    meta:
        ref1 = "https://securelist.com/blog/incidents/34344/the-flame-questions-and-answers-51/"
        ref2 = "https://www.crysys.hu/skywiper/skywiper.pd"
    strings:
        $file1 = "SYSTEMROOT\\..\\Program Files\\common files\\microsoft shared\\msaudio" nocase wide
        $file2 = "SYSTEMROOT\\..\\Program Files\\common files\\microsoft shared\\mssecuritymgr" nocase wide
        $file3 = "SYSTEMROOT\\..\\Program Files\\common files\\micfosoft shared\\MSAPackages" nocase wide
    condition:
        any of them
        //all of them
}
