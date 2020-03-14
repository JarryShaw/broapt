rule Unknown_2 : APT
{
    meta:
        ref1 = "http://blog.talosintelligence.com/2014/04/snake-campaign-few-words-about-uroburos.html"
        ref2 = "http://thehackernews.com/2014/03/uroburos-rootkit-most-sophisticated-3.html"
    strings:
        $directory1 = "SYSPATH\\driver32\\ldf" nocase wide
        $file1 = "\\.\\Hd1" nocase wide
        $file2 = "\\.\\Hd2" nocase wide
        $file3 = "\\.\\IdeDrive1" nocase wide
        $file4 = "\\.\\IdeDrive2" nocase wide
        $dirver1 = "fdisk.sys" nocase wide
    condition:
        any of them
        //all of them
}
