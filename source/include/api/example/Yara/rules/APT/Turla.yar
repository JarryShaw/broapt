rule Turla : APT
{
    meta:
        ref1 = "https://totalhash.cymru.com/analysis/?4dd95ce1ec9941f362d4a6ceb65ab915dbfd9458"
        ref2 = "https://virustotal.com/hu/file/71eb7c15a026d011cca82fed8b634c10b569bb6b0cda1af532287218b9ee110f/analysis"
    strings:
        $reg1 = "System\\CurrentControlSet\\Control\\CrashImage" nocase wide
        $driver1 = "atmarpd.sys"  nocase wide
        $domain1 = "pressbrig1.tripod.com" nocase wide        
        $domain2 = "www.scifi.pages.at" nocase wide
        $hash1 = "4dd95ce1ec9941f362d4a6ceb65ab915dbfd9458" nocase wide
        $hash2 = "71eb7c15a026d011cca82fed8b634c10b569bb6b0cda1af532287218b9ee110f" nocase wide
    condition:
        any of them
        //all of them
}
