rule Unknown_13 : APT
{
    meta:
        ref = "https://webcache.googleusercontent.com/search?q=cache:8oUmzaCr0zoJ:https://kam.lt/download/48227/assessment%2520of%2520threat%2520to%2520national%2520security%25202015.pdf+&cd=3&hl=en&ct=clnk&gl=hu"
    strings:
        $file1 = "SYSPATH\\nsecm.dll" nocase wide
        $driver = "nsecm.sys " nocase wide
    condition:
        any of them
        //all of them
}