rule Unknown_4 : APT
{
    meta:
        ref1 = "http://telussecuritylabs.com/threats/show/TSL20120120-06"
    strings:
        $hash = "63d5d58cb833f84c4c2687a7cb8303ca1306022ba01f68337d2180fd6521def8"
    condition:
        any of them
}
