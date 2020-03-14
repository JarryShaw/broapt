rule Unknown_hash_3 : APT
{
    strings:
        $hash1 = "453F502CF1DB45BF234600D50127EC8FAD1003A6 "
    condition:
        any of them
}
