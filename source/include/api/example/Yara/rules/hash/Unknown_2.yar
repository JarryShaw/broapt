rule Unknown_hash_2 : APT
{
    strings:
        $hash1 = "33460a8f849550267910b7893f0867afe55a5a24452d538f796d9674e629acc4"
    condition:
        any of them
}
