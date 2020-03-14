rule Unknown_hash_18 : APT
{
    strings:
        $hash1 = "4f9786ddd6e75750221c59dcecc6e84822cf6050"
    condition:
        any of them
}
