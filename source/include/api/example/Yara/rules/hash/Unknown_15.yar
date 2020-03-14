rule Unknown_hash_15 : APT
{
    strings:
        $hash1 = "2007aa72dfe0c6c93beb44f737b85b6cd487175e7abc6b717dae9344bed46c6c"
    condition:
        any of them
}
