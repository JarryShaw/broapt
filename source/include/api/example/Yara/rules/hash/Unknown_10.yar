rule Unknown_hash_10 : APT
{
    strings:
        $hash1 = "6b3f6b6fb370836ea78bbfb68f00308d374a897c"
    condition:
        any of them
}
