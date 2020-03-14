rule Moonflower_hash : APT
{
    strings:
        $hash1 = "6719ff0eab92f8c88c0e34cb54ea92bb"
    condition:
        any of them
}

