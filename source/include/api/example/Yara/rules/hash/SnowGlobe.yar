rule SnowGlobe_hash : APT
{
    strings:
        $hash1 = "7ba09403e9d7122a20fa510de11f7809822e6e11efb164414e2148b762cf4e75"
    condition:
        any of them
}

