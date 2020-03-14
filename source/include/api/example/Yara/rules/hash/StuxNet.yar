rule StuxNet_hash : APT
{
    strings:
        $hash1 = "b834ebeb777ea07fb6aab6bf35cdf07f"
        $hash2 = "ad19fbaa55e8ad585a97bbcddcde59d4"
        $hash3 = "f8153747bae8b4ae48837ee17172151e"
        $hash4 = "cc1db5360109de3b857654297d262ca1"
        $hash5 = "7a4e2d2638a454442efb95f23df391a1"
        $hash6 = "5b855cff1dba22ca12d4b70b43927db7"
        $hash7 = "ad19fbaa55e8ad585a97bbcddcde59d4"
        $hash8 = "d102bdad06b27616babe442e14461059"
        $hash9 = "b834ebeb777ea07fb6aab6bf35cdf07f"
    condition:
        any of them
}