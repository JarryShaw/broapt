rule Unknown_hash_1 : APT
{
    strings:
        $hash1 = "bf9eba33cf5f161ae8260732ba0a80fbfacac99957d6b9fd4ca36795175dc798"
        $hash2 = "b3df5e63a72bf60c5ffda75e663037463874ccd446f123fca3630e7ce3f3b23a"
        $hash3 = "febc132c608fe85ecf4b235b80426cf2d722143fbfee5996fdaa167509115e60"
        $hash4 = "9e97a774cfc8a92e9f2dd6e074784dea215eceaf3dc90a560164aad98b9f9052"
        $hash5 = "53c0d4d159aad1022bd8c7df263921c9799bd31ee75515c84d05a77584ccf539"
        $hash6 = "d431ba45cc2182f7c9e153586a6b153a286ccfcd4f26d83d246c3611d48fced9"
    condition:
        any of them
}
