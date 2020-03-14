rule Unknown_hash_9 : APT
{
    strings:
        $hash1 = "8805f1d7d603face71d5c926af7d7e84e7120456"
        $hash2 = "c924855408cca3dc55555f5b9ad1e1f2ab3b3d1558e13e8464f3db4578d41056"
        $hash3 = "12f5968b1d551f7a35adc482f5cfe957b1caf0513daba9c6c7187b478ddc81a7"
        $hash4 = "23be7e7eeb654533ca82bd6564a6ddf53a31eb61f4793856106da7d979764fa8"
        $hash5 = "9344b0b20a28fd50e28025c984cbeaff8216cfaab247dbca57f680f1356eec2a"
        $hash6 = "9363ae91667316a3bbffaf47d181d84c8a832812b4d89a56e942b32337f76b9a"
        $hash7 = "6e3a7fe487b928726fb55907faa344dcfd10b0e3c0bfc3c2e8268bd5baef19d1"
        $hash8 = "ba5f55cca1d119fa602cc21b5b3dfbe2a47f5416ecdcf5c165ef635d5a4eeb62"
    condition:
        any of them
}