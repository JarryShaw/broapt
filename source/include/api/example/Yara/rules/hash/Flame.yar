rule Flame_hash : APT
{
    strings:
        $hash1 = "554924ebdde8e68cb8d367b8e9a016c5908640954ec9fb936ece07ac4c5e1b75"
        $hash2 = "333875eb8a6baa773d69e38e8f05d914def30750fdec3d9f2c8fbb01efa80fe1"
        $hash3 = "9bae0b89aa47f37f199d0b38ca8631020c9d221ea3e66aafecb7105c064ae343"
        $hash4 = "c6776d9ebe91b2d33b3ac36c845528fd7a81b35095beffbd2ea080fe6eab67cf"
    condition:
        any of them
}