rule DarkHotel_hash : APT
{
    strings:
        $hash1 = "de4ff8901766e8fc89e8443f8732394618bf925ce29b6a8aafe1d60f496e7f0e"
    condition:
        any of them
}