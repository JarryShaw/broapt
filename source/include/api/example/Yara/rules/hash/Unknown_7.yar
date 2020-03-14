rule Unknown_hash_7 : APT
{
    strings:
        $hash = "ce792f3ed7eaa53b1a26bf0d879e861f645413c7f629e6db8e14a5feff61e517"
    condition:
        any of them
}