rule Turla_hash : APT
{
    strings:
        $hash1 = "4dd95ce1ec9941f362d4a6ceb65ab915dbfd9458"
        $hash2 = "71eb7c15a026d011cca82fed8b634c10b569bb6b0cda1af532287218b9ee110f"
    condition:
        any of them
}
