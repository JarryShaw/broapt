rule Unknown_15 : APT
{
    meta:
        ref1 = "https://malwr.com/analysis/ZTdlNjRmMGNhMzQzNGE5ZjhkM2Q5YmM1MjQzYzAwOWI/"
        ref2 = "http://www.crysys.hu/turlaepiccc/turla_epic_cc_v1.pdf"
        ref3 = "https://securelist.com/analysis/publications/65545/the-epic-turla-operation/"
    strings:
        $reg = "software\\microsoft\\NetWin" nocase wide
    condition:
        any of them
        //all of them
}