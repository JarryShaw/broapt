rule Agent_BTZ : APT
{
    meta:
        ref1 = "https://www.f-secure.com/v-descs/worm_w32_agent_btz.shtml"
        ref2 = "https://www.wired.com/2008/11/army-bans-usb-d/"
        ref3 = "http://blog.threatexpert.com/2008/11/agentbtz-threat-that-hit-pentagon.html"
    strings:
        $reg1 = "software\\microsoft\\windows\\currentversion\\StrtdCfg" nocase wide
    condition:
        any of them
        //all of them
}

