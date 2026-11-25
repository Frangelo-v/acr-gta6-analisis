rule gta6_clipper
{
    strings:
        $mtx = "update-S-1-5-26-15297236-4840534596-8490206048-3100" wide
        $contract = "e9D1A9fB1C57a00e8D696FE799cD717c8f311ac9" nocase
    condition:
        uint16(0) == 0x5a4d and any of them
}

rule acr_proxy
{
    strings:
        $a = "github.com/acr/proxy-panel"
        $b = "zanakillakill"
    condition:
        uint16(0) == 0x5a4d and any of them
}

rule wsf_msbuild_loader
{
    strings:
        $a = "MSBUILDENABLEALLPROPERTYFUNCTIONS"
        $b = "MSBUILDDISABLENODEREUSE"
        $c = "WScript.Shell"
        $d = ".csproj"
    condition:
        filesize < 20KB and all of them
}
