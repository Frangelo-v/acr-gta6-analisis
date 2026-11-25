rule clipper_audio_service_helper
{
    strings:
        $mutex = "update-S-1-5-26-15297236-4840534596-8490206048-3100" wide
        $contrato = "e9D1A9fB1C57a00e8D696FE799cD717c8f311ac9" ascii nocase
    condition:
        uint16(0) == 0x5a4d and any of them
}

rule proxy_acr_panel
{
    strings:
        $ruta = "github.com/acr/proxy-panel" ascii
        $c2 = "zanakillakill" ascii
    condition:
        uint16(0) == 0x5a4d and any of them
}

rule wsf_msbuild_property_functions
{
    meta:
        nota = "lanzador: prende las property functions y abre un csproj con MSBuild"
    strings:
        $a = "MSBUILDENABLEALLPROPERTYFUNCTIONS" ascii
        $b = "MSBUILDDISABLENODEREUSE" ascii
        $c = "WScript.Shell" ascii
        $d = ".csproj" ascii
    condition:
        filesize < 20KB and all of them
}
