#Requires -RunAsAdministrator
#Requires -Modules xDSCResourceDesigner

$DSCResourceName = 'MSFT_xCertReq'

$Splat = @{
    Path = $PSScriptRoot
    ChildPath = "..\..\DSCResources\$DSCResourceName\$DSCResourceName.psm1"
    Resolve = $true
    ErrorAction = 'Stop'
}
$DSCResourceModuleFile = Get-Item -Path (Join-Path @Splat)

Describe "Schema Validation $DSCResourceName" {
    It 'should pass Test-xDscResource' {
        $result = Test-xDscResource -Name $DSCResourceModuleFile.DirectoryName
        $result | Should Be $true
    }

    It 'should pass Test-xDscSchema' {
        $Splat = @{
            Path = $DSCResourceModuleFile.DirectoryName
            ChildPath = "$($DSCResourceName).schema.mof"
        }
        $result = Test-xDscSchema -Path (Join-Path @Splat -Resolve -ErrorAction Stop)
        $result | Should Be $true
    }
}

if (Get-Module -Name $DSCResourceName)
{
    Remove-Module -Name $DSCResourceName
}
