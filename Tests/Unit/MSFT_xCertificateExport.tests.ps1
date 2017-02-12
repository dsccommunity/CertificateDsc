$script:DSCModuleName      = 'xCertificate'
$script:DSCResourceName    = 'MSFT_xCertificateExport'

#region HEADER
# Integration Test Template Version: 1.1.0
[String] $script:moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ( (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
     (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone','https://github.com/PowerShell/DscResource.Tests.git',(Join-Path -Path $script:moduleRoot -ChildPath '\DSCResource.Tests\'))
}

Import-Module (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1') -Force
$TestEnvironment = Initialize-TestEnvironment `
    -DSCModuleName $script:DSCModuleName `
    -DSCResourceName $script:DSCResourceName `
    -TestType Unit
#endregion

# Begin Testing
try
{
    InModuleScope $script:DSCResourceName {
        $DSCResourceName = 'MSFT_xCertificateExport'

        $certPath = Join-Path -Path $ENV:Temp -ChildPath 'xCertificateExportTestCert.cer'
        $pfxPath = Join-Path -Path $ENV:Temp -ChildPath 'xCertificateExportTestCert.cer'
        $certDNSNames = @('www.fabrikam.com', 'www.contoso.com')
        $certKeyUsage = @('DigitalSignature','DataEncipherment')
        $certEKU = @('Server Authentication','Client authentication')
        $certSubject = 'CN=contoso, DC=com'
        $certFriendlyName = 'Contoso Test Cert'

        $validCert = New-Object -TypeName PSObject -Property @{
            Thumbprint   = $certThumbprint
            Subject      = "CN=$certSubject"
            Issuer       = "CN=$certSubject"
            FriendlyName = $certFriendlyName
            DnsNameList  = @(
                @{ Unicode = $certDNSNames[0] }
                @{ Unicode = $certDNSNames[1] }
            )
            Extensions   = @(
                @{ EnhancedKeyUsages = ($certKeyUsage -join ', ') }
            )
            EnhancedKeyUsages = @(
                @{ FriendlyName = $certEKU[0] }
                @{ FriendlyName = $certEKU[1] }
            )
            NotBefore    = (Get-Date).AddDays(-30) # Issued on
            NotAfter     = (Get-Date).AddDays(31) # Expires after
        }

        Describe "$DSCResourceName\Get-TargetResource" {
            Context 'Certificate has been exported' {
                Mock `
                    -CommandName Test-Path `
                    -MockWith { $True } `
                    -ParameterFilter { $Path -eq $certPath } `
                    -Verifiable

                It 'should return IsExported true' {
                    $Result = Get-TargetResource -Path $certPath -Verbose
                    $Result.IsExported | Should Be $True
                }
                It 'should call the expected mocks' {
                    Assert-VerifiableMocks
                }
            }

            Context 'Certificate has not been exported' {
                Mock `
                    -CommandName Test-Path `
                    -MockWith { $False } `
                    -ParameterFilter { $Path -eq $certPath } `
                    -Verifiable

                It 'should return IsExported false' {
                    $Result = Get-TargetResource -Path $certPath -Verbose
                    $Result.IsExported | Should Be $False
                }
                It 'should call the expected mocks' {
                    Assert-VerifiableMocks
                }
            }
        }

        Describe "$DSCResourceName\Test-TargetResource" {
        }
        Describe "$DSCResourceName\Set-TargetResource" {
        }
    }
}
finally
{
    #region FOOTER
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
    #endregion
}
