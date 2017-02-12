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
        $pfxPath = Join-Path -Path $ENV:Temp -ChildPath 'xCertificateExportTestCert.pfx'
        $certDNSNames = @('www.fabrikam.com', 'www.contoso.com')
        $certKeyUsage = @('DigitalSignature','DataEncipherment')
        $certEKU = @('Server Authentication','Client authentication')
        $certSubject = 'CN=contoso, DC=com'
        $certFriendlyName = 'Contoso Test Cert'
        $certThumbprint = '1111111111111111111111111111111111111111'
        $certStore = 'My'

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

        $validCertParams = @{
            Path             = $certPath
            Thumbprint       = $certThumbprint
            FriendlyName     = $certFriendlyName
            Subject          = $certSubject
            DNSName          = $certDNSNames
            Issuer           = $certSubject
            KeyUsage         = $certKeyUsage
            EnhancedKeyUsage = $certEKU
            Store            = $certStore
            AllowExpired     = $False
            MatchSource      = $True
            Type             = 'Cert'
        }

        $pfxPlainTextPassword = 'P@ssword!1'
        $pfxPassword = ConvertTo-SecureString -String $pfxPlainTextPassword -AsPlainText -Force
        $pfxCred = New-Object -TypeName System.Management.Automation.PSCredential `
            -ArgumentList ('Dummy',$pfxPassword)

        $validPfxParams = @{
            Path             = $PfxPath
            Thumbprint       = $certThumbprint
            FriendlyName     = $certFriendlyName
            Subject          = $certSubject
            DNSName          = $certDNSNames
            Issuer           = $certSubject
            KeyUsage         = $certKeyUsage
            EnhancedKeyUsage = $certEKU
            Store            = $certStore
            AllowExpired     = $False
            MatchSource      = $True
            Password         = $pfxCred
            ProtectTo        = 'Administrators'
            Type             = 'PFX'
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

        Describe "$DSCResourceName\Set-TargetResource" {
            Mock `
                -CommandName Find-Certificate `
                -MockWith { } `
                -Verifiable

            Context 'Certificate is not found' {
                It 'should not throw exception' {
                    { Set-TargetResource @validCertParams -Verbose } | Should Not Throw
                }
                It 'should call the expected mocks' {
                    Assert-VerifiableMocks
                }
            }

            Context 'Certificate is found and needs to be exported as Cert' {
                # Needs to be done because Export-Certificate requires a real cert object
                function Export-Certificate {
                    [CmdletBinding()]
                    param
                    (
                        $FilePath,
                        $Cert,
                        $Force,
                        $Type
                    )
                }
                Mock `
                    -CommandName Find-Certificate `
                    -MockWith { $validCert } `
                    -Verifiable
                Mock `
                    -CommandName Export-Certificate `
                    -Verifiable
                Mock `
                    -CommandName Export-PfxCertificate

                It 'should not throw exception' {
                    { Set-TargetResource @validCertParams -Verbose } | Should Not Throw
                }
                It 'should call the expected mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Export-PfxCertificate -Times 0
                }
            }

            Context 'Certificate is found and needs to be exported as PFX' {
                # Needs to be done because Export-PfxCertificate requires a real cert object
                function Export-PfxCertificate {
                    [CmdletBinding()]
                    param
                    (
                        $FilePath,
                        $Cert,
                        $Force,
                        $Type,
                        $Password,
                        $ChainOption,
                        $ProtectTo
                    )
                }

                Mock `
                    -CommandName Find-Certificate `
                    -MockWith { $validCert } `
                    -Verifiable
                Mock `
                    -CommandName Export-Certificate
                Mock `
                    -CommandName Export-PfxCertificate `
                    -Verifiable

                It 'should not throw exception' {
                    { Set-TargetResource @validPfxParams -Verbose } | Should Not Throw
                }
                It 'should call the expected mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Export-Certificate -Times 0
                }
            }

        }

        Describe "$DSCResourceName\Test-TargetResource" {
        }
    }
}
finally
{
    #region FOOTER
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
    #endregion
}
