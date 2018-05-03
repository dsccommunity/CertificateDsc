[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
param ()

$script:DSCModuleName = 'CertificateDsc'
$script:DSCResourceName = 'MSFT_PfxImport'

#region HEADER
# Integration Test Template Version: 1.1.0
[String] $script:moduleRoot = Join-Path -Path $(Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $Script:MyInvocation.MyCommand.Path))) -ChildPath 'Modules\CertificateDsc'
if ( (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
    (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone', 'https://github.com/PowerShell/DscResource.Tests.git', (Join-Path -Path $script:moduleRoot -ChildPath '\DSCResource.Tests\'))
}

Import-Module (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1') -Force
$TestEnvironment = Initialize-TestEnvironment `
    -DSCModuleName $script:DSCModuleName `
    -DSCResourceName $script:DSCResourceName `
    -TestType Integration
#endregion

# Using try/finally to always cleanup even if something awful happens.
try
{
    # Generate a self-signed certificate, export it and remove it from the store
    # to use for testing.
    # Don't use CurrentUser certificates for this test because they won't be found because
    # DSC LCM runs under a different context (Local System).
    $certificate = New-SelfSignedCertificate `
        -DnsName $env:ComputerName `
        -CertStoreLocation Cert:\LocalMachine\My
    $pfxPath = Join-Path `
        -Path $env:Temp `
        -ChildPath "PfxImport-$($certificate.Thumbprint).pfx"
    $cerPath = Join-Path `
        -Path $env:Temp `
        -ChildPath "CerImport-$($certificate.Thumbprint).cer"

    $testUsername = 'DummyUsername'
    $testPassword = 'DummyPassword'
    $testCredential = New-Object `
        -TypeName System.Management.Automation.PSCredential `
        -ArgumentList $testUsername, (ConvertTo-SecureString $testPassword -AsPlainText -Force)

    $null = Export-PfxCertificate `
        -Cert $certificate `
        -FilePath $pfxPath `
        -Password $testCredential.Password

    $null = Export-Certificate `
        -Type CERT `
        -Cert $certificate `
        -FilePath $cerPath

    $null = Remove-Item `
        -Path $certificate.PSPath `
        -Force

    Describe "$($script:DSCResourceName)_Add_Integration" {
        $ConfigFile = Join-Path -Path $PSScriptRoot -ChildPath "$($script:DSCResourceName)_Add.config.ps1"
        . $ConfigFile

        Context 'When certificate has not been imported yet' {
            It 'Should compile and apply the MOF without throwing' {
                {
                    $configData = @{
                        AllNodes = @(
                            @{
                                NodeName                    = 'localhost'
                                PSDscAllowPlainTextPassword = $true
                            }
                        )
                    }

                    & "$($script:DSCResourceName)_Add_Config" `
                        -OutputPath $TestDrive `
                        -ConfigurationData $configData `
                        -Path $pfxPath `
                        -Thumbprint $certificate.Thumbprint `
                        -Credential $testCredential

                    Start-DscConfiguration `
                        -Path $TestDrive `
                        -ComputerName localhost `
                        -Wait `
                        -Verbose `
                        -Force `
                        -ErrorAction Stop
                } | Should -Not -Throw
            }

            It 'Should be able to call Get-DscConfiguration without throwing' {
                { Get-DscConfiguration -Verbose -ErrorAction Stop } | Should -Not -Throw
            }

            It 'Should have set the resource and all the parameters should match' {
                # Get the Certificate details
                $certificateNew = Get-Item `
                    -Path "Cert:\LocalMachine\My\$($certificate.Thumbprint)"
                $certificateNew                             | Should -BeOfType System.Security.Cryptography.X509Certificates.X509Certificate2
                $certificateNew.HasPrivateKey               | Should -Be $true
                $certificateNew.Thumbprint                  | Should -Be $certificate.Thumbprint
                $certificateNew.Subject                     | Should -Be $certificate.Subject
            }
        }

        Context 'When certificate has been imported but the private key is missing' {
            $null = Remove-Item `
                -Path $certificate.PSPath `
                -Force

            Import-Certificate -FilePath $cerPath -CertStoreLocation Cert:\LocalMachine\My

            It 'Should compile and apply the MOF without throwing' {
                {
                    $configData = @{
                        AllNodes = @(
                            @{
                                NodeName                    = 'localhost'
                                PSDscAllowPlainTextPassword = $true
                            }
                        )
                    }

                    & "$($script:DSCResourceName)_Add_Config" `
                        -OutputPath $TestDrive `
                        -ConfigurationData $configData `
                        -Path $pfxPath `
                        -Thumbprint $certificate.Thumbprint `
                        -Credential $testCredential

                    Start-DscConfiguration `
                        -Path $TestDrive `
                        -ComputerName localhost `
                        -Wait `
                        -Verbose `
                        -Force `
                        -ErrorAction Stop
                } | Should -Not -Throw
            }

            It 'Should be able to call Get-DscConfiguration without throwing' {
                { Get-DscConfiguration -Verbose -ErrorAction Stop } | Should -Not -Throw
            }

            It 'Should have set the resource and all the parameters should match' {
                # Get the Certificate details
                $certificateNew = Get-Item `
                    -Path "Cert:\LocalMachine\My\$($certificate.Thumbprint)"
                $certificateNew                             | Should -BeOfType System.Security.Cryptography.X509Certificates.X509Certificate2
                $certificateNew.HasPrivateKey               | Should -Be $true
                $certificateNew.Thumbprint                  | Should -Be $certificate.Thumbprint
                $certificateNew.Subject                     | Should -Be $certificate.Subject
            }
        }

        Context 'When certificate has already been imported' {
            It 'Should compile and apply the MOF without throwing' {
                {
                    $configData = @{
                        AllNodes = @(
                            @{
                                NodeName                    = 'localhost'
                                PSDscAllowPlainTextPassword = $true
                            }
                        )
                    }

                    & "$($script:DSCResourceName)_Add_Config" `
                        -OutputPath $TestDrive `
                        -ConfigurationData $configData `
                        -Path $pfxPath `
                        -Thumbprint $certificate.Thumbprint `
                        -Credential $testCredential

                    Start-DscConfiguration `
                        -Path $TestDrive `
                        -ComputerName localhost `
                        -Wait `
                        -Verbose `
                        -Force `
                        -ErrorAction Stop
                } | Should -Not -Throw
            }

            It 'Should be able to call Get-DscConfiguration without throwing' {
                { Get-DscConfiguration -Verbose -ErrorAction Stop } | Should -Not -Throw
            }

            It 'Should have set the resource and all the parameters should match' {
                # Get the Certificate details
                $certificateNew = Get-Item `
                    -Path "Cert:\LocalMachine\My\$($certificate.Thumbprint)"
                $certificateNew                             | Should -BeOfType System.Security.Cryptography.X509Certificates.X509Certificate2
                $certificateNew.HasPrivateKey               | Should -Be $true
                $certificateNew.Thumbprint                  | Should -Be $certificate.Thumbprint
                $certificateNew.Subject                     | Should -Be $certificate.Subject
            }
        }
    }

    Describe "$($script:DSCResourceName)_Remove_Integration" {
        $ConfigFile = Join-Path -Path $PSScriptRoot -ChildPath "$($script:DSCResourceName)_Remove.config.ps1"
        . $ConfigFile

        Context 'When certificate has been imported but needs to be removed' {
            It 'Should compile without throwing' {
                {
                    & "$($script:DSCResourceName)_Remove_Config" `
                        -OutputPath $TestDrive `
                        -Path $pfxPath `
                        -Thumbprint $certificate.Thumbprint

                    Start-DscConfiguration `
                        -Path $TestDrive `
                        -ComputerName localhost `
                        -Wait `
                        -Verbose `
                        -Force `
                        -ErrorAction Stop
                } | Should -Not -Throw
            }

            It 'Should be able to call Get-DscConfiguration without throwing' {
                { Get-DscConfiguration -Verbose -ErrorAction Stop } | Should -Not -Throw
            }

            It 'Should have set the resource and all the parameters should match' {
                # Get the Certificate details
                $certificateNew = Get-Item `
                    -Path "Cert:\LocalMachine\My\$($certificate.Thumbprint)" `
                    -ErrorAction SilentlyContinue
                $certificateNew                             | Should -BeNullOrEmpty
            }
        }
    }
}
finally
{
    # Clean up
    $null = Remove-Item `
        -Path $pfxPath `
        -Force `
        -ErrorAction SilentlyContinue
    $null = Remove-Item `
        -Path $certificate.PSPath `
        -Force `
        -ErrorAction SilentlyContinue

    #region FOOTER
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
    #endregion
}
