$script:ModuleName = 'CertificateDsc.Common'
<#
    These integration tests are the easiest way to effectively test the
    Import-Certificate and Import-PfxCertificate cmdlets due to the use
    of .NET objects to perform the work.

    These tests are potentially destructive tests and so should not be
    considered unit tests.
#>

#region HEADER
# Integration Test Template Version: 1.1.0
[System.String] $script:moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ( (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
    (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone', 'https://github.com/PowerShell/DscResource.Tests.git', (Join-Path -Path $script:moduleRoot -ChildPath '\DSCResource.Tests\'))
}

Import-Module (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1') -Force
Import-Module -Name (Join-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath (Join-Path -Path 'Modules' -ChildPath $script:ModuleName)) -ChildPath "$script:ModuleName.psm1") -Force
Import-Module -Name (Join-Path -Path (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'TestHelpers') -ChildPath 'CommonTestHelper.psm1') -Global
#endregion

# Using try/finally to always cleanup even if something awful happens.
try
{
    InModuleScope $script:ModuleName {
        $ModuleName = 'CertificateDsc.Common'

        <#
            Generate a self-signed certificate, export it and remove it from the store to use for testing.
            Don't use CurrentUser certificates for this test because they won't be found because
            DSC LCM runs under a different context (Local System).
        #>
        $certificate = New-SelfSignedCertificate `
            -DnsName $ENV:ComputerName `
            -CertStoreLocation Cert:\LocalMachine\My
        $certificatePath = Join-Path `
            -Path $ENV:Temp `
            -ChildPath "CertificateDsc.Common.Tests-$($certificate.Thumbprint).cer"
        $null = Export-Certificate `
            -Cert $certificate `
            -Type CERT `
            -FilePath $certificatePath
        $null = Remove-Item `
            -Path $certificate.PSPath `
            -Force

        Describe "$ModuleName\Import-CertificateEx" {
            Context 'Import a valid x509 Certificate file into "CurrentUser\My" store' {
                It 'Should not throw an exception' {
                    { Import-CertificateEx -FilePath $certificatePath -CertStoreLocation 'Cert:\CurrentUser\My' } | Should -Not -Throw
                }

                It 'Should have imported the certificate with the correct values' {
                    $importedCert = Get-ChildItem -Path ('Cert:\CurrentUser\My\{0}' -f $certificate.Thumbprint)
                    $importedCert.Thumbprint | Should -Be $certificate.Thumbprint
                    $importedCert.HasPrivateKey | Should -Be $false
                }
            }
        }

        # Remove the imported certificate
        Remove-Item -Path ('Cert:\CurrentUser\My\{0}' -f $certificate.Thumbprint) -Force -ErrorAction SilentlyContinue

        <#
            Generate a self-signed certificate, export it and remove it from the store to use for testing.
            Don't use CurrentUser certificates for this test because they won't be found because
            DSC LCM runs under a different context (Local System).
        #>
        $rootCertificate = New-SelfSignedCertificate -FriendlyName "TestRootCA" `
            -KeyExportPolicy Exportable `
            -Provider "Microsoft Strong Cryptographic Provider" `
            -Subject "SN=TestRootCA" -NotAfter (Get-Date).AddYears(1) `
            -CertStoreLocation Cert:\LocalMachine\My -KeyUsageProperty All `
            -KeyUsage CertSign, CRLSign, DigitalSignature

        $childCertificate = New-SelfSignedCertificate `
            -Signer $rootCertificate `
            -DnsName $ENV:ComputerName `
            -CertStoreLocation Cert:\LocalMachine\My

        $certificatePath = Join-Path `
            -Path $ENV:Temp `
            -ChildPath "CertificateDsc.Common.Tests-$($childCertificate.Thumbprint).p7b"
        $certificateExportPath = Join-Path `
            -Path $ENV:Temp `
            -ChildPath "CertificateDsc.Common.Tests.Export-$($childCertificate.Thumbprint).p7b"
        $testUsername = 'DummyUsername'
        $testPassword = 'DummyPassword'
        $testPasswordSecure = (ConvertTo-SecureString $testPassword -AsPlainText -Force)
        $testCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList @($testUsername, $testPasswordSecure)

        $null = @($rootCertificate, $childCertificate) | Export-Certificate `
            -FilePath $certificatePath `
            -Type p7b
        $null = Remove-Item `
            -Path $rootCertificate.PSPath `
            -Force
        $null = Remove-Item `
            -Path $childCertificate.PSPath `
            -Force

        Describe "$ModuleName\Import-CertificateEx" {
            Context 'Import a valid p7b Certificate chain into "CurrentUser\My" store' {
                It 'Should not throw an exception' {
                    { Import-CertificateEx -FilePath $certificatePath -CertStoreLocation 'Cert:\CurrentUser\My' } | Should -Not -Throw
                }

                It 'Should have imported the child certificate with the correct values' {
                    $importedCert = Get-ChildItem -Path ('Cert:\CurrentUser\My\{0}' -f $childCertificate.Thumbprint)
                    $importedCert.Thumbprint | Should -Be $childCertificate.Thumbprint
                    $importedCert.HasPrivateKey | Should -Be $false
                }

                It 'Should have imported the root certificate with the correct values' {
                    $importedCert = Get-ChildItem -Path ('Cert:\CurrentUser\My\{0}' -f $rootCertificate.Thumbprint)
                    $importedCert.Thumbprint | Should -Be $rootCertificate.Thumbprint
                    $importedCert.HasPrivateKey | Should -Be $false
                }
            }
        }

        # Remove the imported certificate
        Remove-Item -Path ('Cert:\CurrentUser\My\{0}' -f $childCertificate.Thumbprint) -Force -ErrorAction SilentlyContinue
        Remove-Item -Path ('Cert:\CurrentUser\My\{0}' -f $rootCertificate.Thumbprint) -Force -ErrorAction SilentlyContinue

        <#
            Generate a self-signed certificate, export it and remove it from the store to use for testing.
            Don't use CurrentUser certificates for this test because they won't be found because
            DSC LCM runs under a different context (Local System).
        #>
        $certificate = New-SelfSignedCertificate `
            -DnsName $ENV:ComputerName `
            -CertStoreLocation Cert:\LocalMachine\My
        $certificatePath = Join-Path `
            -Path $ENV:Temp `
            -ChildPath "CertificateDsc.Common.Tests-$($Certificate.Thumbprint).pfx"
        $certificateExportPath = Join-Path `
            -Path $ENV:Temp `
            -ChildPath "CertificateDsc.Common.Tests.Export-$($Certificate.Thumbprint).pfx"
        $testUsername = 'DummyUsername'
        $testPassword = 'DummyPassword'
        $testPasswordSecure = (ConvertTo-SecureString $testPassword -AsPlainText -Force)
        $testCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList @($testUsername, $testPasswordSecure)
        $null = Export-PfxCertificate `
            -Cert $certificate `
            -FilePath $certificatePath `
            -Password $testCredential.Password
        $null = Remove-Item `
            -Path $certificate.PSPath `
            -Force

        Describe "$ModuleName\Import-PfxCertificateEx" {
            Context 'Import a valid PKCS12 PFX Certificate file into "CurrentUser\My" store with non-exportable key' {
                It 'Should not throw an exception' {
                    { Import-PfxCertificateEx -FilePath $certificatePath -CertStoreLocation 'Cert:\CurrentUser\My' -Password $testPasswordSecure } | Should -Not -Throw
                }

                It 'Should have imported the certificate with the correct values' {
                    $importedCert = Get-ChildItem -Path ('Cert:\CurrentUser\My\{0}' -f $certificate.Thumbprint)
                    $importedCert.Thumbprint | Should -Be $certificate.Thumbprint
                    $importedCert.HasPrivateKey | Should -Be $true
                }

                It 'Should not be exportable and should throw the expected exception message' {
                    $importedCert = Get-ChildItem -Path ('Cert:\CurrentUser\My\{0}' -f $certificate.Thumbprint)
                    { $null = Export-PfxCertificate `
                        -Cert $importedCert `
                        -FilePath $certificateExportPath `
                        -Password $testCredential.Password
                    } | Should -Throw 'Cannot export non-exportable private key.'

                    $null = Remove-Item `
                        -Path $certificateExportPath `
                        -Force `
                        -ErrorAction SilentlyContinue
                }

                # Remove the imported certificate
                Remove-Item -Path ('Cert:\CurrentUser\My\{0}' -f $certificate.Thumbprint) -Force -ErrorAction SilentlyContinue
            }

            Context 'Import a valid PKCS12 PFX Certificate file into "CurrentUser\My" store with exportable key' {
                It 'Should not throw an exception' {
                    { Import-PfxCertificateEx -FilePath $certificatePath -CertStoreLocation 'Cert:\CurrentUser\My' -Password $testPasswordSecure -Exportable } | Should -Not -Throw
                }

                It 'Should have imported the certificate with the correct values' {
                    $importedCert = Get-ChildItem -Path ('Cert:\CurrentUser\My\{0}' -f $certificate.Thumbprint)
                    $importedCert.Thumbprint | Should -Be $certificate.Thumbprint
                    $importedCert.HasPrivateKey | Should -Be $true
                }

                It 'Should be exportable' {
                    $importedCert = Get-ChildItem -Path ('Cert:\CurrentUser\My\{0}' -f $certificate.Thumbprint)
                    { $null = Export-PfxCertificate `
                        -Cert $importedCert `
                        -FilePath $certificateExportPath `
                        -Password $testCredential.Password
                    } | Should -Not -Throw

                    $null = Remove-Item `
                        -Path $certificateExportPath `
                        -Force `
                        -ErrorAction SilentlyContinue
                }

                # Remove the imported certificate
                Remove-Item -Path ('Cert:\CurrentUser\My\{0}' -f $certificate.Thumbprint) -Force -ErrorAction SilentlyContinue
            }
        }
    }
}
finally
{
    #region FOOTER

    #endregion
}
