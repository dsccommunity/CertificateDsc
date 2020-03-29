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
InModuleScope 'CertificateDsc.Common' {
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

    Describe 'CertificateDsc.Common\Import-CertificateEx' {
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
        Generate two certificates, export both to a P7B and remove them from the store to use for testing.
        Don't use CurrentUser certificates for this test because they won't be found because
        DSC LCM runs under a different context (Local System).
    #>
    $containingCertificate = New-SelfSignedCertificate `
        -DnsName "ContainingCertificate" `
        -CertStoreLocation Cert:\LocalMachine\My
    $includedCertificate = New-SelfSignedCertificate `
        -DnsName "IncludedCertificate" `
        -CertStoreLocation Cert:\LocalMachine\My

    $certificatePath = Join-Path `
        -Path $ENV:Temp `
        -ChildPath "CertificateDsc.Common.Tests-$($containingCertificate.Thumbprint).p7b"
    $certificateExportPath = Join-Path `
        -Path $ENV:Temp `
        -ChildPath "CertificateDsc.Common.Tests.Export-$($containingCertificate.Thumbprint).p7b"
    $testUsername = 'DummyUsername'
    $testPassword = 'DummyPassword'
    $testPasswordSecure = (ConvertTo-SecureString $testPassword -AsPlainText -Force)
    $testCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList @($testUsername, $testPasswordSecure)

    $null = @($containingCertificate, $includedCertificate) | Export-Certificate `
        -FilePath $certificatePath `
        -Type p7b
    $null = Remove-Item `
        -Path $containingCertificate.PSPath `
        -Force
    $null = Remove-Item `
        -Path $includedCertificate.PSPath `
        -Force

    Describe 'CertificateDsc.Common\Import-CertificateEx' {
        Context 'Import a valid p7b Certificate chain into "CurrentUser\My" store' {
            It 'Should not throw an exception' {
                { Import-CertificateEx -FilePath $certificatePath -CertStoreLocation 'Cert:\CurrentUser\My' } | Should -Not -Throw
            }

            It 'Should have imported the containing certificate with the correct values' {
                $importedCert = Get-ChildItem -Path ('Cert:\CurrentUser\My\{0}' -f $containingCertificate.Thumbprint)
                $importedCert.Thumbprint | Should -Be $containingCertificate.Thumbprint
                $importedCert.HasPrivateKey | Should -Be $false
            }

            It 'Should have imported the included certificate with the correct values' {
                $importedCert = Get-ChildItem -Path ('Cert:\CurrentUser\My\{0}' -f $includedCertificate.Thumbprint)
                $importedCert.Thumbprint | Should -Be $includedCertificate.Thumbprint
                $importedCert.HasPrivateKey | Should -Be $false
            }
        }
    }

    # Remove the imported certificate
    Remove-Item -Path ('Cert:\CurrentUser\My\{0}' -f $containingCertificate.Thumbprint) -Force -ErrorAction SilentlyContinue
    Remove-Item -Path ('Cert:\CurrentUser\My\{0}' -f $includedCertificate.Thumbprint) -Force -ErrorAction SilentlyContinue

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

    Describe 'CertificateDsc.Common\Import-PfxCertificateEx' {
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
