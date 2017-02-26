$script:DSCModuleName   = 'xCertificate'
$script:DSCResourceName = 'MSFT_xCertificateExport'

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
    -TestType Integration
#endregion

Import-Module -Name (Join-Path -Path (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'TestHelpers') -ChildPath 'CommonTestHelper.psm1') -Global

# Using try/finally to always cleanup even if something awful happens.
try
{
    #region Integration Tests
    $ConfigFile = Join-Path -Path $PSScriptRoot -ChildPath "$($script:DSCResourceName).config.ps1"
    . $ConfigFile

    Describe "$($script:DSCResourceName)_Integration" {
        # Download and dot source the New-SelfSignedCertificateEx script
        . (Install-NewSelfSignedCertificateExScript)

        # Prepare CER certificate properties
        $script:certificatePath = Join-Path -Path $env:Temp -ChildPath 'xCertificateExportTestCert.cer'
        $null = Remove-Item -Path $script:certificatePath -Force -ErrorAction SilentlyContinue

        # Prepare PFX certificate properties
        $script:pfxPath = Join-Path -Path $env:Temp -ChildPath 'xCertificateExportTestCert.pfx'
        $null = Remove-Item -Path $script:pfxPath -Force -ErrorAction SilentlyContinue
        $pfxPlainTextPassword = 'P@ssword!1'
        $pfxPassword = ConvertTo-SecureString -String $pfxPlainTextPassword -AsPlainText -Force
        $pfxCredential = New-Object -TypeName System.Management.Automation.PSCredential `
            -ArgumentList ('Dummy',$pfxPassword)

        # Generate the Valid certificate for testing
        $certificateDNSNames = @('www.fabrikam.com', 'www.contoso.com')
        $certificateKeyUsage = @('DigitalSignature','DataEncipherment')
        $certificateEKU = @('Server Authentication','Client authentication')
        $certificateSubject = 'CN=contoso, DC=com'
        $certFriendlyName = 'Contoso Test Cert'
        $validCertificate = New-SelfSignedCertificateEx `
            -Subject $certificateSubject `
            -KeyUsage $certificateKeyUsage `
            -KeySpec 'Exchange' `
            -EKU $certificateEKU `
            -SubjectAlternativeName $certificateDNSNames `
            -FriendlyName $certFriendlyName `
            -StoreLocation 'LocalMachine' `
            -Exportable
        $script:validCertificateThumbprint = $validCertificate.Thumbprint

        Context 'Export CERT' {
            #region DEFAULT TESTS
            It 'Should compile and apply the MOF without throwing' {
                {
                    # This is to allow the testing of certreq with domain credentials
                    $ConfigData = @{
                        AllNodes = @(
                            @{
                                NodeName         = 'localhost'
                                Path             = $script:certificatePath
                                FriendlyName     = $certFriendlyName
                                Subject          = $certificateSubject
                                DNSName          = $certificateDNSNames
                                Issuer           = $certificateSubject
                                KeyUsage         = $certificateKeyUsage
                                EnhancedKeyUsage = $certificateEKU
                                MatchSource      = $true
                                Type             = 'CERT'
                            }
                        )
                    }

                    & "$($script:DSCResourceName)_Config" `
                        -OutputPath $TestDrive `
                        -ConfigurationData $ConfigData

                    Start-DscConfiguration -Path $TestDrive -ComputerName localhost -Wait -Verbose -Force
                } | Should Not Throw
            }

            It 'Should be able to call Get-DscConfiguration without throwing' {
                { $script:currentCertificate = Get-DscConfiguration -Verbose -ErrorAction Stop } | Should Not Throw
            }
            #endregion

            It 'Should have exported a Cert certificate' {
                $script:currentCertificate.IsExported | Should Be $true
            }

            It 'Should have set the resource and the thumbprint of the exported certificate should match' {
                $exportedCertificate = New-Object -TypeName 'System.Security.Cryptography.X509Certificates.X509Certificate2Collection'
                $exportedCertificate.Import($script:certificatePath)
                $exportedCertificate[0].Thumbprint | Should Be $script:validCertificateThumbprint
            }
        }

        Context 'Export PFX' {
            #region DEFAULT TESTS
            It 'Should compile and apply the MOF without throwing' {
                {
                    # This is to allow the testing of certreq with domain credentials
                    $ConfigData = @{
                        AllNodes = @(
                            @{
                                NodeName                    = 'localhost'
                                Path                        = $script:pfxPath
                                FriendlyName                = $certFriendlyName
                                Subject                     = $certificateSubject
                                DNSName                     = $certificateDNSNames
                                Issuer                      = $certificateSubject
                                KeyUsage                    = $certificateKeyUsage
                                EnhancedKeyUsage            = $certificateEKU
                                MatchSource                 = $true
                                Type                        = 'PFX'
                                ChainOption                 = 'BuildChain'
                                Password                    = $pfxCredential
                                PsDscAllowPlainTextPassword = $true
                            }
                        )
                    }

                    & "$($script:DSCResourceName)_Config" `
                        -OutputPath $TestDrive `
                        -ConfigurationData $ConfigData

                    Start-DscConfiguration -Path $TestDrive -ComputerName localhost -Wait -Verbose -Force
                } | Should Not Throw
            }

            It 'Should be able to call Get-DscConfiguration without throwing' {
                { $script:currentPFX = Get-DscConfiguration -Verbose -ErrorAction Stop } | Should Not Throw
            }
            #endregion

            It 'Should have exported a PFX certificate' {
                $script:currentPFX.IsExported | Should Be $true
            }

            It 'Should have set the resource and the thumbprint of the exported certificate should match' {
                $exportedCertificate = New-Object -TypeName 'System.Security.Cryptography.X509Certificates.X509Certificate2Collection'
                $exportedCertificate.Import($script:certificatePath,$pfxPassword,[System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet)
                $exportedCertificate[0].Thumbprint | Should Be $script:validCertificateThumbprint
            }
        }

        AfterAll {
            # Cleanup
            $validCertificate = Get-Item -Path "cert:\LocalMachine\My\$($script:validCertificateThumbprint)"
            $null = Remove-Item -Path $validCertificate.PSPath -Force -ErrorAction SilentlyContinue
            $null = Remove-Item -Path $script:pfxPath -Force -ErrorAction SilentlyContinue
            $null = Remove-Item -Path $script:certificatePath -Force -ErrorAction SilentlyContinue
        }
    }
    #endregion
}
finally
{
    #region FOOTER
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
    #endregion
}
