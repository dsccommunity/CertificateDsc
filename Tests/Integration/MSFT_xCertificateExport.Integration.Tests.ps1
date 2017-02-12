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
        $script:certPath = Join-Path -Path $ENV:Temp -ChildPath 'xCertificateExportTestCert.cer'
        $null = Remove-Item -Path $script:certPath -Force -ErrorAction SilentlyContinue

        # Prepare PFX certificate properties
        $script:pfxPath = Join-Path -Path $ENV:Temp -ChildPath 'xCertificateExportTestCert.pfx'
        $null = Remove-Item -Path $script:pfxPath -Force -ErrorAction SilentlyContinue
        $pfxPlainTextPassword = 'P@ssword!1'
        $pfxPassword = ConvertTo-SecureString -String $pfxPlainTextPassword -AsPlainText -Force
        $pfxCred = New-Object -TypeName System.Management.Automation.PSCredential `
            -ArgumentList ('Dummy',$pfxPassword)

        # Generate the Valid certificate for testing
        $certDNSNames = @('www.fabrikam.com', 'www.contoso.com')
        $certKeyUsage = @('DigitalSignature','DataEncipherment')
        $certEKU = @('Server Authentication','Client authentication')
        $certSubject = 'CN=contoso, DC=com'
        $certFriendlyName = 'Contoso Test Cert'
        $validCert = New-SelfSignedCertificateEx `
            -Subject $certSubject `
            -KeyUsage $certKeyUsage `
            -KeySpec 'Exchange' `
            -EKU $certEKU `
            -SubjectAlternativeName $certDNSNames `
            -FriendlyName $certFriendlyName `
            -StoreLocation 'LocalMachine' `
            -Exportable
        $script:validThumbprint = $validCert.Thumbprint

        Context 'Export CERT' {
            #region DEFAULT TESTS
            It 'Should compile without throwing' {
                {
                    # This is to allow the testing of certreq with domain credentials
                    $ConfigData = @{
                        AllNodes = @(
                            @{
                                NodeName         = 'localhost'
                                Path             = $script:certPath
                                FriendlyName     = $certFriendlyName
                                Subject          = $certSubject
                                DNSName          = $certDNSNames
                                Issuer           = $certSubject
                                KeyUsage         = $certKeyUsage
                                EnhancedKeyUsage = $certEKU
                                Type             = 'CERT'
                            }
                        )
                    }

                    & "$($script:DSCResourceName)_Config" `
                        -OutputPath $TestDrive `
                        -ConfigurationData $ConfigData
                    Start-DscConfiguration -Path $TestDrive -ComputerName localhost -Wait -Verbose -Force
                } | Should not throw
            }

            It 'should be able to call Get-DscConfiguration without throwing' {
                { $script:currentCert = Get-DscConfiguration -Verbose -ErrorAction Stop } | Should Not throw
            }
            #endregion

            It 'should have exported a Cert certificate' {
                $script:currentCert.IsExported | Should Be $True
            }

            It 'Should have set the resource and the thumbprint of the exported certificate should match' {
                $exportedCert = New-Object -TypeName 'System.Security.Cryptography.X509Certificates.X509Certificate2Collection'
                $exportedCert.Import($script:certPath)
                $exportedCert[0].Thumbprint | Should Be $script:validThumbprint
            }
        }

        Context 'Export PFX' {
            #region DEFAULT TESTS
            It 'Should compile without throwing' {
                {
                    # This is to allow the testing of certreq with domain credentials
                    $ConfigData = @{
                        AllNodes = @(
                            @{
                                NodeName                    = 'localhost'
                                Path                        = $script:pfxPath
                                FriendlyName                = $certFriendlyName
                                Subject                     = $certSubject
                                DNSName                     = $certDNSNames
                                Issuer                      = $certSubject
                                KeyUsage                    = $certKeyUsage
                                EnhancedKeyUsage            = $certEKU
                                Type                        = 'PFX'
                                ChainOption                 = 'BuildChain'
                                Password                    = $pfxCred
                                PsDscAllowPlainTextPassword = $true
                            }
                        )
                    }

                    & "$($script:DSCResourceName)_Config" `
                        -OutputPath $TestDrive `
                        -ConfigurationData $ConfigData
                    Start-DscConfiguration -Path $TestDrive -ComputerName localhost -Wait -Verbose -Force
                } | Should not throw
            }

            It 'should be able to call Get-DscConfiguration without throwing' {
                { $script:currentPFX = Get-DscConfiguration -Verbose -ErrorAction Stop } | Should Not throw
            }
            #endregion

            It 'should have exported a PFX certificate' {
                $script:currentPFX.IsExported | Should Be $True
            }

            It 'Should have set the resource and the thumbprint of the exported certificate should match' {
                $exportedCert = New-Object -TypeName 'System.Security.Cryptography.X509Certificates.X509Certificate2Collection'
                $exportedCert.Import($script:certPath,$pfxPassword,[System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet)
                $exportedCert[0].Thumbprint | Should Be $script:validThumbprint
            }
        }

        AfterAll {
            # Cleanup
            $validCert = Get-Item -Path "cert:\LocalMachine\My\$($script:validThumbprint)"
            $null = Remove-Item -Path $validCert.PSPath -Force -ErrorAction SilentlyContinue
            $null = Remove-Item -Path $script:pfxPath -Force -ErrorAction SilentlyContinue
            $null = Remove-Item -Path $script:certPath -Force -ErrorAction SilentlyContinue
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
