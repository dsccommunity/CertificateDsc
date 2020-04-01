[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
param ()

$script:dscModuleName = 'CertificateDsc'
$script:dscResourceName = 'DSC_PfxImport'

try
{
    Import-Module -Name DscResource.Test -Force -ErrorAction 'Stop'
}
catch [System.IO.FileNotFoundException]
{
    throw 'DscResource.Test module dependency not found. Please run ".\build.ps1 -Tasks build" first.'
}

$script:testEnvironment = Initialize-TestEnvironment `
    -DSCModuleName $script:dscModuleName `
    -DSCResourceName $script:dscResourceName `
    -ResourceType 'Mof' `
    -TestType 'Integration'

Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath '..\TestHelpers\CommonTestHelper.psm1')

try
{
    Describe "$($script:DSCResourceName)_Integration" {
        BeforeAll {
            $configFile = Join-Path -Path $PSScriptRoot -ChildPath "$($script:DSCResourceName).config.ps1"
            . $configFile

            <#
                Generate a self-signed certificate, export it and remove it from the store
                to use for testing.
                Don't use CurrentUser certificates for this test because they won't be found because
                DSC LCM runs under a different context (Local System).
            #>
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

            $certificateFriendlyName = 'Test Certificate Friendly Name'

            $configDataForAdd = @{
                AllNodes = @(
                    @{
                        NodeName                    = 'localhost'
                        Thumbprint                  = $certificate.Thumbprint
                        Location                    = 'LocalMachine'
                        Store                       = 'My'
                        Ensure                      = 'Present'
                        Path                        = $pfxPath
                        Credential                  = $testCredential
                        FriendlyName                = $certificateFriendlyName
                        PSDscAllowPlainTextPassword = $true
                    }
                )
            }

            $configDataForRemove = @{
                AllNodes = @(
                    @{
                        NodeName                    = 'localhost'
                        Thumbprint                  = $certificate.Thumbprint
                        Location                    = 'LocalMachine'
                        Store                       = 'My'
                        Ensure                      = 'Absent'
                        PSDscAllowPlainTextPassword = $true
                    }
                )
            }
        }

        AfterAll {
            # Clean up
            $null = Remove-Item `
                -Path $pfxPath `
                -Force `
                -ErrorAction SilentlyContinue
            $null = Remove-Item `
                -Path $certificate.PSPath `
                -Force `
                -ErrorAction SilentlyContinue
        }

        Context 'When certificate has not been imported yet' {
            It 'Should compile the MOF without throwing an exception' {
                {
                    & "$($script:DSCResourceName)_Add_Config" `
                        -OutputPath $TestDrive `
                        -ConfigurationData $configDataForAdd
                } | Should -Not -Throw
            }

            It 'Should apply the MOF without throwing an exception' {
                {
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
                $certificateNew | Should -BeOfType System.Security.Cryptography.X509Certificates.X509Certificate2
                $certificateNew.HasPrivateKey | Should -Be $true
                $certificateNew.Thumbprint | Should -BeExactly $certificate.Thumbprint
                $certificateNew.Subject | Should -BeExactly $certificate.Subject
                $certificateNew.FriendlyName | Should -BeExactly $certificateFriendlyName
            }
        }

        Context 'When certificate has been imported but the private key is missing' {
            $null = Remove-Item `
                -Path $certificate.PSPath `
                -Force

            Import-Certificate -FilePath $cerPath -CertStoreLocation Cert:\LocalMachine\My

            It 'Should compile the MOF without throwing an exception' {
                {
                    & "$($script:DSCResourceName)_Add_Config" `
                        -OutputPath $TestDrive `
                        -ConfigurationData $configDataForAdd
                } | Should -Not -Throw
            }

            It 'Should apply the MOF without throwing an exception' {
                {
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
                $certificateNew | Should -BeOfType System.Security.Cryptography.X509Certificates.X509Certificate2
                $certificateNew.HasPrivateKey | Should -BeTrue
                $certificateNew.Thumbprint | Should -BeExactly $certificate.Thumbprint
                $certificateNew.Subject | Should -BeExactly $certificate.Subject
                $certificateNew.FriendlyName | Should -BeExactly $certificateFriendlyName
            }
        }

        Context 'When certificate has already been imported' {
            It 'Should compile the MOF without throwing an exception' {
                {
                    & "$($script:DSCResourceName)_Add_Config" `
                        -OutputPath $TestDrive `
                        -ConfigurationData $configDataForAdd
                } | Should -Not -Throw
            }

            It 'Should apply the MOF without throwing an exception' {
                {
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
                $certificateNew | Should -BeOfType System.Security.Cryptography.X509Certificates.X509Certificate2
                $certificateNew.HasPrivateKey | Should -BeTrue
                $certificateNew.Thumbprint | Should -BeExactly $certificate.Thumbprint
                $certificateNew.Subject | Should -BeExactly $certificate.Subject
                $certificateNew.FriendlyName | Should -BeExactly $certificateFriendlyName
            }
        }

        Context 'When certificate has been imported but needs to be removed' {
            It 'Should compile the MOF without throwing an exception' {
                {
                    & "$($script:DSCResourceName)_Remove_Config" `
                        -OutputPath $TestDrive `
                        -ConfigurationData $configDataForRemove
                } | Should -Not -Throw
            }

            It 'Should apply the MOF without throwing an exception' {
                {
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
                $certificateNew | Should -BeNullOrEmpty
            }
        }
    }
}
finally
{
    Restore-TestEnvironment -TestEnvironment $script:testEnvironment
}
