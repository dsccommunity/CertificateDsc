$script:DSCModuleName = 'CertificateDsc'
$script:DSCResourceName = 'MSFT_CertificateImport'

#region HEADER
# Integration Test Template Version: 1.1.1
[System.String] $script:moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ( (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
    (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone', 'https://github.com/PowerShell/DscResource.Tests.git', (Join-Path -Path $script:moduleRoot -ChildPath '\DSCResource.Tests\'))
}

Import-Module -Name (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1') -Force
$TestEnvironment = Initialize-TestEnvironment `
    -DSCModuleName $script:DSCModuleName `
    -DSCResourceName $script:DSCResourceName `
    -TestType Integration
#endregion

# Using try/finally to always cleanup even if something awful happens.
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
            $certificatePath = Join-Path `
                -Path $env:Temp `
                -ChildPath "CertificateImport-$($certificate.Thumbprint).cer"
            $null = Export-Certificate `
                -Cert $certificate `
                -Type CERT `
                -FilePath $certificatePath
            $null = Remove-Item `
                -Path $certificate.PSPath `
                -Force
            $certificateFriendlyName = 'Test Certificate Friendly Name'
        }

        AfterAll {
            # Cleanup
            $null = Remove-Item `
                -Path $certificatePath `
                -Force `
                -ErrorAction SilentlyContinue
            $null = Remove-Item `
                -Path $certificate.PSPath `
                -Force `
                -ErrorAction SilentlyContinue
        }

        Context 'Import certificate' {
            $configData = @{
                AllNodes = @(
                    @{
                        NodeName     = 'localhost'
                        Thumbprint   = $certificate.Thumbprint
                        Location     = 'LocalMachine'
                        Store        = 'My'
                        Ensure       = 'Present'
                        Path         = $certificatePath
                        FriendlyName = $certificateFriendlyName
                    }
                )
            }

            It 'Should compile the MOF without throwing an exception' {
                {
                    & "$($script:DSCResourceName)_Config" `
                        -OutputPath $TestDrive `
                        -ConfigurationData $configData
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
                $certificateNew.Thumbprint | Should -BeExactly $certificate.Thumbprint
                $certificateNew.Subject | Should -BeExactly $certificate.Subject
                $certificateNew.FriendlyName | Should -BeExactly $certificateFriendlyName
            }
        }

        Context 'Remove certificate' {
            $configData = @{
                AllNodes = @(
                    @{
                        NodeName     = 'localhost'
                        Thumbprint   = $certificate.Thumbprint
                        Location     = 'LocalMachine'
                        Store        = 'My'
                        Ensure       = 'Absent'
                        Path         = $certificatePath
                        FriendlyName = $certificateFriendlyName
                    }
                )
            }

            It 'Should compile the MOF without throwing an exception' {
                {
                    & "$($script:DSCResourceName)_Config" `
                        -OutputPath $TestDrive `
                        -ConfigurationData $configData
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
    #region FOOTER
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
    #endregion
}
