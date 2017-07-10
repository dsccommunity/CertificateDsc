<#
 IMPORTANT INFORMATION:
 Running these tests requires access to a AD CS Certificate Authority.
 These integration tests are configured to use credentials to connect to the CA.
 Therefore, automation of these tests shouldn't be performed using a production CA.
#>

$script:DSCModuleName = 'xCertificate'
$script:DSCResourceName = 'MSFT_xWaitForCertificateServices'

#region HEADER
# Integration Test Template Version: 1.1.0
[String] $script:moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
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
    #region Integration Tests
    $ConfigFile = Join-Path -Path $PSScriptRoot -ChildPath "$($script:DSCResourceName).config.ps1"
    . $ConfigFile

    $CertUtilResult = & "$env:SystemRoot\system32\certutil.exe" @('-dump')

    Describe "$($script:DSCResourceName)_Integration" {
        $caFound = ([regex]::matches($CertUtilResult, 'Name:[ \t]+`([\sA-Za-z0-9._-]+)''', 'IgnoreCase'))

        # These ests can only be executed if a CA is available
        if ([String]::IsNullOrEmpty($caFound))
        {
            Write-Warning -Message 'A CA is not available, so CA online tests skipped. Run tests on a machine with a CA available to complete full test suite.'
        }
        else
        {
            #region DEFAULT TESTS
            Context 'CA is online' {
                $caServerFQDN = ([regex]::matches($certUtilResult, 'Server:[ \t]+`([A-Za-z0-9._-]+)''', 'IgnoreCase')).Groups[1].Value
                $caRootName = ([regex]::matches($certUtilResult, 'Name:[ \t]+`([\sA-Za-z0-9._-]+)''', 'IgnoreCase')).Groups[1].Value

                $configData = @{
                    AllNodes = @(
                        @{
                            NodeName         = 'localhost'
                            CAServerFQDN     = $caServerFQDN
                            CARootName       = $caRootName
                            RetryIntervalSeconds = 1
                            RetryCount       = 2
                        }
                    )
                }

                It 'Should compile and apply the MOF without throwing' {
                    {
                        & "$($script:DSCResourceName)_Config" `
                            -OutputPath $TestDrive `
                            -ConfigurationData $configData

                        Start-DscConfiguration -Path $TestDrive -ComputerName localhost -Wait -Verbose -Force
                    } | Should Not Throw
                }

                It 'Should be able to call Get-DscConfiguration without throwing' {
                    { Get-DscConfiguration -Verbose -ErrorAction Stop } | Should Not Throw
                }

                It 'Should have set the resource and all the parameters should match' {
                    $current = Get-DscConfiguration | Where-Object {
                        $_.ConfigurationName -eq "$($script:DSCResourceName)_Config"
                    }

                    $current.CAServerFQDN | Should Be $caServerFQDN
                    $current.CARootName   | Should Be $caRootName
                }
            }
            #endregion
        }

        #region DEFAULT TESTS
        Context 'CA is offline' {
            $caServerFQDN = 'someplace.else'
            $caRootName = 'noexistent-ca'

            $configData = @{
                AllNodes = @(
                    @{
                        NodeName         = 'localhost'
                        CAServerFQDN     = $caServerFQDN
                        CARootName       = $caRootName
                        RetryIntervalSeconds = 1
                        RetryCount       = 2
                    }
                )
            }

            It 'Should compile and apply the MOF without throwing' {
                {
                    & "$($script:DSCResourceName)_Config" `
                        -OutputPath $TestDrive `
                        -ConfigurationData $configData

                    Start-DscConfiguration -Path $TestDrive -ComputerName localhost -Wait -Verbose -Force
                } | Should Not Throw
            }

            It 'Should be able to call Get-DscConfiguration without throwing' {
                { Get-DscConfiguration -Verbose -ErrorAction Stop } | Should Not Throw
            }

            It 'Should have set the resource and all the parameters should match' {
                $current = Get-DscConfiguration | Where-Object {
                    $_.ConfigurationName -eq "$($script:DSCResourceName)_Config"
                }

                $current.CAServerFQDN | Should Be $caServerFQDN
                $current.CARootName   | Should Be $caRootName
            }
        }
        #endregion
    }
    #endregion
}
finally
{
    #region FOOTER
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
    #endregion
}
