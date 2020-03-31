<#
    IMPORTANT INFORMATION:
    Running these tests requires access to a AD CS Certificate Authority.
    These integration tests are configured to use credentials to connect to the CA.
    Therefore, automation of these tests shouldn't be performed using a production CA.
#>

$script:dscModuleName = 'CertificateDsc'
$script:dscResourceName = 'DSC_WaitForCertificateServices'

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

            $certUtilResult = & "$env:SystemRoot\system32\certutil.exe" @('-dump')

            $caFound = ([regex]::matches($certUtilResult, 'Name:[ \t]+`([\sA-Za-z0-9._-]+)''', 'IgnoreCase'))
        }

        # These tests can only be executed if a CA is available
        if ([String]::IsNullOrEmpty($caFound))
        {
            Write-Warning -Message 'A CA is not available, so CA online tests skipped. Run tests on a machine with a CA available to complete full test suite.'
        }
        else
        {
            Context 'CA is online' {
                $caServerFQDN = ([regex]::matches($certUtilResult, 'Server:[ \t]+`([A-Za-z0-9._-]+)''', 'IgnoreCase')).Groups[1].Value
                $caRootName = ([regex]::matches($certUtilResult, 'Name:[ \t]+`([\sA-Za-z0-9._-]+)''', 'IgnoreCase')).Groups[1].Value
                $configData = @{
                    AllNodes = @(
                        @{
                            NodeName             = 'localhost'
                            CAServerFQDN         = $caServerFQDN
                            CARootName           = $caRootName
                            RetryIntervalSeconds = 1
                            RetryCount           = 2
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
                    $current = Get-DscConfiguration | Where-Object -FilterScript {
                        $_.ConfigurationName -eq "$($script:DSCResourceName)_Config"
                    }

                    $current.CAServerFQDN | Should -Be $caServerFQDN
                    $current.CARootName | Should -Be $caRootName
                }
            }
        }

        Context 'CA is offline' {
            $caServerFQDN = 'someplace.else'
            $caRootName = 'noexistent-ca'
            $configData = @{
                AllNodes = @(
                    @{
                        NodeName             = 'localhost'
                        CAServerFQDN         = $caServerFQDN
                        CARootName           = $caRootName
                        RetryIntervalSeconds = 1
                        RetryCount           = 2
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

            It 'Should apply the MOF throwing an exception' {
                {
                    Start-DscConfiguration `
                        -Path $TestDrive `
                        -ComputerName localhost `
                        -Wait `
                        -Verbose `
                        -Force `
                        -ErrorAction Stop
                } | Should -Throw
            }

            It 'Should be able to call Get-DscConfiguration without throwing' {
                { Get-DscConfiguration -Verbose -ErrorAction Stop } | Should -Not -Throw
            }

            It 'Should have set the resource and all the parameters should match' {
                $current = Get-DscConfiguration | Where-Object -FilterScript {
                    $_.ConfigurationName -eq "$($script:DSCResourceName)_Config"
                }

                $current.CAServerFQDN | Should -Be $caServerFQDN
                $current.CARootName | Should -Be $caRootName
            }
        }
    }
}
finally
{
    Restore-TestEnvironment -TestEnvironment $script:testEnvironment
}
