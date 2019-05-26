#region HEADER
$script:dscModuleName = 'CertificateDsc'
$script:dscResourceName = 'MSFT_CertificateImport'

# Unit Test Template Version: 1.2.4
$script:moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ( (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
    (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone', 'https://github.com/PowerShell/DscResource.Tests.git', (Join-Path -Path $script:moduleRoot -ChildPath 'DscResource.Tests'))
}

Import-Module -Name (Join-Path -Path $script:moduleRoot -ChildPath (Join-Path -Path 'DSCResource.Tests' -ChildPath 'TestHelper.psm1')) -Force

$TestEnvironment = Initialize-TestEnvironment `
    -DSCModuleName $script:dscModuleName `
    -DSCResourceName $script:dscResourceName `
    -ResourceType 'Mof' `
    -TestType Unit
#endregion HEADER

# Begin Testing
try
{
    InModuleScope $script:dscResourceName {
        $definedRuntimeTypes = ([System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object -FilterScript { $null -ne $_.DefinedTypes }).GetTypes()
        $validThumbprint = (
            $definedRuntimeTypes | Where-Object -FilterScript {
                $_.BaseType.BaseType -eq [System.Security.Cryptography.HashAlgorithm] -and
                ($_.Name -cmatch 'Managed$' -or $_.Name -cmatch 'Provider$')
            } | Select-Object -First 1 | ForEach-Object -Process {
                (New-Object $_).ComputeHash([String]::Empty) | ForEach-Object -Process {
                    '{0:x2}' -f $_
                }
            }
        ) -join ''

        $testFile = 'test.cer'

        $validPath = "TestDrive:\$testFile"
        $validCertPath = "Cert:\LocalMachine\My"

        $presentParams = @{
            Thumbprint = $validThumbprint
            Path       = $validPath
            Ensure     = 'Present'
            Location   = 'LocalMachine'
            Store      = 'My'
            Verbose    = $true
        }

        $absentParams = @{
            Thumbprint = $validThumbprint
            Path       = $validPath
            Ensure     = 'Absent'
            Location   = 'LocalMachine'
            Store      = 'My'
            Verbose    = $true
        }


        Describe 'MSFT_CertificateImport\Get-TargetResource' -Tag 'Get' {
            $null | Set-Content -Path $validPath

            $result = Get-TargetResource @presentParams

            It 'Should return a hashtable' {
                $result | Should -BeOfType System.Collections.Hashtable
            }

            It 'Should contain the input values' {
                $result.Thumbprint | Should -BeExactly $validThumbprint
                $result.Path | Should -BeExactly $validPath
            }
        }

        Describe 'MSFT_CertificateImport\Test-TargetResource' -Tag 'Test' {
            $null | Set-Content -Path $validPath

            Context 'When valid path and thumbprint and certificate is not in store but should be' {
                It 'Should return false' {
                    Mock -CommandName Get-TargetResource {
                        return @{
                            Thumbprint = $validThumbprint
                            Path       = $validPath
                            Ensure     = 'Absent'
                        }
                    }

                    Test-TargetResource @presentParams | Should -Be $false
                }
            }

            Context 'When valid path and thumbprint and certificate is not in store and should not be' {
                It 'Should return true' {
                    Mock -CommandName Get-TargetResource {
                        return @{
                            Thumbprint = $validThumbprint
                            Path       = $validPath
                            Ensure     = 'Absent'
                        }
                    }

                    Test-TargetResource @absentParams | Should -Be $true
                }
            }

            Context 'When valid path and thumbprint and certificate is in store and should be' {
                It 'Should return true' {
                    Mock -CommandName Get-TargetResource {
                        return @{
                            Thumbprint = $validThumbprint
                            Path       = $validPath
                            Ensure     = 'Present'
                        }
                    }

                    Test-TargetResource @presentParams | Should -Be $true
                }
            }

            Context 'When valid path and thumbprint and certificate is in store but should not be' {
                It 'Should return false' {
                    Mock -CommandName Get-TargetResource {
                        return @{
                            Thumbprint = $validThumbprint
                            Path       = $validPath
                            Ensure     = 'Present'
                        }
                    }

                    Test-TargetResource @absentParams | Should -Be $false
                }
            }
        }

        Describe 'MSFT_CertificateImport\Set-TargetResource' -Tag 'Set' {
            $null | Set-Content -Path $validPath

            Context 'Valid path and thumbprint and Ensure is Present' {
                Mock -CommandName Import-CertificateEx
                Mock -CommandName Remove-CertificateFromCertificateStore

                Set-TargetResource @presentParams

                It 'Should call Import-Certificate with the parameters supplied' {
                    Assert-MockCalled `
                        -CommandName Import-CertificateEx `
                        -ParameterFilter {
                            $CertStoreLocation -eq $validCertPath -and `
                                $FilePath -eq $validPath
                        } -Exactly -Times 1
                }

                It 'Should not call Remove-CertificateFromCertificateStore' {
                    Assert-MockCalled -CommandName Remove-CertificateFromCertificateStore -Exactly -Times 0
                }
            }

            Context 'Valid path and thumbprint and Ensure is Absent' {
                Mock -CommandName Import-CertificateEx
                Mock -CommandName Remove-CertificateFromCertificateStore

                Set-TargetResource @absentParams

                It 'Should not call Import-CertificateEx' {
                    Assert-MockCalled -CommandName Import-CertificateEx -Exactly -Times 0
                }

                It 'Should not call Remove-CertificateFromCertificateStore' {
                    Assert-MockCalled `
                        -CommandName Remove-CertificateFromCertificateStore `
                        -ParameterFilter {
                            $Location -eq 'LocalMachine' -and `
                            $Store -eq 'My' -and `
                            $Thumbprint -eq $validThumbprint
                        } -Exactly -Times 1
                }
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
