[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
param ()

#region HEADER
$script:dscModuleName = 'CertificateDsc'
$script:dscResourceName = 'MSFT_PfxImport'

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

        $testFile = 'test.pfx'

        $testUsername = 'DummyUsername'
        $testPassword = 'DummyPassword'
        $testCredential = New-Object `
            -TypeName System.Management.Automation.PSCredential `
            -ArgumentList $testUsername, (ConvertTo-SecureString $testPassword -AsPlainText -Force)

        $validPath = "TestDrive:\$testFile"
        $validCertPath = "Cert:\LocalMachine\My"
        $validCertFullPath = '{0}\{1}' -f $validCertPath, $validThumbprint

        $validCertificateWithPrivateKey = @{
            HasPrivateKey = $true
        }

        $validCertificateWithoutPrivateKey = @{
            HasPrivateKey = $false
        }

        $testCertificatePath_parameterfilter = {
            $Path -eq $validPath
        }

        $testGetChildItem_parameterfilter = {
            $Path -eq $validCertFullPath
        }

        $importPfxCertificate_parameterfilter = {
            $CertStoreLocation -eq $validCertPath -and `
                $FilePath -eq $validPath -and `
                $Exportable -eq $True -and `
                $Password -eq $testCredential.Password
        }

        $presentParams = @{
            Thumbprint = $validThumbprint
            Path       = $validPath
            Ensure     = 'Present'
            Location   = 'LocalMachine'
            Store      = 'My'
            Exportable = $True
            Credential = $testCredential
            Verbose    = $True
        }

        $absentParams = @{
            Thumbprint = $validThumbprint
            Ensure     = 'Absent'
            Location   = 'LocalMachine'
            Store      = 'My'
            Verbose    = $True
        }

        Describe 'MSFT_PfxImport\Get-TargetResource' -Tag 'Get' {
            Context 'When the PFX file exists and the certificate exists with a private key' {
                Mock `
                    -CommandName Test-CertificatePath `
                    -MockWith {
                    $true
                } `
                    -ParameterFilter $testCertificatePath_parameterfilter

                Mock `
                    -CommandName Get-ChildItem `
                    -MockWith {
                    $validCertificateWithPrivateKey
                } `
                    -ParameterFilter $testGetChildItem_parameterfilter

                $result = Get-TargetResource @presentParams

                It 'Should return a hashtable' {
                    $result | Should -BeOfType System.Collections.Hashtable
                }

                It 'Should contain the input values' {
                    $result.Thumbprint | Should -BeExactly $validThumbprint
                    $result.Path | Should -BeExactly $validPath
                    $result.Ensure | Should -BeExactly 'Present'
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled `
                        -CommandName Test-CertificatePath `
                        -ParameterFilter $testCertificatePath_parameterfilter `
                        -Exactly -Times 1

                    Assert-MockCalled `
                        -CommandName Get-ChildItem `
                        -ParameterFilter $testGetChildItem_parameterfilter `
                        -Exactly -Times 1
                }
            }

            Context 'When the PFX file exists and the certificate exists without private key' {
                Mock `
                    -CommandName Test-CertificatePath `
                    -MockWith {
                    $true
                } `
                    -ParameterFilter $testCertificatePath_parameterfilter

                Mock `
                    -CommandName Get-ChildItem `
                    -MockWith {
                    $validCertificateWithoutPrivateKey
                } `
                    -ParameterFilter $testGetChildItem_parameterfilter

                $result = Get-TargetResource @presentParams

                It 'Should return a hashtable' {
                    $result | Should -BeOfType System.Collections.Hashtable
                }

                It 'Should contain the input values' {
                    $result.Thumbprint | Should -BeExactly $validThumbprint
                    $result.Path | Should -BeExactly $validPath
                    $result.Ensure | Should -BeExactly 'Absent'
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled `
                        -CommandName Test-CertificatePath `
                        -ParameterFilter $testCertificatePath_parameterfilter `
                        -Exactly -Times 1

                    Assert-MockCalled `
                        -CommandName Get-ChildItem `
                        -ParameterFilter $testGetChildItem_parameterfilter `
                        -Exactly -Times 1
                }
            }

            Context 'When the PFX file exists and the certificate does not exist' {
                Mock `
                    -CommandName Test-CertificatePath `
                    -MockWith {
                    $true
                } `
                    -ParameterFilter $testCertificatePath_parameterfilter

                Mock `
                    -CommandName Get-ChildItem `
                    -ParameterFilter $testGetChildItem_parameterfilter

                $result = Get-TargetResource @presentParams

                It 'Should return a hashtable' {
                    $result | Should -BeOfType System.Collections.Hashtable
                }

                It 'Should contain the input values' {
                    $result.Thumbprint | Should -BeExactly $validThumbprint
                    $result.Path | Should -BeExactly $validPath
                    $result.Ensure | Should -BeExactly 'Absent'
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled `
                        -CommandName Test-CertificatePath `
                        -ParameterFilter $testCertificatePath_parameterfilter `
                        -Exactly -Times 1

                    Assert-MockCalled `
                        -CommandName Get-ChildItem `
                        -ParameterFilter $testGetChildItem_parameterfilter `
                        -Exactly -Times 1
                }
            }

            Context 'When the PFX file does not exist and ensure is absent' {
                Mock `
                    -CommandName Test-CertificatePath `
                    -MockWith {
                    $false
                } `
                    -ParameterFilter $testCertificatePath_parameterfilter

                Mock `
                    -CommandName Get-ChildItem `
                    -MockWith {
                    $validCertificateWithoutPrivateKey
                } `
                    -ParameterFilter $testGetChildItem_parameterfilter

                $result = Get-TargetResource @absentParams

                It 'Should return a hashtable' {
                    $result | Should -BeOfType System.Collections.Hashtable
                }

                It 'Should contain the input values' {
                    $result.Thumbprint | Should -BeExactly $validThumbprint
                    $result.Ensure | Should -BeExactly 'Absent'
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled `
                        -CommandName Test-CertificatePath `
                        -ParameterFilter $testCertificatePath_parameterfilter `
                        -Exactly -Times 0

                    Assert-MockCalled `
                        -CommandName Get-ChildItem `
                        -ParameterFilter $testGetChildItem_parameterfilter `
                        -Exactly -Times 1
                }
            }

            Context 'When the PFX file does not exist and ensure is present' {
                Mock `
                    -CommandName Test-CertificatePath `
                    -MockWith {
                    $false
                } `
                    -ParameterFilter $testCertificatePath_parameterfilter

                It 'Should throw expected exception' {
                    $errorRecord = Get-InvalidArgumentRecord `
                        -Message ($LocalizedData.CertificatePfxFileNotFoundError -f $validPath) `
                        -ArgumentName 'Path'

                    {
                        $script:result = Get-TargetResource @presentParams
                    } | Should -Throw $errorRecord
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled `
                        -CommandName Test-CertificatePath `
                        -ParameterFilter $testCertificatePath_parameterfilter `
                        -Exactly -Times 1
                }
            }
        }

        Describe 'MSFT_PfxImport\Test-TargetResource' -Tag 'Test' {
            It 'Should return a bool' {
                Mock -CommandName Get-TargetResource {
                    return @{
                        Thumbprint = $validThumbprint
                        Path       = $validPath
                        Ensure     = 'Absent'
                    }
                }

                Test-TargetResource @presentParams | Should -BeOfType Boolean
            }

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

            Context 'When valid path and thumbprint and PFX is not in store and should not be' {
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

            Context 'When valid path and thumbprint and PFX is in store and should be' {
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

            Context 'When valid path and thumbprint and PFX is in store but should not be' {
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

        Describe 'MSFT_PfxImport\Set-TargetResource' -Tag 'Set' {
            Context 'When PFX file exists and thumbprint and Ensure is Present' {
                Mock `
                    -CommandName Import-PfxCertificate `
                    -ParameterFilter $importPfxCertificate_parameterfilter
                Mock -CommandName Get-ChildItem
                Mock -CommandName Remove-Item

                Set-TargetResource @presentParams

                It 'Should call Import-PfxCertificate with the parameters supplied' {
                    Assert-MockCalled `
                        -CommandName Import-PfxCertificate `
                        -ParameterFilter $importPfxCertificate_parameterfilter `
                        -Exactly -Times 1
                }

                It 'Should not call Get-ChildItem' {
                    Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 0
                }

                It 'Should not call Remove-Item' {
                    Assert-MockCalled -CommandName Remove-Item -Exactly -Times 0
                }
            }

            Context 'When certificate exists and Ensure is Absent' {
                Mock -CommandName Import-PfxCertificate
                Mock -CommandName Get-ChildItem -MockWith {
                    @{ Thumbprint = $validThumbprint }
                }
                Mock -CommandName Remove-Item

                Set-TargetResource @absentParams

                It 'Should not call Import-PfxCertificate' {
                    Assert-MockCalled -CommandName Import-PfxCertificate -Exactly -Times 0
                }

                It 'Should call Get-ChildItem' {
                    Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
                }

                It 'Should call Remove-Item' {
                    Assert-MockCalled -CommandName Remove-Item -Exactly -Times 1
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
