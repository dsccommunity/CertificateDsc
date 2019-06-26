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
        $certificateFriendlyName = 'Test Certificate Friendly Name'

        $validPath = "TestDrive:\$testFile"
        $validCertPath = "Cert:\LocalMachine\My"

        $validCertificate_mock = {
            @{
                Thumbprint   = $validThumbprint
                FriendlyName = $certificateFriendlyName
            }
        }

        $validCertificateWithDifferentFriendlyName_mock = {
            @{
                Thumbprint   = $validThumbprint
                FriendlyName = 'Different Friendly Name'
            }
        }

        $testPath_parameterfilter = {
            $Path -eq $validPath
        }

        $getCertificateFromCertificateStore_parameterfilter = {
            $Thumbprint -eq $validThumbprint -and `
                $Location -eq 'LocalMachine' -and `
                $Store -eq 'My'
        }

        $importCertificateEx_parameterfilter = {
            $CertStoreLocation -eq $validCertPath -and `
                $FilePath -eq $validPath
        }

        $setCertificateFriendlyNameInCertificateStore_parameterfilter = {
            $Thumbprint -eq $validThumbprint -and `
                $Location -eq 'LocalMachine' -and `
                $Store -eq 'My' -and `
                $FriendlyName -eq $certificateFriendlyName
        }

        $removeCertificateFromCertificateStore_parameterfilter = {
            $Location -eq 'LocalMachine' -and `
                $Store -eq 'My' -and `
                $Thumbprint -eq $validThumbprint
        }

        $presentParams = @{
            Thumbprint   = $validThumbprint
            Path         = $validPath
            Ensure       = 'Present'
            Location     = 'LocalMachine'
            Store        = 'My'
            Verbose      = $true
        }

        $presentParamsWithFriendlyName = @{
            Thumbprint   = $validThumbprint
            Path         = $validPath
            Ensure       = 'Present'
            Location     = 'LocalMachine'
            Store        = 'My'
            Verbose      = $true
            FriendlyName = $certificateFriendlyName
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
            Context 'When the certificate exists' {
                Mock -CommandName Get-CertificateFromCertificateStore `
                    -MockWith $validCertificate_mock

                It 'Should not throw exception' {
                    {
                        $script:result = Get-TargetResource @presentParams
                    } | Should -Not -Throw
                }

                It 'Should return a hashtable' {
                    $script:result | Should -BeOfType System.Collections.Hashtable
                }

                It 'Should contain the input values' {
                    $script:result.Thumbprint | Should -BeExactly $validThumbprint
                    $script:result.Path | Should -BeExactly $validPath
                    $script:result.Ensure | Should -BeExactly 'Present'
                    $script:result.FriendlyName | Should -BeExactly $certificateFriendlyName
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled `
                        -CommandName Get-CertificateFromCertificateStore `
                        -ParameterFilter $getCertificateFromCertificateStore_parameterfilter `
                        -Exactly -Times 1
                }
            }

            Context 'When the certificate does not exist' {
                Mock -CommandName Get-CertificateFromCertificateStore

                It 'Should not throw exception' {
                    {
                        $script:result = Get-TargetResource @presentParams
                    } | Should -Not -Throw
                }

                It 'Should return a hashtable' {
                    $script:result | Should -BeOfType System.Collections.Hashtable
                }

                It 'Should contain the input values' {
                    $script:result.Thumbprint | Should -BeExactly $validThumbprint
                    $script:result.Path | Should -BeExactly $validPath
                    $script:result.Ensure | Should -BeExactly 'Absent'
                    $script:result.FriendlyName | Should -BeNullOrEmpty
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled `
                        -CommandName Get-CertificateFromCertificateStore `
                        -ParameterFilter $getCertificateFromCertificateStore_parameterfilter `
                        -Exactly -Times 1
                }
            }
        }

        Describe 'MSFT_CertificateImport\Test-TargetResource' -Tag 'Test' {
            Context 'When certificate is not in store but should be' {
                Mock -CommandName Get-CertificateFromCertificateStore

                It 'Should return false' {
                    Test-TargetResource @presentParams | Should -Be $false
                }
            }

            Context 'When certificate is not in store and should not be' {
                Mock -CommandName Get-CertificateFromCertificateStore

                It 'Should return true' {
                    Test-TargetResource @absentParams | Should -Be $true
                }
            }

            Context 'When certificate is in store and should be' {
                Mock -CommandName Get-CertificateFromCertificateStore `
                    -MockWith $validCertificate_mock

                It 'Should return true' {
                    Test-TargetResource @presentParams | Should -Be $true
                }
            }

            Context 'When certificate is in store and should be and the FriendlyName is correct' {
                Mock -CommandName Get-CertificateFromCertificateStore `
                    -MockWith $validCertificate_mock

                It 'Should return true' {
                    Test-TargetResource @presentParamsWithFriendlyName | Should -Be $true
                }
            }

            Context 'When certificate is in store and should be but the Friendlyname is different' {
                Mock -CommandName Get-CertificateFromCertificateStore `
                    -MockWith $validCertificateWithDifferentFriendlyName_mock

                It 'Should return false' {
                    Test-TargetResource @presentParamsWithFriendlyName | Should -Be $false
                }
            }

            Context 'When certificate is in store but should not be' {
                Mock -CommandName Get-CertificateFromCertificateStore `
                    -MockWith $validCertificate_mock

                It 'Should return false' {
                    Test-TargetResource @absentParams | Should -Be $false
                }
            }
        }

        Describe 'MSFT_CertificateImport\Set-TargetResource' -Tag 'Set' {
            BeforeAll {
                Mock -CommandName Test-Path -MockWith { $true }
                Mock -CommandName Import-CertificateEx
                Mock -CommandName Remove-CertificateFromCertificateStore
                Mock -CommandName Set-CertificateFriendlyNameInCertificateStore
            }

            Context 'When certificate file exists and certificate should be in the store but is not' {
                Mock -CommandName Get-CertificateFromCertificateStore

                It 'Should not throw exception' {
                    {
                        Set-TargetResource @presentParams
                    } | Should -Not -Throw
                }

                It 'Should call Test-Path with expected parameters' {
                    Assert-MockCalled `
                        -CommandName Test-Path `
                        -ParameterFilter $testPath_parameterfilter `
                        -Exactly -Times 1
                }

                It 'Should call Import-Certificate with expected parameters' {
                    Assert-MockCalled `
                        -CommandName Import-CertificateEx `
                        -ParameterFilter $importCertificateEx_parameterfilter `
                        -Exactly -Times 1
                }

                It 'Should not call Set-CertificateFriendlyNameInCertificateStore' {
                    Assert-MockCalled -CommandName Set-CertificateFriendlyNameInCertificateStore -Exactly -Times 0
                }

                It 'Should not call Remove-CertificateFromCertificateStore' {
                    Assert-MockCalled -CommandName Remove-CertificateFromCertificateStore -Exactly -Times 0
                }
            }

            Context 'When certificate file exists and certificate should be in the store and is' {
                Mock -CommandName Get-CertificateFromCertificateStore `
                    -MockWith $validCertificate_mock

                It 'Should not throw exception' {
                    {
                        Set-TargetResource @presentParams
                    } | Should -Not -Throw
                }

                It 'Should not call Test-Path' {
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 0
                }

                It 'Should not call Import-Certificate' {
                    Assert-MockCalled -CommandName Import-CertificateEx -Exactly -Times 0
                }

                It 'Should not call Set-CertificateFriendlyNameInCertificateStore' {
                    Assert-MockCalled -CommandName Set-CertificateFriendlyNameInCertificateStore -Exactly -Times 0
                }

                It 'Should not call Remove-CertificateFromCertificateStore' {
                    Assert-MockCalled -CommandName Remove-CertificateFromCertificateStore -Exactly -Times 0
                }
            }

            Context 'When certificate file exists and certificate should be in the store and is and the friendly name is different' {
                Mock -CommandName Get-CertificateFromCertificateStore `
                    -MockWith $validCertificateWithDifferentFriendlyName_mock

                It 'Should not throw exception' {
                    {
                        Set-TargetResource @presentParamsWithFriendlyName
                    } | Should -Not -Throw
                }

                It 'Should not call Test-Path with the parameters supplied' {
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 0
                }

                It 'Should not call Import-Certificate with the parameters supplied' {
                    Assert-MockCalled -CommandName Import-CertificateEx -Exactly -Times 0
                }

                It 'Should call Set-CertificateFriendlyNameInCertificateStore with expected parameters' {
                    Assert-MockCalled `
                        -CommandName Set-CertificateFriendlyNameInCertificateStore `
                        -ParameterFilter $setCertificateFriendlyNameInCertificateStore_parameterfilter `
                        -Exactly -Times 1
                }

                It 'Should not call Remove-CertificateFromCertificateStore' {
                    Assert-MockCalled -CommandName Remove-CertificateFromCertificateStore -Exactly -Times 0
                }
            }

            Context 'When certificate file exists and certificate should be in the store and is and the friendly name is the same' {
                Mock -CommandName Get-CertificateFromCertificateStore `
                    -MockWith $validCertificate_mock

                It 'Should not throw exception' {
                    {
                        Set-TargetResource @presentParamsWithFriendlyName
                    } | Should -Not -Throw
                }

                It 'Should not call Test-Path with the parameters supplied' {
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 0
                }

                It 'Should not call Import-Certificate with the parameters supplied' {
                    Assert-MockCalled -CommandName Import-CertificateEx -Exactly -Times 0
                }

                It 'Should not call Set-CertificateFriendlyNameInCertificateStore' {
                    Assert-MockCalled -CommandName Set-CertificateFriendlyNameInCertificateStore -Exactly -Times 0
                }

                It 'Should not call Remove-CertificateFromCertificateStore' {
                    Assert-MockCalled -CommandName Remove-CertificateFromCertificateStore -Exactly -Times 0
                }
            }

            Context 'When certificate file exists and certificate should not be in the store but is' {
                Mock -CommandName Get-CertificateFromCertificateStore `
                    -MockWith $validCertificate_mock

                It 'Should not throw exception' {
                    {
                        Set-TargetResource @absentParams
                    } | Should -Not -Throw
                }

                It 'Should not call Test-Path' {
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 0
                }

                It 'Should not call Import-CertificateEx' {
                    Assert-MockCalled -CommandName Import-CertificateEx -Exactly -Times 0
                }

                It 'Should not call Set-CertificateFriendlyNameInCertificateStore' {
                    Assert-MockCalled -CommandName Set-CertificateFriendlyNameInCertificateStore -Exactly -Times 0
                }

                It 'Should call Remove-CertificateFromCertificateStore with expected parameters' {
                    Assert-MockCalled `
                        -CommandName Remove-CertificateFromCertificateStore `
                        -ParameterFilter $removeCertificateFromCertificateStore_parameterfilter `
                        -Exactly -Times 1
                }
            }

            Context 'When certificate file exists and certificate should not be in the store and is not' {
                Mock -CommandName Get-CertificateFromCertificateStore

                It 'Should not throw exception' {
                    {
                        Set-TargetResource @absentParams
                    } | Should -Not -Throw
                }

                It 'Should not call Test-Path' {
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 0
                }

                It 'Should not call Import-CertificateEx' {
                    Assert-MockCalled -CommandName Import-CertificateEx -Exactly -Times 0
                }

                It 'Should not call Set-CertificateFriendlyNameInCertificateStore' {
                    Assert-MockCalled -CommandName Set-CertificateFriendlyNameInCertificateStore -Exactly -Times 0
                }

                It 'Should call Remove-CertificateFromCertificateStore' {
                    Assert-MockCalled `
                        -CommandName Remove-CertificateFromCertificateStore `
                        -ParameterFilter $removeCertificateFromCertificateStore_parameterfilter `
                        -Exactly -Times 1
                }
            }

            Context 'When certificate file does not exist and certificate should be in the store' {
                Mock -CommandName Test-Path -MockWith { $false }

                It 'Should throw exception' {
                    {
                        Set-TargetResource @presentParams
                    } | Should -Throw ($script:localizedData.CertificatePfxFileNotFoundError -f $validPath)
                }

                It 'Should call Test-Path with the parameters supplied' {
                    Assert-MockCalled `
                        -CommandName Test-Path `
                        -ParameterFilter $testPath_parameterfilter `
                        -Exactly -Times 1
                }

                It 'Should not call Import-CertificateEx' {
                    Assert-MockCalled -CommandName Import-CertificateEx -Exactly -Times 0
                }

                It 'Should not call Set-CertificateFriendlyNameInCertificateStore' {
                    Assert-MockCalled -CommandName Set-CertificateFriendlyNameInCertificateStore -Exactly -Times 0
                }

                It 'Should not call Remove-CertificateFromCertificateStore' {
                    Assert-MockCalled -CommandName Remove-CertificateFromCertificateStore -Exactly -Times 0
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
