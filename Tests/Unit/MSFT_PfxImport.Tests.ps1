[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
param ()

$script:DSCModuleName      = 'CertificateDsc'
$script:DSCResourceName    = 'MSFT_PfxImport'

#region HEADER
# Integration Test Template Version: 1.1.0
[String] $script:moduleRoot = Join-Path -Path $(Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $Script:MyInvocation.MyCommand.Path))) -ChildPath 'Modules\CertificateDsc'
if ( (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
     (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone','https://github.com/PowerShell/DscResource.Tests.git',(Join-Path -Path $script:moduleRoot -ChildPath '\DSCResource.Tests\'))
}

Import-Module (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1') -Force
$TestEnvironment = Initialize-TestEnvironment `
    -DSCModuleName $script:DSCModuleName `
    -DSCResourceName $script:DSCResourceName `
    -TestType Unit
#endregion

# Begin Testing
try
{
    InModuleScope $script:DSCResourceName {
        $DSCResourceName = 'MSFT_PfxImport'
        $validThumbprint = (
            [System.AppDomain]::CurrentDomain.GetAssemblies().GetTypes() | Where-Object {
                $_.BaseType.BaseType -eq [System.Security.Cryptography.HashAlgorithm] -and
                ($_.Name -cmatch 'Managed$' -or $_.Name -cmatch 'Provider$')
            } | Select-Object -First 1 | ForEach-Object {
                (New-Object $_).ComputeHash([String]::Empty) | ForEach-Object {
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

        $PresentParams = @{
            Thumbprint = $validThumbprint
            Path       = $validPath
            Ensure     = 'Present'
            Location   = 'LocalMachine'
            Store      = 'My'
            Exportable = $True
            Credential = $testCredential
            Verbose    = $True
        }

        $AbsentParams = @{
            Thumbprint = $validThumbprint
            Path       = $validPath
            Ensure     = 'Absent'
            Location   = 'LocalMachine'
            Store      = 'My'
            Verbose    = $True
        }

        Describe "$DSCResourceName\Get-TargetResource" {
            $null | Set-Content -Path $validPath

            Context 'When yhe certificate exists with a private key' {
                Mock `
                    -CommandName Get-ChildItem `
                    -MockWith {
                        $validCertificateWithPrivateKey
                    } `
                    -ParameterFilter {
                        $Path -eq $validCertFullPath
                    }

                $result = Get-TargetResource @PresentParams

                It 'Should return a hashtable' {
                    $result | Should -BeOfType System.Collections.Hashtable
                }

                It 'Should contain the input values' {
                    $result.Thumbprint | Should -BeExactly $validThumbprint
                    $result.Path | Should -BeExactly $validPath
                    $result.Ensure | Should -BeExactly 'Present'
                }

                It 'Should call the exected mocks' {
                    Assert-MockCalled `
                        -CommandName Get-ChildItem `
                        -ParameterFilter { $Path -eq $validCertFullPath } `
                        -Exactly -Times 1
                }
            }

            Context 'When the certificate exists without private key' {
                Mock `
                    -CommandName Get-ChildItem `
                    -MockWith {
                        $validCertificateWithoutPrivateKey
                    } `
                    -ParameterFilter {
                        $Path -eq $validCertFullPath
                    }

                $null | Set-Content -Path $validPath

                $result = Get-TargetResource @PresentParams

                It 'Should return a hashtable' {
                    $result | Should -BeOfType System.Collections.Hashtable
                }

                It 'Should contain the input values' {
                    $result.Thumbprint | Should -BeExactly $validThumbprint
                    $result.Path | Should -BeExactly $validPath
                    $result.Ensure | Should -BeExactly 'Absent'
                }

                It 'Should call the exected mocks' {
                    Assert-MockCalled `
                        -CommandName Get-ChildItem `
                        -ParameterFilter { $Path -eq $validCertFullPath } `
                        -Exactly -Times 1
                }
            }

            Context 'When the certificate does not exist' {
                Mock -CommandName Get-ChildItem

                $null | Set-Content -Path $validPath

                $result = Get-TargetResource @PresentParams

                It 'Should return a hashtable' {
                    $result | Should -BeOfType System.Collections.Hashtable
                }

                It 'Should contain the input values' {
                    $result.Thumbprint | Should -BeExactly $validThumbprint
                    $result.Path | Should -BeExactly $validPath
                    $result.Ensure | Should -BeExactly 'Absent'
                }

                It 'Should call the exected mocks' {
                    Assert-MockCalled `
                        -CommandName Get-ChildItem `
                        -Exactly -Times 1
                }
            }
        }

        Describe "$DSCResourceName\Test-TargetResource" {
            $null | Set-Content -Path $validPath

            It 'Should return a bool' {
                Test-TargetResource @PresentParams | Should -BeOfType Boolean
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

                    Test-TargetResource @PresentParams | Should -Be $false
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

                    Test-TargetResource @AbsentParams | Should -Be $true
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

                    Test-TargetResource @PresentParams | Should -Be $true
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

                    Test-TargetResource @AbsentParams | Should -Be $false
                }
            }
        }

        Describe "$DSCResourceName\Set-TargetResource" {
            $null | Set-Content -Path $validPath

            Context 'When valid path and thumbprint and Ensure is Present' {
                Mock -CommandName Import-PfxCertificate -ParameterFilter {
                    $CertStoreLocation -eq $validCertPath -and `
                    $FilePath -eq $validPath -and `
                    $Exportable -eq $True -and `
                    $Password -eq $testCredential.Password
                }
                Mock -CommandName Get-ChildItem
                Mock -CommandName Remove-Item

                Set-TargetResource @PresentParams


                It 'Should call Import-PfxCertificate with the parameters supplied' {
                    Assert-MockCalled -CommandName Import-PfxCertificate -Exactly -Times 1 -ParameterFilter {
                        $CertStoreLocation -eq $validCertPath -and `
                        $FilePath -eq $validPath -and `
                        $Exportable -eq $True -and `
                        $Password -eq $testCredential.Password
                    }
                }

                It 'Should not call Get-ChildItem' {
                    Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 0
                }

                It 'Should not call Remove-Item' {
                    Assert-MockCalled -CommandName Remove-Item -Exactly -Times 0
                }
            }

            Context 'When valid path and thumbprint and Ensure is Absent' {
                Mock -CommandName Import-PfxCertificate
                Mock -CommandName Get-ChildItem -MockWith {
                    Get-Item -Path $validPath
                }
                Mock -CommandName Where-Object -MockWith {
                    Get-Item -Path $validPath
                }
                Mock -CommandName Remove-Item

                Set-TargetResource @AbsentParams

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
