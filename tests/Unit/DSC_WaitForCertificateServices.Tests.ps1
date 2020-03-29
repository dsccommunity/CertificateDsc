$script:dscModuleName = 'CertificateDsc'
$script:dscResourceName = 'DSC_WaitForCertificateServices'

function Invoke-TestSetup
{
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
        -TestType 'Unit'

    Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath '..\TestHelpers\CommonTestHelper.psm1')
}

function Invoke-TestCleanup
{
    Restore-TestEnvironment -TestEnvironment $script:testEnvironment
}

Invoke-TestSetup

# Begin Testing
try
{
    InModuleScope $script:dscResourceName {
        $caServerFQDN = 'rootca.contoso.com'
        $caRootName = 'contoso-CA'
        $retryIntervalSec = 1
        $retryCount = 5

        $paramsCAOnline = @{
            CAServerFQDN     = $caServerFQDN
            CARootName       = $caRootName
            RetryIntervalSeconds = $retryIntervalSec
            RetryCount       = $retryCount
        }

        $ca = "$caServerFQDN\$caRootName"

        Describe 'DSC_WaitForCertificateServices\Get-TargetResource' -Tag 'Get' {
            Context 'Online CA parameters passed' {
                $result = Get-TargetResource @paramsCAOnline -Verbose

                It 'Should return a hashtable' {
                    $result | Should -BeOfType System.Collections.Hashtable
                }

                It 'Should contain the same values passed as parameters' {
                    $result.CAServerFQDN         | Should -BeExactly $caServerFQDN
                    $result.CARootName           | Should -BeExactly $caRootName
                    $result.RetryIntervalSeconds | Should -Be $retryIntervalSec
                    $result.RetryCount           | Should -Be $retryCount
                }
            }
        }

        Describe 'DSC_WaitForCertificateServices\Set-TargetResource' -Tag 'Set' {
            Context 'CA is online' {
                Mock `
                    -CommandName Test-CertificateAuthority `
                    -MockWith { $true } `
                    -ParameterFilter { $CAServerFQDN -eq $caServerFQDN -and $CARootName -eq $caRootName }

                It 'Should not throw' {
                    { Set-TargetResource @paramsCAOnline -Verbose } | Should -Not -Throw
                }

                It 'Should call expected mocks' {
                    Assert-MockCalled `
                        -CommandName Test-CertificateAuthority `
                        -Exactly -Times 1
                }
            }

            Context 'CA is offline' {
                Mock `
                    -CommandName Test-CertificateAuthority `
                    -MockWith { $false } `
                    -ParameterFilter { $CAServerFQDN -eq $caServerFQDN -and $CARootName -eq $caRootName }

                Mock `
                    -CommandName Start-Sleep `
                    -MockWith { } `
                    -ParameterFilter { $Seconds -eq $retryIntervalSec }

                $errorRecord = Get-InvalidOperationRecord `
                    -Message $($localizedData.CertificateAuthorityNotFoundAfterError -f $ca,$retryCount)

                It 'Should throw CANotFoundAfterError exception' {
                    { Set-TargetResource @paramsCAOnline -Verbose } | Should -Throw $errorRecord
                }

                It 'Should call expected mocks' {
                    Assert-MockCalled `
                        -CommandName Test-CertificateAuthority `
                        -ParameterFilter { $CAServerFQDN -eq $caServerFQDN -and $CARootName -eq $caRootName } `
                        -Exactly -Times $retryCount

                    Assert-MockCalled `
                        -CommandName Start-Sleep `
                        -ParameterFilter { $Seconds -eq $retryIntervalSec } `
                        -Exactly -Times $retryCount
                }
            }
        }

        Describe 'DSC_WaitForCertificateServices\Test-TargetResource' -Tag 'Test' {
            Context 'CA is online' {
                Mock `
                    -CommandName Test-CertificateAuthority `
                    -MockWith { $true } `
                    -ParameterFilter { $CAServerFQDN -eq $caServerFQDN -and $CARootName -eq $caRootName }

                It 'Should not throw' {
                    { $script:result = Test-TargetResource @paramsCAOnline -Verbose } | Should -Not -Throw
                }

                It 'Should return true' {
                    $script:result | Should -Be $true
                }

                It 'Should call expected mocks' {
                    Assert-MockCalled `
                        -CommandName Test-CertificateAuthority `
                        -ParameterFilter { $CAServerFQDN -eq $caServerFQDN -and $CARootName -eq $caRootName } `
                        -Exactly -Times 1
                }
            }

            Context 'CA is offline' {
                Mock `
                    -CommandName Test-CertificateAuthority `
                    -MockWith { $false } `
                    -ParameterFilter { $CAServerFQDN -eq $caServerFQDN -and $CARootName -eq $caRootName }

                It 'Should not throw' {
                    { $script:result = Test-TargetResource @paramsCAOnline -Verbose } | Should -Not -Throw
                }

                It 'Should return false' {
                    $script:result | Should -Be $false
                }

                It 'Should call expected mocks' {
                    Assert-MockCalled `
                        -CommandName Test-CertificateAuthority `
                        -ParameterFilter { $CAServerFQDN -eq $caServerFQDN -and $CARootName -eq $caRootName } `
                        -Exactly -Times 1
                }
            }
        }
    }
}
finally
{
    Invoke-TestCleanup
}
