$script:dscModuleName = 'CertificateDsc'
$script:dscResourceName = 'DSC_CertificateImport'

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
        $validThumbprint = New-CertificateThumbprint -Fips

        $testFile = 'test.cer'
        $certificateFriendlyName = 'Test Certificate Friendly Name'

        $certificateContent = [System.Convert]::ToBase64String(@(00, 00, 00))

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

        $importCertificateExWithFile_parameterfilter = {
            $CertStoreLocation -eq $validCertPath -and `
                $FilePath -eq $validPath
        }

        $importCertificateExWithContent_parameterfilter = {
            $CertStoreLocation -eq $validCertPath -and `
                $Base64Content -eq $certificateContent
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

        $presentParamsWithContent = @{
            Thumbprint   = $validThumbprint
            Content      = $certificateContent
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

        $presentParamsWithFriendlyNameWithContent = @{
            Thumbprint   = $validThumbprint
            Content      = $certificateContent
            Ensure       = 'Present'
            Location     = 'LocalMachine'
            Store        = 'My'
            Verbose      = $true
            FriendlyName = $certificateFriendlyName
        }

        $presentParamsWithoutContentAndPath = @{
            Thumbprint   = $validThumbprint
            Ensure       = 'Present'
            Location     = 'LocalMachine'
            Store        = 'My'
            Verbose      = $true
        }

        $presentParamsWithBothContentAndPath = @{
            Thumbprint   = $validThumbprint
            Content      = $certificateContent
            Path         = $validPath
            Ensure       = 'Present'
            Location     = 'LocalMachine'
            Store        = 'My'
            Verbose      = $true
        }

        $absentParamsWithBothContentAndPath = @{
            Thumbprint   = $validThumbprint
            Ensure       = 'Absent'
            Location     = 'LocalMachine'
            Store        = 'My'
            Verbose      = $true
        }

        $absentParams = @{
            Thumbprint = $validThumbprint
            Path       = $validPath
            Ensure     = 'Absent'
            Location   = 'LocalMachine'
            Store      = 'My'
            Verbose    = $true
        }

        $absentParamsWithContent = @{
            Thumbprint = $validThumbprint
            Content    = $certificateContent
            Ensure     = 'Absent'
            Location   = 'LocalMachine'
            Store      = 'My'
            Verbose    = $true
        }

        $absentParamsWithoutContentAndPath = @{
            Thumbprint = $validThumbprint
            Ensure     = 'Absent'
            Location   = 'LocalMachine'
            Store      = 'My'
            Verbose    = $true
        }

        Describe 'DSC_CertificateImport\Get-TargetResource' -Tag 'Get' {
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
                        $script:result = Get-TargetResource @presentParamsWithContent
                    } | Should -Not -Throw
                }

                It 'Should return a hashtable' {
                    $script:result | Should -BeOfType System.Collections.Hashtable
                }

                It 'Should contain the input values' {
                    $script:result.Thumbprint | Should -BeExactly $validThumbprint
                    $script:result.Path | Should -BeExactly ''
                    $script:result.Content | Should -BeExactly $presentParamsWithContent.Content
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

        Describe 'DSC_CertificateImport\Test-TargetResource' -Tag 'Test' {
            Context 'When Content and Path parameters are null' {
                It 'Should throw exception when Ensure is Present' {
                    {
                        Test-TargetResource @presentParamsWithoutContentAndPath
                    } | Should -Throw
                }

                It 'Should not throw exception when Ensure is Absent' {
                    {
                        Test-TargetResource @absentParamsWithoutContentAndPath
                    } | Should -Not -Throw
                }
            }

            Context 'When both Content and Path parameters are set' {
                It 'Should throw exception when Ensure is Present' {
                    {
                        Test-TargetResource @presentParamsWithBothContentAndPath
                    } | Should -Throw ($script:localizedData.ContentAndPathParametersAreSet)
                }

                It 'Should not throw exception when Ensure is Absent' {
                    {
                        Test-TargetResource @absentParamsWithBothContentAndPath
                    } | Should -Not -Throw
                }
            }

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

        Describe 'DSC_CertificateImport\Set-TargetResource' -Tag 'Set' {
            BeforeAll {
                Mock -CommandName Test-Path -MockWith { $true }
                Mock -CommandName Import-CertificateEx
                Mock -CommandName Remove-CertificateFromCertificateStore
                Mock -CommandName Set-CertificateFriendlyNameInCertificateStore
            }

            Context 'When Content and Path parameters are null' {
                It 'Should throw exception when Ensure is Present' {
                    {
                        Set-TargetResource @presentParamsWithoutContentAndPath
                    } | Should -Throw
                }

                It 'Should not throw exception when Ensure is Absent' {
                    {
                        Set-TargetResource @absentParamsWithoutContentAndPath
                    } | Should -Not -Throw
                }
            }

            Context 'When both Content and Path parameters are set' {
                It 'Should throw exception when Ensure is Present' {
                    {
                        Set-TargetResource @presentParamsWithBothContentAndPath
                    } | Should -Throw ($script:localizedData.ContentAndPathParametersAreSet)
                }

                It 'Should not throw exception when Ensure is Absent' {
                    {
                        Set-TargetResource @absentParamsWithBothContentAndPath
                    } | Should -Not -Throw
                }
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
                        -ParameterFilter $importCertificateExWithFile_parameterfilter `
                        -Exactly -Times 1
                }

                It 'Should not call Set-CertificateFriendlyNameInCertificateStore' {
                    Assert-MockCalled -CommandName Set-CertificateFriendlyNameInCertificateStore -Exactly -Times 0
                }

                It 'Should not call Remove-CertificateFromCertificateStore' {
                    Assert-MockCalled -CommandName Remove-CertificateFromCertificateStore -Exactly -Times 0
                }
            }

            Context 'When certificate content is used and certificate should be in the store but is not' {
                Mock -CommandName Get-CertificateFromCertificateStore

                It 'Should not throw exception' {
                    {
                        Set-TargetResource @presentParamsWithContent
                    } | Should -Not -Throw
                }

                It 'Should call Test-Path with expected parameters' {
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 0
                }

                It 'Should call Import-Certificate with expected parameters' {
                    Assert-MockCalled `
                        -CommandName Import-CertificateEx `
                        -ParameterFilter $importCertificateExWithContent_parameterfilter `
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

            Context 'When certificate content is used and certificate should be in the store and is' {
                Mock -CommandName Get-CertificateFromCertificateStore `
                    -MockWith $validCertificate_mock

                It 'Should not throw exception' {
                    {
                        Set-TargetResource @presentParamsWithContent
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

                It 'Should not call Test-Path' {
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 0
                }

                It 'Should not call Import-Certificate' {
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

            Context 'When certificate content is used and certificate should be in the store and is and the friendly name is different' {
                Mock -CommandName Get-CertificateFromCertificateStore `
                    -MockWith $validCertificateWithDifferentFriendlyName_mock

                It 'Should not throw exception' {
                    {
                        Set-TargetResource @presentParamsWithFriendlyNameWithContent
                    } | Should -Not -Throw
                }

                It 'Should not call Test-Path' {
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 0
                }

                It 'Should not call Import-Certificate' {
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

            Context 'When certificate content is used and certificate should be in the store and is and the friendly name is the same' {
                Mock -CommandName Get-CertificateFromCertificateStore `
                    -MockWith $validCertificate_mock

                It 'Should not throw exception' {
                    {
                        Set-TargetResource @presentParamsWithFriendlyNameWithContent
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

            Context 'When certificate content is used and certificate should not be in the store but is' {
                Mock -CommandName Get-CertificateFromCertificateStore `
                    -MockWith $validCertificate_mock

                It 'Should not throw exception' {
                    {
                        Set-TargetResource @absentParamsWithContent
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

            Context 'When certificate content is used and certificate should not be in the store and is not' {
                Mock -CommandName Get-CertificateFromCertificateStore

                It 'Should not throw exception' {
                    {
                        Set-TargetResource @absentParamsWithContent
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

            Context 'When certificate content is invalid and certificate should be in the store' {
                Mock -CommandName Import-CertificateEx -MockWith { throw }

                It 'Should throw exception' {
                    {
                        Set-TargetResource @presentParamsWithContent
                    } | Should -Throw
                }

                It 'Should not call Test-Path' {
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 0
                }

                It 'Should call Import-Certificate with expected parameters' {
                    Assert-MockCalled `
                        -CommandName Import-CertificateEx `
                        -ParameterFilter $importCertificateExWithContent_parameterfilter `
                        -Exactly -Times 1
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
    Invoke-TestCleanup
}
