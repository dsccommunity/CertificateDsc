#region HEADER
$script:moduleName = 'CertificateDsc.Common'

# Unit Test Template Version: 1.2.4
$script:moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ( (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
    (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone', 'https://github.com/PowerShell/DscResource.Tests.git', (Join-Path -Path $script:moduleRoot -ChildPath 'DscResource.Tests'))
}

Import-Module -Name (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1') -Force
Import-Module -Name (Join-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath (Join-Path -Path 'Modules' -ChildPath $script:ModuleName)) -ChildPath "$script:ModuleName.psm1") -Force
Import-Module -Name (Join-Path -Path (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'TestHelpers') -ChildPath 'CommonTestHelper.psm1') -Global
#endregion HEADER

# Begin Testing
InModuleScope 'CertificateDsc.Common' {
    Describe 'CertificateDsc.Common\Test-DscParameterState' -Tag TestDscParameterState {
        Context -Name 'When passing values' -Fixture {
            It 'Should return true for two identical tables' {
                $mockDesiredValues = @{ Example = 'test' }

                $testParameters = @{
                    CurrentValues = $mockDesiredValues
                    DesiredValues = $mockDesiredValues
                }

                Test-DscParameterState @testParameters | Should -Be $true
            }

            It 'Should return false when a value is different for [System.String]' {
                $mockCurrentValues = @{ Example = [System.String] 'something' }
                $mockDesiredValues = @{ Example = [System.String] 'test' }

                $testParameters = @{
                    CurrentValues = $mockCurrentValues
                    DesiredValues = $mockDesiredValues
                }

                Test-DscParameterState @testParameters | Should -Be $false
            }

            It 'Should return false when a value is different for [System.Int32]' {
                $mockCurrentValues = @{ Example = [System.Int32] 1 }
                $mockDesiredValues = @{ Example = [System.Int32] 2 }

                $testParameters = @{
                    CurrentValues = $mockCurrentValues
                    DesiredValues = $mockDesiredValues
                }

                Test-DscParameterState @testParameters | Should -Be $false
            }

            It 'Should return false when a value is different for [Int16]' {
                $mockCurrentValues = @{ Example = [System.Int16] 1 }
                $mockDesiredValues = @{ Example = [System.Int16] 2 }

                $testParameters = @{
                    CurrentValues = $mockCurrentValues
                    DesiredValues = $mockDesiredValues
                }

                Test-DscParameterState @testParameters | Should -Be $false
            }

            It 'Should return false when a value is different for [UInt16]' {
                $mockCurrentValues = @{ Example = [System.UInt16] 1 }
                $mockDesiredValues = @{ Example = [System.UInt16] 2 }

                $testParameters = @{
                    CurrentValues = $mockCurrentValues
                    DesiredValues = $mockDesiredValues
                }

                Test-DscParameterState @testParameters | Should -Be $false
            }

            It 'Should return false when a value is different for [Boolean]' {
                $mockCurrentValues = @{ Example = [System.Boolean] $true }
                $mockDesiredValues = @{ Example = [System.Boolean] $false }

                $testParameters = @{
                    CurrentValues = $mockCurrentValues
                    DesiredValues = $mockDesiredValues
                }

                Test-DscParameterState @testParameters | Should -Be $false
            }

            It 'Should return false when a value is missing' {
                $mockCurrentValues = @{ }
                $mockDesiredValues = @{ Example = 'test' }

                $testParameters = @{
                    CurrentValues = $mockCurrentValues
                    DesiredValues = $mockDesiredValues
                }

                Test-DscParameterState @testParameters | Should -Be $false
            }

            It 'Should return true when only a specified value matches, but other non-listed values do not' {
                $mockCurrentValues = @{ Example = 'test'; SecondExample = 'true' }
                $mockDesiredValues = @{ Example = 'test'; SecondExample = 'false' }

                $testParameters = @{
                    CurrentValues = $mockCurrentValues
                    DesiredValues = $mockDesiredValues
                    ValuesToCheck = @('Example')
                }

                Test-DscParameterState @testParameters | Should -Be $true
            }

            It 'Should return false when only specified values do not match, but other non-listed values do ' {
                $mockCurrentValues = @{ Example = 'test'; SecondExample = 'true' }
                $mockDesiredValues = @{ Example = 'test'; SecondExample = 'false' }

                $testParameters = @{
                    CurrentValues = $mockCurrentValues
                    DesiredValues = $mockDesiredValues
                    ValuesToCheck = @('SecondExample')
                }

                Test-DscParameterState @testParameters | Should -Be $false
            }

            It 'Should return false when an empty hash table is used in the current values' {
                $mockCurrentValues = @{ }
                $mockDesiredValues = @{ Example = 'test'; SecondExample = 'false' }

                $testParameters = @{
                    CurrentValues = $mockCurrentValues
                    DesiredValues = $mockDesiredValues
                }

                Test-DscParameterState @testParameters | Should -Be $false
            }

            It 'Should return true when evaluating a table against a CimInstance' {
                $mockCurrentValues = @{ Handle = '0'; ProcessId = '1000' }

                $mockWin32ProcessProperties = @{
                    Handle    = 0
                    ProcessId = 1000
                }

                $mockNewCimInstanceParameters = @{
                    ClassName  = 'Win32_Process'
                    Property   = $mockWin32ProcessProperties
                    Key        = 'Handle'
                    ClientOnly = $true
                }

                $mockDesiredValues = New-CimInstance @mockNewCimInstanceParameters

                $testParameters = @{
                    CurrentValues = $mockCurrentValues
                    DesiredValues = $mockDesiredValues
                    ValuesToCheck = @('Handle', 'ProcessId')
                }

                Test-DscParameterState @testParameters | Should -Be $true
            }

            It 'Should return false when evaluating a table against a CimInstance and a value is wrong' {
                $mockCurrentValues = @{ Handle = '1'; ProcessId = '1000' }

                $mockWin32ProcessProperties = @{
                    Handle    = 0
                    ProcessId = 1000
                }

                $mockNewCimInstanceParameters = @{
                    ClassName  = 'Win32_Process'
                    Property   = $mockWin32ProcessProperties
                    Key        = 'Handle'
                    ClientOnly = $true
                }

                $mockDesiredValues = New-CimInstance @mockNewCimInstanceParameters

                $testParameters = @{
                    CurrentValues = $mockCurrentValues
                    DesiredValues = $mockDesiredValues
                    ValuesToCheck = @('Handle', 'ProcessId')
                }

                Test-DscParameterState @testParameters | Should -Be $false
            }

            It 'Should return true when evaluating a hash table containing an array' {
                $mockCurrentValues = @{ Example = 'test'; SecondExample = @('1', '2') }
                $mockDesiredValues = @{ Example = 'test'; SecondExample = @('1', '2') }

                $testParameters = @{
                    CurrentValues = $mockCurrentValues
                    DesiredValues = $mockDesiredValues
                }

                Test-DscParameterState @testParameters | Should -Be $true
            }

            It 'Should return false when evaluating a hash table containing an array with wrong values' {
                $mockCurrentValues = @{ Example = 'test'; SecondExample = @('A', 'B') }
                $mockDesiredValues = @{ Example = 'test'; SecondExample = @('1', '2') }

                $testParameters = @{
                    CurrentValues = $mockCurrentValues
                    DesiredValues = $mockDesiredValues
                }

                Test-DscParameterState @testParameters | Should -Be $false
            }

            It 'Should return false when evaluating a hash table containing an array, but the CurrentValues are missing an array' {
                $mockCurrentValues = @{ Example = 'test' }
                $mockDesiredValues = @{ Example = 'test'; SecondExample = @('1', '2') }

                $testParameters = @{
                    CurrentValues = $mockCurrentValues
                    DesiredValues = $mockDesiredValues
                }

                Test-DscParameterState @testParameters | Should -Be $false
            }

            It 'Should return false when evaluating a hash table containing an array, but the property i CurrentValues is $null' {
                $mockCurrentValues = @{ Example = 'test'; SecondExample = $null }
                $mockDesiredValues = @{ Example = 'test'; SecondExample = @('1', '2') }

                $testParameters = @{
                    CurrentValues = $mockCurrentValues
                    DesiredValues = $mockDesiredValues
                }

                Test-DscParameterState @testParameters | Should -Be $false
            }
        }

        Context -Name 'When passing invalid types for DesiredValues' -Fixture {
            It 'Should throw the correct error when DesiredValues is of wrong type' {
                $mockCurrentValues = @{ Example = 'something' }
                $mockDesiredValues = 'NotHashTable'

                $testParameters = @{
                    CurrentValues = $mockCurrentValues
                    DesiredValues = $mockDesiredValues
                }

                $mockCorrectErrorMessage = ($script:localizedData.PropertyTypeInvalidForDesiredValues -f $testParameters.DesiredValues.GetType().Name)
                { Test-DscParameterState @testParameters } | Should -Throw $mockCorrectErrorMessage
            }

            It 'Should write a warning when DesiredValues contain an unsupported type' {
                Mock -CommandName Write-Warning -Verifiable

                # This is a dummy type to test with a type that could never be a correct one.
                class MockUnknownType
                {
                    [ValidateNotNullOrEmpty()]
                    [System.String]
                    $Property1

                    [ValidateNotNullOrEmpty()]
                    [System.String]
                    $Property2

                    MockUnknownType()
                    {
                    }
                }

                $mockCurrentValues = @{ Example = New-Object -TypeName MockUnknownType }
                $mockDesiredValues = @{ Example = New-Object -TypeName MockUnknownType }

                $testParameters = @{
                    CurrentValues = $mockCurrentValues
                    DesiredValues = $mockDesiredValues
                }

                Test-DscParameterState @testParameters | Should -Be $false

                Assert-MockCalled -CommandName Write-Warning -Exactly -Times 1
            }
        }

        Context -Name 'When passing an CimInstance as DesiredValue and ValuesToCheck is $null' -Fixture {
            It 'Should throw the correct error' {
                $mockCurrentValues = @{ Example = 'something' }

                $mockWin32ProcessProperties = @{
                    Handle    = 0
                    ProcessId = 1000
                }

                $mockNewCimInstanceParameters = @{
                    ClassName  = 'Win32_Process'
                    Property   = $mockWin32ProcessProperties
                    Key        = 'Handle'
                    ClientOnly = $true
                }

                $mockDesiredValues = New-CimInstance @mockNewCimInstanceParameters

                $testParameters = @{
                    CurrentValues = $mockCurrentValues
                    DesiredValues = $mockDesiredValues
                    ValuesToCheck = $null
                }

                $mockCorrectErrorMessage = $script:localizedData.PropertyTypeInvalidForValuesToCheck
                { Test-DscParameterState @testParameters } | Should -Throw $mockCorrectErrorMessage
            }
        }

        Assert-VerifiableMock
    }

    Describe 'CertificateDsc.Common\Get-LocalizedData' {
        $mockTestPath = {
            return $mockTestPathReturnValue
        }

        $mockImportLocalizedData = {
            $BaseDirectory | Should -Be $mockExpectedLanguagePath
        }

        BeforeEach {
            Mock -CommandName Test-Path -MockWith $mockTestPath -Verifiable
            Mock -CommandName Import-LocalizedData -MockWith $mockImportLocalizedData -Verifiable
        }

        Context 'When loading localized data for Swedish' {
            $mockExpectedLanguagePath = 'sv-SE'
            $mockTestPathReturnValue = $true

            It 'Should call Import-LocalizedData with sv-SE language' {
                Mock -CommandName Join-Path -MockWith {
                    return 'sv-SE'
                } -Verifiable

                { Get-LocalizedData -ResourceName 'DummyResource' } | Should -Not -Throw

                Assert-MockCalled -CommandName Join-Path -Exactly -Times 3 -Scope It
                Assert-MockCalled -CommandName Test-Path -Exactly -Times 1 -Scope It
                Assert-MockCalled -CommandName Import-LocalizedData -Exactly -Times 1 -Scope It
            }

            $mockExpectedLanguagePath = 'en-US'
            $mockTestPathReturnValue = $false

            It 'Should call Import-LocalizedData and fallback to en-US if sv-SE language does not exist' {
                Mock -CommandName Join-Path -MockWith {
                    return $ChildPath
                } -Verifiable

                { Get-LocalizedData -ResourceName 'DummyResource' } | Should -Not -Throw

                Assert-MockCalled -CommandName Join-Path -Exactly -Times 4 -Scope It
                Assert-MockCalled -CommandName Test-Path -Exactly -Times 1 -Scope It
                Assert-MockCalled -CommandName Import-LocalizedData -Exactly -Times 1 -Scope It
            }

            Context 'When $ScriptRoot is set to a path' {
                $mockExpectedLanguagePath = 'sv-SE'
                $mockTestPathReturnValue = $true

                It 'Should call Import-LocalizedData with sv-SE language' {
                    Mock -CommandName Join-Path -MockWith {
                        return 'sv-SE'
                    } -Verifiable

                    { Get-LocalizedData -ResourceName 'DummyResource' -ScriptRoot '.' } | Should -Not -Throw

                    Assert-MockCalled -CommandName Join-Path -Exactly -Times 1 -Scope It
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1 -Scope It
                    Assert-MockCalled -CommandName Import-LocalizedData -Exactly -Times 1 -Scope It
                }

                $mockExpectedLanguagePath = 'en-US'
                $mockTestPathReturnValue = $false

                It 'Should call Import-LocalizedData and fallback to en-US if sv-SE language does not exist' {
                    Mock -CommandName Join-Path -MockWith {
                        return $ChildPath
                    } -Verifiable

                    { Get-LocalizedData -ResourceName 'DummyResource' -ScriptRoot '.' } | Should -Not -Throw

                    Assert-MockCalled -CommandName Join-Path -Exactly -Times 2 -Scope It
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1 -Scope It
                    Assert-MockCalled -CommandName Import-LocalizedData -Exactly -Times 1 -Scope It
                }
            }
        }

        Context 'When loading localized data for English' {
            Mock -CommandName Join-Path -MockWith {
                return 'en-US'
            } -Verifiable

            $mockExpectedLanguagePath = 'en-US'
            $mockTestPathReturnValue = $true

            It 'Should call Import-LocalizedData with en-US language' {
                { Get-LocalizedData -ResourceName 'DummyResource' } | Should -Not -Throw
            }
        }

        Assert-VerifiableMock
    }

    Describe 'CertificateDsc.Common\New-InvalidResultException' {
        Context 'When calling with Message parameter only' {
            It 'Should throw the correct error' {
                $mockErrorMessage = 'Mocked error'

                { New-InvalidResultException -Message $mockErrorMessage } | Should -Throw $mockErrorMessage
            }
        }

        Context 'When calling with both the Message and ErrorRecord parameter' {
            It 'Should throw the correct error' {
                $mockErrorMessage = 'Mocked error'
                $mockExceptionErrorMessage = 'Mocked exception error message'

                $mockException = New-Object -TypeName System.Exception -ArgumentList $mockExceptionErrorMessage
                $mockErrorRecord = New-Object -TypeName System.Management.Automation.ErrorRecord -ArgumentList $mockException, $null, 'InvalidResult', $null

                { New-InvalidResultException -Message $mockErrorMessage -ErrorRecord $mockErrorRecord } | Should -Throw ('System.Exception: {0} ---> System.Exception: {1}' -f $mockErrorMessage, $mockExceptionErrorMessage)
            }
        }

        Assert-VerifiableMock
    }

    Describe 'CertificateDsc.Common\New-ObjectNotFoundException' {
        Context 'When calling with Message parameter only' {
            It 'Should throw the correct error' {
                $mockErrorMessage = 'Mocked error'

                { New-ObjectNotFoundException -Message $mockErrorMessage } | Should -Throw $mockErrorMessage
            }
        }

        Context 'When calling with both the Message and ErrorRecord parameter' {
            It 'Should throw the correct error' {
                $mockErrorMessage = 'Mocked error'
                $mockExceptionErrorMessage = 'Mocked exception error message'

                $mockException = New-Object -TypeName System.Exception -ArgumentList $mockExceptionErrorMessage
                $mockErrorRecord = New-Object -TypeName System.Management.Automation.ErrorRecord -ArgumentList $mockException, $null, 'InvalidResult', $null

                { New-ObjectNotFoundException -Message $mockErrorMessage -ErrorRecord $mockErrorRecord } | Should -Throw ('System.Exception: {0} ---> System.Exception: {1}' -f $mockErrorMessage, $mockExceptionErrorMessage)
            }
        }

        Assert-VerifiableMock
    }

    Describe 'CertificateDsc.Common\New-InvalidOperationException' {
        Context 'When calling with Message parameter only' {
            It 'Should throw the correct error' {
                $mockErrorMessage = 'Mocked error'

                { New-InvalidOperationException -Message $mockErrorMessage } | Should -Throw $mockErrorMessage
            }
        }

        Context 'When calling with both the Message and ErrorRecord parameter' {
            It 'Should throw the correct error' {
                $mockErrorMessage = 'Mocked error'
                $mockExceptionErrorMessage = 'Mocked exception error message'

                $mockException = New-Object -TypeName System.Exception -ArgumentList $mockExceptionErrorMessage
                $mockErrorRecord = New-Object -TypeName System.Management.Automation.ErrorRecord -ArgumentList $mockException, $null, 'InvalidResult', $null

                { New-InvalidOperationException -Message $mockErrorMessage -ErrorRecord $mockErrorRecord } | Should -Throw ('System.InvalidOperationException: {0} ---> System.Exception: {1}' -f $mockErrorMessage, $mockExceptionErrorMessage)
            }
        }

        Assert-VerifiableMock
    }

    Describe 'CertificateDsc.Common\New-NotImplementedException' {
        Context 'When called with Message parameter only' {
            It 'Should throw the correct error' {
                $mockErrorMessage = 'Mocked error'

                { New-NotImplementedException -Message $mockErrorMessage } | Should -Throw $mockErrorMessage
            }
        }

        Context 'When called with both the Message and ErrorRecord parameter' {
            It 'Should throw the correct error' {
                $mockErrorMessage = 'Mocked error'
                $mockExceptionErrorMessage = 'Mocked exception error message'

                $mockException = New-Object -TypeName System.Exception -ArgumentList $mockExceptionErrorMessage
                $mockErrorRecord = New-Object -TypeName System.Management.Automation.ErrorRecord -ArgumentList $mockException, $null, 'InvalidResult', $null

                { New-NotImplementedException -Message $mockErrorMessage -ErrorRecord $mockErrorRecord } | Should -Throw ('System.NotImplementedException: {0} ---> System.Exception: {1}' -f $mockErrorMessage, $mockExceptionErrorMessage)
            }
        }

        Assert-VerifiableMock
    }

    Describe 'CertificateDsc.Common\New-InvalidArgumentException' {
        Context 'When calling with both the Message and ArgumentName parameter' {
            It 'Should throw the correct error' {
                $mockErrorMessage = 'Mocked error'
                $mockArgumentName = 'MockArgument'

                { New-InvalidArgumentException -Message $mockErrorMessage -ArgumentName $mockArgumentName } | Should -Throw ('Parameter name: {0}' -f $mockArgumentName)
            }
        }

        Assert-VerifiableMock
    }

    $invalidThumbprint = 'Zebra'
    $definedRuntimeTypes = ([System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object -FilterScript { $null -ne $_.DefinedTypes }).GetTypes()

    # This thumbprint is valid (but not FIPS valid)
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

    # This thumbprint is valid for FIPS
    $validFipsThumbprint = (
        $definedRuntimeTypes | Where-Object -FilterScript {
            $_.BaseType.BaseType -eq [System.Security.Cryptography.HashAlgorithm] -and
            ($_.Name -cmatch 'Provider$' -and $_.Name -cnotmatch 'MD5')
        } | Select-Object -First 1 | ForEach-Object -Process {
            (New-Object $_).ComputeHash([String]::Empty) | ForEach-Object -Process {
                '{0:x2}' -f $_
            }
        }
    ) -join ''

    $testFile = 'test.pfx'

    $invalidPath = 'TestDrive:'
    $validPath = "TestDrive:\$testFile"

    $cerFileWithSan = "
            -----BEGIN CERTIFICATE-----
            MIIGJDCCBAygAwIBAgITewAAAAqQ+bxgiZZPtgAAAAAACjANBgkqhkiG9w0BAQsF
            ADBDMRMwEQYKCZImiZPyLGQBGRYDY29tMRcwFQYKCZImiZPyLGQBGRYHY29udG9z
            bzETMBEGA1UEAwwKTGFiUm9vdENBMTAeFw0xNzA1MDkxNTM5NTJaFw0xOTA1MDkx
            NTM5NTJaMBYxFDASBgNVBAMMC3NvbWVtYWNoaW5lMIIBIjANBgkqhkiG9w0BAQEF
            AAOCAQ8AMIIBCgKCAQEA0Id9FC2vq90HPWraZnAouit8MZI/p/DeucFiCb6mieuP
            017DPCiQKuMQFQmx5VWvv82mpddxmTPtV6zfda0E5R12a11KHJ2mJrK5oR2iuI/I
            P2SJBlNAkLTsvd96zUqQcWCCE/Q2nSrK7nx3oBq4Dd5+wLfUvAMKR45RXK58J4z5
            h3mLxF+ryKnQzQHKXDC4x92hMIPJVwvPym8C3067Ry6kLHhFOk5IoJjiRmS6P1TT
            48aHipWeiK9G/aLgKTS4UEbUMooAPfeHQXGRfS4fIEQmaaeY0wqQAVYGau2oDn6m
            31SiNEA+NmAmHZFvM2kXf63L58lJASFqRnXquVCw9QIDAQABo4ICPDCCAjgwIQYJ
            KwYBBAGCNxQCBBQeEgBXAGUAYgBTAGUAcgB2AGUAcjATBgNVHSUEDDAKBggrBgEF
            BQcDATAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0OBBYEFGFGkDLulJ3m1Bx3DIa1BosB
            WpOXMCgGA1UdEQQhMB+CCGZpcnN0c2FugglzZWNvbmRzYW6CCHRoaXJkc2FuMB8G
            A1UdIwQYMBaAFN75yc566Q03FdJ4ZQ/6Kn8dohYVMIHEBgNVHR8Egbwwgbkwgbag
            gbOggbCGga1sZGFwOi8vL0NOPUxhYlJvb3RDQTEsQ049Q0ExLENOPUNEUCxDTj1Q
            dWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0
            aW9uLERDPWNvbnRvc28sREM9Y29tP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/
            YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBvAYIKwYBBQUH
            AQEEga8wgawwgakGCCsGAQUFBzAChoGcbGRhcDovLy9DTj1MYWJSb290Q0ExLENO
            PUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1D
            b25maWd1cmF0aW9uLERDPWNvbnRvc28sREM9Y29tP2NBQ2VydGlmaWNhdGU/YmFz
            ZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MA0GCSqGSIb3DQEB
            CwUAA4ICAQBUkvBdMgZsUHDEaVyBuHzALExcEflkvCq1AmJ1U2nixnfcqc5Wb3df
            W+gauW+YbOA9EfQrwPqMXvo0dhsjLn3H5tTWe0VVT5H8pgsdcXS/5cYDjoC6N3pd
            NZGCDN/oHAm8BgcNPPYyG8VDMxR+atp8Iv12nCDGQlpPkANK+nUHR8Nu66l/wDqF
            G8ftnQ7C3mSu4/baAFOAx91rXDbrs1ewrqfcBWxRQn4CZbZs9LMg+NQjrAM8WtQX
            DZd96IMY6m8DeVbIQQiHytpjpQr8aJs6s5Cd5XzRWPXb4lDMOe/4KwpyQAHjtFPY
            mYhUfaInXtna/li9MKLK+j641FnBJv6bjWhw1Jp++wHdjef+1RTtG1hslHQXsH48
            +n+jHZ5A5DKgOYUJWq3NhYvQwtQmDlBNe5aJbTmAFz7qpsPFWjoOqX8RXCE3Mt+R
            EhwMvEGNZHdsgMVXeJsqVssG2FfM7cqcslaUL/vULRWJ6LmJerjmSBRXcEHL6uTe
            IJPSLdUdPx7uvm+P4qpuIuzZ2bdHXqiFbL6yPyWi8lTaApzT/K7Y0Q3oRWYOuThK
            P2l4M+F7l346gaIDDZOXdrSsrPghSgkS4Xp3QtE6NnKq+V0pX2YHnns+JO97hEXt
            2EvKX3TnKnUPPrsl/CffTBpJEsD7xugu6OAn4KnEzzVTNYqzDbYx6g==
            -----END CERTIFICATE-----
            "

    $cerFileWithoutSan = "
            -----BEGIN CERTIFICATE-----
            MIIDBjCCAe6gAwIBAgIQRQyErZRGrolI5DfZCJDaTTANBgkqhkiG9w0BAQsFADAW
            MRQwEgYDVQQDDAtTb21lU2VydmVyMjAeFw0xNzA1MDkxNjI0MTZaFw0xODA1MDkx
            NjQ0MTZaMBYxFDASBgNVBAMMC1NvbWVTZXJ2ZXIyMIIBIjANBgkqhkiG9w0BAQEF
            AAOCAQ8AMIIBCgKCAQEA2x7gR/yQYSiqszd0+e3ZMX2b/mK3XwwEHhoXARoC/Jv/
            rmOmESB6AYabIheGmDv2qUESx6r8KtO4afunVEyoxeThQ8LffgduSo0YIUVgqyg9
            o+HUOaV4MX5cGutgov62MCs+HO2AYcl2QvmbJ9CF/nyGOigoLNOX1pLPHHM1vIFQ
            euBCX8KGK02kgl629QVckiUKrn5bCjboxx7JvSsb2UTcCDjR7x1FcGkxwj069koq
            VdtmwzC3ibYSxQ2UQo1rShol8FPTMkpf8NIZmApY3RGddnAl+r0fznbqqdwzRPjp
            1zXuNwYiG/cL/OOt50TQqCKA7CrD9m8Y3yWKK1ilOQIDAQABo1AwTjAOBgNVHQ8B
            Af8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMB0GA1UdDgQW
            BBSfthQiQydgIs0dXquThRhnkj78HTANBgkqhkiG9w0BAQsFAAOCAQEAuaACrNbE
            clIxVjSsJA4kT7z+ajTD7EmT3iX+h1sOABTuiSjR+fBCF/7AgViK24+xdLzuptCH
            MnoLW7epdP1tRXjs0vb5xwXRsTruwlIzCbvkH8/xkrc6YGw5LzdvxtFPYV+vSsx3
            uUmNlrD7ElllzRVzyGBd2VBm8hCAI0297Ls9zJlWDPYTMpedleO2D9vZBAxg3iY7
            yiMbficleMbVEE3LTNjK6iYuENZ4KOBkOJU936+lqfcVnOFTvWhLJKxTEMZ7XW4k
            pP3LiEhYnnxMfm7OyNHL+MnQhq8OV7tY3pZofPdImEeG13qcV8EBYhefFgsSxQRe
            JqptPVHBXySjMg==
            -----END CERTIFICATE-----
            "

    $cerFileWithAltTemplateName = "
            -----BEGIN CERTIFICATE-----
            MIIDVjCCAj6gAwIBAgIQIA9TO/nfla5FrjJZIiI6nzANBgkqhkiG9w0BAQsFADAW
            MRQwEgYDVQQDDAtzb21lbWFjaGluZTAeFw0xOTAyMTUxNjI3NDVaFw0yMDAyMTUx
            NjQ3NDVaMBYxFDASBgNVBAMMC3NvbWVtYWNoaW5lMIIBIjANBgkqhkiG9w0BAQEF
            AAOCAQ8AMIIBCgKCAQEAuwr0qT/ekYvp4RIHfEqsZyabdWUIR842P/1+t2b0W5bn
            LqxER+mUuBOrbdNcekjQjTnq5rYy1WsIwjeuJ7zgmVINvL8KeYna750M5ngAZsqO
            QoRR9xbQAeht2H1Q9vj/GHbakOKUW45It/0EvZLmF/FJ2+WdIGQMuqQVdr4N+w0f
            DPIVjDCjRLT5USZOHWJGrKYDSaWSf5tEQAp/6RW3JnFkE2biWsYQ3FGZtVgRxjLS
            4+602xnLTyjakQiXBosE0AuW36jiFPeW3WVVF1pdinPpIbtzE0CkoeEwPMfWNJaA
            BfIVmkEKL8HeQGk4kSEvZ/zfNbPr7RfY3S925SeR5QIDAQABo4GfMIGcMA4GA1Ud
            DwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwKAYDVR0R
            BCEwH4IIZmlyc3RzYW6CCXNlY29uZHNhboIIdGhpcmRzYW4wIgYJKwYBBAGCNxQC
            BBUeEgBXAGUAYgBTAGUAcgB2AGUAcgAwHQYDVR0OBBYEFNzXV7OE2NNKgKeLPTbT
            +YBIcPJXMA0GCSqGSIb3DQEBCwUAA4IBAQBigwVwGdmE/RekuKY++7oxIrnWkQ0L
            VN+ps5pVLM3+P1XaHdtRUVAHErBuRaqZMTHc4REzSE6PNozrznQJknEnMc6d4y4+
            IZ5pfPl8eyuPs6nBAP5aA3KhC9lW72csjXqe+EJNHfCP0k3AOkBb1A6Cja36h8Ef
            lJiPqE2bRualoz6iqcHftilLCF+8s7q1sW12730PK1BD+gqQo0o8N0fZrXhWU4/I
            0nuuz7F7VEaNcpZD7leBPCiNdsyDkLIfkb2cj4R39Fbs0yuuG6Bv1jQ+adXXprCG
            ZMCE85eAK5et3yur0hVcUHppM6oDPOyoCYnUhDthiO3rwnfRCr/1f3IB
            -----END CERTIFICATE-----
            "

    $cerFileWithAltTemplateInformation = "
            -----BEGIN CERTIFICATE-----
            MIIDazCCAlOgAwIBAgIQJx7ZH+jq5YZLy436X4Li3TANBgkqhkiG9w0BAQsFADAW
            MRQwEgYDVQQDDAtzb21lbWFjaGluZTAeFw0xODA4MDcwOTEwNDVaFw0xOTA4MDcw
            OTMwNDVaMBYxFDASBgNVBAMMC3NvbWVtYWNoaW5lMIIBIjANBgkqhkiG9w0BAQEF
            AAOCAQ8AMIIBCgKCAQEA98nll0sk4LiGTJcbZ+jIY86ongKRNE6CH+LZ0gp4mzUY
            FRufTwmWqqoTjg6Q/Ri+CvofX1CbeaHCSdvI76/vIzF0ij+Y3wGg4Ot8YljbTjsF
            aig3hGaWp+/Q345+O+sTlppwipcmdlp8vS8PNWx+FRbPFyPYSNTHbdFQXGjlz7Lu
            s1gFe9VGbBqditYhvYPJeHjUSBWVDve2vd+E9ECRKssxn3UME74yuRSzEq30ly44
            LPZYRYd8maypJERcMAkRz19bXZ1BNYp1kesxoi0KK7LLodSSzPG01Pls/K51KhZA
            6NuFe14kA+jsAnstWQ2lIofUZxHrQ4IfykmgmP3NmQIDAQABo4G0MIGxMA4GA1Ud
            DwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwKAYDVR0R
            BCEwH4IIZmlyc3RzYW6CCXNlY29uZHNhboIIdGhpcmRzYW4wNwYJKwYBBAGCNxUH
            BCowKAYgKwYBBAGCNxUIgt3/eIL6kR6HjYUJhpmDKIHSoVI+ARACAWQCAQUwHQYD
            VR0OBBYEFNt1uNJH8KG4/X0Gzh4rnAPR5lBfMA0GCSqGSIb3DQEBCwUAA4IBAQBI
            MyZvohjsm1wbxJvowp5QrKXvGs8XVl+97zY79h8QqtcZALtIHkZd8rj2Bvkd+qyU
            o01rPj7+LS7HzkdqfmDRUxbAnDclOkUTCMskzxon9CzEsizomFyTq4khWh/p+7fE
            mR2Rq/kA95aupS4Dm7HcncHn89nw9BKcP7WLgIzjRC3ZBzplEGCCL7aKDv66+dv/
            HM2uI47A8kHCFMvaq6O0bjlJfmXvrX8OgVQlRDItiuM+pu9LMkWc0t8U4ekRRQdj
            kVIXdpdvNQmud6JHv3OI0HrjtL7Da1dK7Q8qye3qHBzHwva6SMVbMmFC3ACxukBU
            v+M0WvuaEOEmAQoYaY6K
            -----END CERTIFICATE-----
            "

    $cerBytes = [System.Text.Encoding]::ASCII.GetBytes($cerFileWithSan)
    $cerBytesWithoutSan = [System.Text.Encoding]::ASCII.GetBytes($cerFileWithoutSan)
    $cerBytesWithAltTemplateName = [System.Text.Encoding]::ASCII.GetBytes($cerFileWithAltTemplateName)
    $cerBytesWithAltTemplateInformation = [System.Text.Encoding]::ASCII.GetBytes($cerFileWithAltTemplateInformation)

    $testCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cerBytes)
    $testCertificateWithoutSan = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cerBytesWithoutSan)
    $testCertificateWithAltTemplateName = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cerBytesWithAltTemplateName)
    $testCertificateWithAltTemplateInformation = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cerBytesWithAltTemplateInformation)

    Describe 'CertificateDsc.Common\Test-CertificatePath' {
        $null | Set-Content -Path $validPath

        Context 'a single existing file by parameter' {
            $result = Test-CertificatePath -Path $validPath
            It 'Should return true' {
                ($result -is [bool]) | Should -Be $true
                $result | Should -Be $true
            }
        }

        Context 'a single missing file by parameter' {
            It 'Should throw an exception' {
                # directories are not valid
                { Test-CertificatePath -Path $invalidPath } | Should -Throw
            }
        }

        Context 'a single missing file by parameter with -Quiet' {
            $result = Test-CertificatePath -Path $invalidPath -Quiet
            It 'Should return false' {
                ($result -is [bool]) | Should -Be $true
                $result | Should -Be $false
            }
        }

        Context 'a single existing file by pipeline' {
            $result = $validPath | Test-CertificatePath
            It 'Should return true' {
                ($result -is [bool]) | Should -Be $true
                $result | Should -Be $true
            }
        }

        Context 'a single missing file by pipeline' {
            It 'Should throw an exception' {
                # directories are not valid
                { $invalidPath | Test-CertificatePath } | Should -Throw
            }
        }

        Context 'a single missing file by pipeline with -Quiet' {
            $result = $invalidPath | Test-CertificatePath -Quiet
            It 'Should return false' {
                ($result -is [bool]) | Should -Be $true
                $result | Should -Be $false
            }
        }
    }

    Describe 'CertificateDsc.Common\Test-Thumbprint' {
        Context 'When FIPS not set' {
            Context 'When a single valid thumbrpint by parameter is passed' {
                $result = Test-Thumbprint -Thumbprint $validThumbprint
                It 'Should return true' {
                    $result | Should -BeOfType [System.Boolean]
                    $result | Should -Be $true
                }
            }

            Context 'When a single invalid thumbprint by parameter is passed' {
                It 'Should throw an exception' {
                    { Test-Thumbprint -Thumbprint $invalidThumbprint } | Should -Throw
                }
            }

            Context 'When a single invalid thumbprint by parameter with -Quiet is passed' {
                $result = Test-Thumbprint $invalidThumbprint -Quiet
                It 'Should return false' {
                    $result | Should -BeOfType [System.Boolean]
                    $result | Should -Be $false
                }
            }

            Context 'When a single valid thumbprint by pipeline is passed' {
                $result = $validThumbprint | Test-Thumbprint
                It 'Should return true' {
                    $result | Should -BeOfType [System.Boolean]
                    $result | Should -Be $true
                }
            }

            Context 'When a single invalid thumbprint by pipeline is passed' {
                It 'Should throw an exception' {
                    { $invalidThumbprint | Test-Thumbprint } | Should -Throw
                }
            }

            Context 'When a single invalid thumbprint by pipeline with -Quiet is passed' {
                $result = $invalidThumbprint | Test-Thumbprint -Quiet
                It 'Should return false' {
                    $result | Should -BeOfType [System.Boolean]
                    $result | Should -Be $false
                }
            }
        }

        Context 'When FIPS is enabled' {
            Mock -CommandName Get-ItemProperty -MockWith { @{ Enabled = 1 } }

            Context 'When a single valid FIPS thumbrpint by parameter is passed' {
                $result = Test-Thumbprint -Thumbprint $validFipsThumbprint
                It 'Should return true' {
                    $result | Should -BeOfType [System.Boolean]
                    $result | Should -Be $true
                }
            }

            Context 'When a single invalid FIPS thumbprint by parameter is passed' {
                It 'Should throw an exception' {
                    { Test-Thumbprint -Thumbprint $validThumbprint } | Should -Throw
                }
            }

            Context 'When a single invalid FIPS thumbprint by parameter with -Quiet is passed' {
                $result = Test-Thumbprint $validThumbprint -Quiet
                It 'Should return false' {
                    $result | Should -BeOfType [System.Boolean]
                    $result | Should -Be $false
                }
            }

            Context 'When a single valid FIPS thumbprint by pipeline is passed' {
                $result = $validFipsThumbprint | Test-Thumbprint
                It 'Should return true' {
                    $result | Should -BeOfType [System.Boolean]
                    $result | Should -Be $true
                }
            }

            Context 'When a single invalid FIPS thumbprint by pipeline is passed' {
                It 'Should throw an exception' {
                    { $validThumbprint | Test-Thumbprint } | Should -Throw
                }
            }

            Context 'When a single invalid FIPS thumbprint by pipeline with -Quiet is passed' {
                $result = $validThumbprint | Test-Thumbprint -Quiet
                It 'Should return false' {
                    $result | Should -BeOfType [System.Boolean]
                    $result | Should -Be $false
                }
            }
        }
    }

    Describe 'CertificateDsc.Common\Find-Certificate' {
        # Download and dot source the New-SelfSignedCertificateEx script
        . (Install-NewSelfSignedCertificateExScript)

        # Generate the Valid certificate for testing but remove it from the store straight away
        $certDNSNames = @('www.fabrikam.com', 'www.contoso.com')
        $certDNSNamesReverse = @('www.contoso.com', 'www.fabrikam.com')
        $certDNSNamesNoMatch = $certDNSNames + @('www.nothere.com')
        $certKeyUsage = @('DigitalSignature', 'DataEncipherment')
        $certKeyUsageReverse = @('DataEncipherment', 'DigitalSignature')
        $certKeyUsageNoMatch = $certKeyUsage + @('KeyEncipherment')
        $certEKU = @('Server Authentication', 'Client authentication')
        $certEKUReverse = @('Client authentication', 'Server Authentication')
        $certEKUNoMatch = $certEKU + @('Encrypting File System')
        $certSubject = 'CN=contoso, DC=com'
        $certFriendlyName = 'Contoso Test Cert'
        $validCert = New-SelfSignedCertificateEx `
            -Subject $certSubject `
            -KeyUsage $certKeyUsage `
            -KeySpec 'Exchange' `
            -EKU $certEKU `
            -SubjectAlternativeName $certDNSNames `
            -FriendlyName $certFriendlyName `
            -StoreLocation 'CurrentUser' `
            -Exportable
        # Pull the generated certificate from the store so we have the friendlyname
        $validThumbprint = $validCert.Thumbprint
        $validCert = Get-Item -Path "cert:\CurrentUser\My\$validThumbprint"
        Remove-Item -Path $validCert.PSPath -Force

        # Generate the Expired certificate for testing but remove it from the store straight away
        $expiredCert = New-SelfSignedCertificateEx `
            -Subject $certSubject `
            -KeyUsage $certKeyUsage `
            -KeySpec 'Exchange' `
            -EKU $certEKU `
            -SubjectAlternativeName $certDNSNames `
            -FriendlyName $certFriendlyName `
            -NotBefore ((Get-Date) - (New-TimeSpan -Days 2)) `
            -NotAfter ((Get-Date) - (New-TimeSpan -Days 1)) `
            -StoreLocation 'CurrentUser' `
            -Exportable
        # Pull the generated certificate from the store so we have the friendlyname
        $expiredThumbprint = $expiredCert.Thumbprint
        $expiredCert = Get-Item -Path "cert:\CurrentUser\My\$expiredThumbprint"
        Remove-Item -Path $expiredCert.PSPath -Force

        $nocertThumbprint = '1111111111111111111111111111111111111111'

        # Dynamic mock content for Get-ChildItem
        $mockGetChildItem = {
            switch ( $Path )
            {
                'cert:\LocalMachine\My'
                {
                    return @( $validCert )
                }

                'cert:\LocalMachine\NoCert'
                {
                    return @()
                }

                'cert:\LocalMachine\TwoCerts'
                {
                    return @( $expiredCert, $validCert )
                }

                'cert:\LocalMachine\Expired'
                {
                    return @( $expiredCert )
                }

                default
                {
                    throw 'mock called with unexpected value {0}' -f $Path
                }
            }
        }

        BeforeEach {
            Mock `
                -CommandName Test-Path `
                -MockWith { $true }

            Mock `
                -CommandName Get-ChildItem `
                -MockWith $mockGetChildItem
        }

        Context 'Thumbprint only is passed and matching certificate exists' {
            It 'Should not throw exception' {
                { $script:result = Find-Certificate -Thumbprint $validThumbprint } | Should -Not -Throw
            }

            It 'Should return expected certificate' {
                $script:result.Thumbprint | Should -Be $validThumbprint
            }

            It 'Should call expected mocks' {
                Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
            }
        }

        Context 'Thumbprint only is passed and matching certificate does not exist' {
            It 'Should not throw exception' {
                { $script:result = Find-Certificate -Thumbprint $nocertThumbprint } | Should -Not -Throw
            }

            It 'Should return null' {
                $script:result | Should -BeNullOrEmpty
            }

            It 'Should call expected mocks' {
                Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
            }
        }

        Context 'FriendlyName only is passed and matching certificate exists' {
            It 'Should not throw exception' {
                { $script:result = Find-Certificate -FriendlyName $certFriendlyName } | Should -Not -Throw
            }

            It 'Should return expected certificate' {
                $script:result.Thumbprint | Should -Be $validThumbprint
            }

            It 'Should call expected mocks' {
                Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
            }
        }

        Context 'FriendlyName only is passed and matching certificate does not exist' {
            It 'Should not throw exception' {
                { $script:result = Find-Certificate -FriendlyName 'Does Not Exist' } | Should -Not -Throw
            }

            It 'Should return null' {
                $script:result | Should -BeNullOrEmpty
            }

            It 'Should call expected mocks' {
                Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
            }
        }

        Context 'Subject only is passed and matching certificate exists' {
            It 'Should not throw exception' {
                { $script:result = Find-Certificate -Subject $certSubject } | Should -Not -Throw
            }

            It 'Should return expected certificate' {
                $script:result.Thumbprint | Should -Be $validThumbprint
            }

            It 'Should call expected mocks' {
                Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
            }
        }

        Context 'Subject only is passed and matching certificate does not exist' {
            It 'Should not throw exception' {
                { $script:result = Find-Certificate -Subject 'CN=Does Not Exist' } | Should -Not -Throw
            }

            It 'Should return null' {
                $script:result | Should -BeNullOrEmpty
            }

            It 'Should call expected mocks' {
                Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
            }
        }

        Context 'Issuer only is passed and matching certificate exists' {
            It 'Should not throw exception' {
                { $script:result = Find-Certificate -Issuer $certSubject } | Should -Not -Throw
            }

            It 'Should return expected certificate' {
                $script:result.Thumbprint | Should -Be $validThumbprint
            }

            It 'Should call expected mocks' {
                Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
            }
        }

        Context 'Issuer only is passed and matching certificate does not exist' {
            It 'Should not throw exception' {
                { $script:result = Find-Certificate -Issuer 'CN=Does Not Exist' } | Should -Not -Throw
            }

            It 'Should return null' {
                $script:result | Should -BeNullOrEmpty
            }

            It 'Should call expected mocks' {
                Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
            }
        }

        Context 'DNSName only is passed and matching certificate exists' {
            It 'Should not throw exception' {
                { $script:result = Find-Certificate -DnsName $certDNSNames } | Should -Not -Throw
            }

            It 'Should return expected certificate' {
                $script:result.Thumbprint | Should -Be $validThumbprint
            }

            It 'Should call expected mocks' {
                Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
            }
        }

        Context 'DNSName only is passed in reversed order and matching certificate exists' {
            It 'Should not throw exception' {
                { $script:result = Find-Certificate -DnsName $certDNSNamesReverse } | Should -Not -Throw
            }

            It 'Should return expected certificate' {
                $script:result.Thumbprint | Should -Be $validThumbprint
            }

            It 'Should call expected mocks' {
                Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
            }
        }

        Context 'DNSName only is passed with only one matching DNS name and matching certificate exists' {
            It 'Should not throw exception' {
                { $script:result = Find-Certificate -DnsName $certDNSNames[0] } | Should -Not -Throw
            }

            It 'Should return expected certificate' {
                $script:result.Thumbprint | Should -Be $validThumbprint
            }

            It 'Should call expected mocks' {
                Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
            }
        }

        Context 'DNSName only is passed but an entry is missing and matching certificate does not exist' {
            It 'Should not throw exception' {
                { $script:result = Find-Certificate -DnsName $certDNSNamesNoMatch } | Should -Not -Throw
            }

            It 'Should return null' {
                $script:result | Should -BeNullOrEmpty
            }

            It 'Should call expected mocks' {
                Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
            }
        }

        Context 'KeyUsage only is passed and matching certificate exists' {
            It 'Should not throw exception' {
                { $script:result = Find-Certificate -KeyUsage $certKeyUsage } | Should -Not -Throw
            }

            It 'Should return expected certificate' {
                $script:result.Thumbprint | Should -Be $validThumbprint
            }

            It 'Should call expected mocks' {
                Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
            }
        }

        Context 'KeyUsage only is passed in reversed order and matching certificate exists' {
            It 'Should not throw exception' {
                { $script:result = Find-Certificate -KeyUsage $certKeyUsageReverse } | Should -Not -Throw
            }

            It 'Should return expected certificate' {
                $script:result.Thumbprint | Should -Be $validThumbprint
            }

            It 'Should call expected mocks' {
                Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
            }
        }

        Context 'KeyUsage only is passed with only one matching DNS name and matching certificate exists' {
            It 'Should not throw exception' {
                { $script:result = Find-Certificate -KeyUsage $certKeyUsage[0] } | Should -Not -Throw
            }

            It 'Should return expected certificate' {
                $script:result.Thumbprint | Should -Be $validThumbprint
            }

            It 'Should call expected mocks' {
                Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
            }
        }

        Context 'KeyUsage only is passed but an entry is missing and matching certificate does not exist' {
            It 'Should not throw exception' {
                { $script:result = Find-Certificate -KeyUsage $certKeyUsageNoMatch } | Should -Not -Throw
            }

            It 'Should return null' {
                $script:result | Should -BeNullOrEmpty
            }

            It 'Should call expected mocks' {
                Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
            }
        }

        Context 'EnhancedKeyUsage only is passed and matching certificate exists' {
            It 'Should not throw exception' {
                { $script:result = Find-Certificate -EnhancedKeyUsage $certEKU } | Should -Not -Throw
            }

            It 'Should return expected certificate' {
                $script:result.Thumbprint | Should -Be $validThumbprint
            }

            It 'Should call expected mocks' {
                Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
            }
        }

        Context 'EnhancedKeyUsage only is passed in reversed order and matching certificate exists' {
            It 'Should not throw exception' {
                { $script:result = Find-Certificate -EnhancedKeyUsage $certEKUReverse } | Should -Not -Throw
            }

            It 'Should return expected certificate' {
                $script:result.Thumbprint | Should -Be $validThumbprint
            }

            It 'Should call expected mocks' {
                Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
            }
        }

        Context 'EnhancedKeyUsage only is passed with only one matching DNS name and matching certificate exists' {
            It 'Should not throw exception' {
                { $script:result = Find-Certificate -EnhancedKeyUsage $certEKU[0] } | Should -Not -Throw
            }

            It 'Should return expected certificate' {
                $script:result.Thumbprint | Should -Be $validThumbprint
            }

            It 'Should call expected mocks' {
                Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
            }
        }

        Context 'EnhancedKeyUsage only is passed but an entry is missing and matching certificate does not exist' {
            It 'Should not throw exception' {
                { $script:result = Find-Certificate -EnhancedKeyUsage $certEKUNoMatch } | Should -Not -Throw
            }

            It 'Should return null' {
                $script:result | Should -BeNullOrEmpty
            }

            It 'Should call expected mocks' {
                Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
            }
        }

        Context 'Thumbprint only is passed and matching certificate does not exist in the store' {
            It 'Should not throw exception' {
                { $script:result = Find-Certificate -Thumbprint $validThumbprint -Store 'NoCert' } | Should -Not -Throw
            }

            It 'Should return null' {
                $script:result | Should -BeNullOrEmpty
            }

            It 'Should call expected mocks' {
                Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
            }
        }

        Context 'FriendlyName only is passed and both valid and expired certificates exist' {
            It 'Should not throw exception' {
                { $script:result = Find-Certificate -FriendlyName $certFriendlyName -Store 'TwoCerts' } | Should -Not -Throw
            }

            It 'Should return expected certificate' {
                $script:result.Thumbprint | Should -Be $validThumbprint
            }

            It 'Should call expected mocks' {
                Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
            }
        }

        Context 'FriendlyName only is passed and only expired certificates exist' {
            It 'Should not throw exception' {
                { $script:result = Find-Certificate -FriendlyName $certFriendlyName -Store 'Expired' } | Should -Not -Throw
            }

            It 'Should return expected certificate' {
                $script:result | Should -BeNullOrEmpty
            }

            It 'Should call expected mocks' {
                Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
            }
        }

        Context 'FriendlyName only is passed and only expired certificates exist but allowexpired passed' {
            It 'Should not throw exception' {
                { $script:result = Find-Certificate -FriendlyName $certFriendlyName -Store 'Expired' -AllowExpired:$true } | Should -Not -Throw
            }

            It 'Should return expected certificate' {
                $script:result.Thumbprint | Should -Be $expiredThumbprint
            }

            It 'Should call expected mocks' {
                Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
            }
        }
    }

    Describe 'CertificateDsc.Common\Find-CertificateAuthority' {
        Context 'Function is executed with domain connectivity' {
            Mock `
                -CommandName Get-CdpContainer `
                -MockWith {
                [CmdletBinding()]
                param
                (
                    $DomainName
                )
                return New-Object -TypeName psobject -Property @{
                    Children = @(
                        @{
                            distinguishedName = 'CN=CA1,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                            Children          = @{
                                distinguishedName = 'CN=LabRootCA1,CN=CA1,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                            }
                        }
                    )
                }
            }

            Mock `
                -CommandName Test-CertificateAuthority `
                -ParameterFilter { $CARootName -eq 'LabRootCA1' -and $CAServerFQDN -eq 'CA1' } `
                -MockWith { return $true }

            It 'Should not throw exception' {
                $script:result = Find-CertificateAuthority -DomainName contoso.com -Verbose
            }

            It 'Should return the expected CA' {
                $script:result.CARootName | Should -Be 'LabRootCA1'
                $script:result.CAServerFQDN | Should -Be 'CA1'
            }

            It 'Should call expected mocks' {
                Assert-MockCalled -CommandName Get-CdpContainer -Exactly -Times 1
                Assert-MockCalled -CommandName Test-CertificateAuthority -Exactly -Times 1
            }
        }

        Context 'Function is executed with domain connectivity but CA is uncontactable' {
            Mock `
                -CommandName Get-CdpContainer `
                -MockWith {
                [CmdletBinding()]
                param
                (
                    $DomainName
                )
                return New-Object -TypeName psobject -Property @{
                    Children = @(
                        @{
                            distinguishedName = 'CN=CA1,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                            Children          = @{
                                distinguishedName = 'CN=LabRootCA1,CN=CA1,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                            }
                        }
                    )
                }
            }

            Mock `
                -CommandName Test-CertificateAuthority `
                -ParameterFilter { $CARootName -eq 'LabRootCA1' -and $CAServerFQDN -eq 'CA1' } `
                -MockWith { return $false }

            $errorRecord = Get-InvalidOperationRecord `
                -Message ($LocalizedData.NoCaFoundError)

            It 'Should throw NoCaFoundError exception' {
                { Find-CertificateAuthority -DomainName contoso.com -Verbose } | Should -Throw $errorRecord
            }

            It 'Should call expected mocks' {
                Assert-MockCalled -CommandName Get-CdpContainer -Exactly -Times 1
                Assert-MockCalled -CommandName Test-CertificateAuthority -Exactly -Times 1
            }
        }

        Context 'Function is executed without domain connectivity' {
            Mock `
                -CommandName Get-CdpContainer `
                -MockWith {
                [CmdletBinding()]
                param
                (
                    $DomainName
                )
                New-InvalidOperationException `
                    -Message ($LocalizedData.DomainNotJoinedError)
            }

            Mock `
                -CommandName Test-CertificateAuthority `
                -ParameterFilter { $CARootName -eq 'LabRootCA1' -and $CAServerFQDN -eq 'CA1' } `
                -MockWith { return $false }

            $errorRecord = Get-InvalidOperationRecord `
                -Message ($LocalizedData.DomainNotJoinedError)

            It 'Should throw DomainNotJoinedError exception' {
                { Find-CertificateAuthority -DomainName 'somewhere.overtherainbow' -Verbose } | Should -Throw $errorRecord
            }

            It 'Should call expected mocks' {
                Assert-MockCalled -CommandName Get-CdpContainer -Exactly -Times 1
                Assert-MockCalled -CommandName Test-CertificateAuthority -Exactly -Times 0
            }
        }
    }

    Describe 'CertificateDsc.Common\Test-CertificateAuthority' {
        Mock `
            -CommandName New-Object `
            -ParameterFilter { $TypeName -eq 'System.Diagnostics.ProcessStartInfo' } `
            -MockWith {
            $retObj = New-Object -TypeName psobject -Property @{
                FileName               = ''
                Arguments              = ''
                RedirectStandardError  = $false
                RedirectStandardOutput = $true
                UseShellExecute        = $false
                CreateNoWindow         = $true
            }

            return $retObj
        }

        Context 'Function is executed with CA online' {
            Mock `
                -CommandName New-Object `
                -ParameterFilter { $TypeName -eq 'System.Diagnostics.Process' } `
                -MockWith {
                $retObj = New-Object -TypeName psobject -Property @{
                    StartInfo      = $null
                    ExitCode       = 0
                    StandardOutput = New-Object -TypeName psobject |
                    Add-Member -MemberType ScriptMethod -Name ReadToEnd -Value {
                        return @"
Connecting to LabRootCA1\CA1 ...
Server "CA1" ICertRequest2 interface is alive (32ms)
CertUtil: -ping command completed successfully.
"@
                    } -PassThru
                }

                $retObj |
                Add-Member -MemberType ScriptMethod -Name Start -Value { } -PassThru |
                Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { }

                return $retObj
            }

            It 'Should not throw exception' {
                $script:result = Test-CertificateAuthority `
                    -CARootName 'LabRootCA1' `
                    -CAServerFQDN 'CA1' `
                    -Verbose
            }

            It 'Should return true' {
                $script:result | Should -Be $True
            }

            It 'Should call expected mocks' {
                Assert-MockCalled `
                    -CommandName New-Object `
                    -ParameterFilter { $TypeName -eq 'System.Diagnostics.ProcessStartInfo' } `
                    -Exactly -Times 1

                Assert-MockCalled `
                    -CommandName New-Object `
                    -ParameterFilter { $TypeName -eq 'System.Diagnostics.Process' } `
                    -Exactly -Times 1
            }
        }

        Context 'Function is executed with CA offline' {
            Mock `
                -CommandName New-Object `
                -ParameterFilter { $TypeName -eq 'System.Diagnostics.Process' } `
                -MockWith {
                $retObj = New-Object -TypeName psobject -Property @{
                    StartInfo      = $null
                    ExitCode       = -2147024809
                    StandardOutput = New-Object -TypeName psobject |
                    Add-Member -MemberType ScriptMethod -Name ReadToEnd -Value {
                        return @"
Connecting to LabRootCA1\CA2 ...
Server could not be reached: The parameter is incorrect. 0x80070057 (WIN32: 87 ERROR_INVALID_PARAMETER) -- (31ms)

CertUtil: -ping command FAILED: 0x80070057 (WIN32: 87 ERROR_INVALID_PARAMETER)
CertUtil: The parameter is incorrect.
"@
                    } -PassThru
                }

                $retObj |
                Add-Member -MemberType ScriptMethod -Name Start -Value { } -PassThru |
                Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { }

                return $retObj
            }

            It 'Should not throw exception' {
                $script:result = Test-CertificateAuthority `
                    -CARootName 'LabRootCA1' `
                    -CAServerFQDN 'CA2' `
                    -Verbose
            }

            It 'Should return false' {
                $script:result | Should -Be $false
            }

            It 'Should call expected mocks' {
                Assert-MockCalled `
                    -CommandName New-Object `
                    -ParameterFilter { $TypeName -eq 'System.Diagnostics.ProcessStartInfo' } `
                    -Exactly -Times 1

                Assert-MockCalled `
                    -CommandName New-Object `
                    -ParameterFilter { $TypeName -eq 'System.Diagnostics.Process' } `
                    -Exactly -Times 1
            }
        }
    }

    Describe 'CertificateDsc.Common\Get-CertificateTemplateName' {
        Mock -CommandName Get-CertificateTemplatesFromActiveDirectory -MockWith {
            @(
                [PSCustomObject] @{
                    'Name'                    = 'WebServer'
                    'DisplayName'             = 'Web Server'
                    'mspki-cert-template-oid' = '1.3.6.1.4.1.311.21.8.5734392.6195358.14893705.12992936.3444946.62.1.16'
                }
            )
        }

        Context 'When a certificate with the extension "Certificate Template Name" is used' {
            It 'Should return the template name' {
                Get-CertificateTemplateName -Certificate $testCertificate | Should -Be 'WebServer'
            }
        }

        Context 'When a certificate with the extension "Certificate Template Information" is used.' {
            It 'Should return the template name when there is no display name' {
                Get-CertificateTemplateName -Certificate $testCertificateWithAltTemplateInformation | Should -Be 'WebServer'
            }

            Mock -CommandName Get-CertificateTemplateExtensionText -MockWith {
                @'
Template=Web Server(1.3.6.1.4.1.311.21.8.5734392.6195358.14893705.12992936.3444946.62.1.16)
Major Version Number=100
Minor Version Number=5
'@
            }

            It 'Should return the template name when there is a display name' {
                Get-CertificateTemplateName -Certificate $testCertificateWithAltTemplateInformation | Should -Be 'WebServer'
            }
        }

        Context 'When a certificate with no template name is used' {
            It 'Should return null' {
                Get-CertificateTemplateName -Certificate $testCertificateWithoutSan | Should -BeNullOrEmpty
            }
        }
    }

    Describe 'CertificateDsc.Common\Get-CertificateTemplatesFromActiveDirectory' {
        $MockSearchResults = @(
            @{
                Properties = @(
                    @{
                        Name  = 'name'
                        Value = 'MockData1'
                    }
                    @{
                        Name  = 'displayName'
                        Value = 'Mock Data 1'
                    }
                )
            }
            @{
                Properties = @(
                    @{
                        Name  = 'name'
                        Value = 'MockData2'
                    }
                    @{
                        Name  = 'displayName'
                        Value = 'Mock Data 2'
                    }
                )
            }
            @{
                Properties = @(
                    @{
                        Name  = 'name'
                        Value = 'MockData3'
                    }
                    @{
                        Name  = 'displayName'
                        Value = 'Mock Data 3'
                    }
                )
            }
        )

        $newObject_parameterFilter = {
            $TypeName -eq 'DirectoryServices.DirectorySearcher'
        }

        $newObject_mock = {
            [PSCustomObject] @{
                Filter     = $null
                SearchRoot = $null
            } | Add-Member -MemberType ScriptMethod -Name FindAll -Value {
                $MockSearchResults
            } -PassThru
        }

        Mock -CommandName New-Object -ParameterFilter $newObject_parameterFilter -MockWith $newObject_mock
        Mock -CommandName Get-DirectoryEntry

        Context 'When certificate templates are retrieved from Active Directory successfully' {
            It 'Should get 3 mocked search results' {
                $SearchResults = Get-CertificateTemplatesFromActiveDirectory

                Assert-MockCalled -CommandName Get-DirectoryEntry -Exactly -Times 1
                Assert-MockCalled -CommandName New-Object         -Exactly -Times 1

                $SearchResults.Count | Should -Be 3
            }
        }

        Context 'When certificate templates are not retrieved from Active Directory successfully' {
            Mock -CommandName Get-DirectoryEntry -MockWith {
                throw 'Mock Function Failure'
            }

            It 'Should display a warning message' {
                $Message = 'Failed to get the certificate templates from Active Directory.'

                (Get-CertificateTemplatesFromActiveDirectory -Verbose 3>&1).Message | Should -Be $Message
            }

            It 'Should display a verbose message' {
                $Message = 'Mock Function Failure'

                (Get-CertificateTemplatesFromActiveDirectory -Verbose 4>&1).Message | Should -Be $Message
            }
        }
    }

    Describe 'CertificateDsc.Common\Get-CertificateTemplateInformation' {
        $mockADTemplates = @(
            @{
                'Name'                    = 'DisplayName1'
                'DisplayName'             = 'Display Name 1'
                'msPKI-Cert-Template-OID' = '1.3.6.1.4.1.311.21.8.5734392.6195358.14893705.12992936.3444946.62.3384218.1234567'
            }
            @{
                'Name'                    = 'DisplayName2'
                'DisplayName'             = 'Display Name 2'
                'msPKI-Cert-Template-OID' = '1.3.6.1.4.1.311.21.8.5734392.6195358.14893705.12992936.3444946.62.3384218.2345678'
            }
        )

        $certificateTemplateExtensionFormattedText1 = @'
Template=Display Name 1(1.3.6.1.4.1.311.21.8.5734392.6195358.14893705.12992936.3444946.62.3384218.1234567)
Major Version Number=100
Minor Version Number=5
'@

        $certificateTemplateExtensionFormattedText1NoDisplayName = @'
Template=1.3.6.1.4.1.311.21.8.5734392.6195358.14893705.12992936.3444946.62.3384218.1234567
Major Version Number=100
Minor Version Number=5
'@

        $certificateTemplateExtensionFormattedText2 = @'
Template=Display Name 2(1.3.6.1.4.1.311.21.8.5734392.6195358.14893705.12992936.3444946.62.3384218.2345678)
Major Version Number=100
Minor Version Number=5
'@

        $certificateTemplateExtensionFormattedText2NoDisplayName = @'
Template=1.3.6.1.4.1.311.21.8.5734392.6195358.14893705.12992936.3444946.62.3384218.2345678
Major Version Number=100
Minor Version Number=5
'@

        $certificateTemplateExtensionFormattedText3 = @'
Template=Display Name 3(1.3.6.1.4.1.311.21.8.5734392.6195358.14893705.12992936.3444946.62.3384218.3456789)
Major Version Number=100
Minor Version Number=5
'@

        $certificateTemplateExtensionFormattedText3NoDisplayName = @'
Template=1.3.6.1.4.1.311.21.8.5734392.6195358.14893705.12992936.3444946.62.3384218.3456789
Major Version Number=100
Minor Version Number=5
'@

        $RegexTemplatePattern = '^\w+=(?<Name>.*)\((?<Oid>[\.\d]+)\)'

        Mock -CommandName Get-CertificateTemplatesFromActiveDirectory -MockWith { $mockADTemplates }

        Context 'When FormattedTemplate contains a Template OID with a Template Display Name' {

            It 'Should return the Template Name "DisplayName1"' {
                $params = @{
                    FormattedTemplate = $certificateTemplateExtensionFormattedText1
                }

                (Get-CertificateTemplateInformation @params).Name | Should -Be 'DisplayName1'
            }
            It 'Should return the Template Name "DisplayName2"' {
                $params = @{
                    FormattedTemplate = $certificateTemplateExtensionFormattedText2
                }

                (Get-CertificateTemplateInformation @params).Name | Should -Be 'DisplayName2'
            }
            It 'Should write a warning when there is no match in Active Directory' {
                $templateValues = [Regex]::Match($certificateTemplateExtensionFormattedText3, $RegexTemplatePattern)

                $templateText = '{0}({1})' -f $templateValues.Groups['Name'].Value, $templateValues.Groups['Oid'].Value

                $warningMessage = $localizedData.TemplateNameResolutionError -f $templateText

                $params = @{
                    FormattedTemplate = $certificateTemplateExtensionFormattedText3
                }

                (Get-CertificateTemplateInformation @params 3>&1)[0].Message | Should -Be $warningMessage
            }
        }

        Context 'When FormattedTemplate contains a Template OID without a Template Display Name' {
            It 'Should return the Template Name "DisplayName1"' {
                $params = @{
                    FormattedTemplate = $certificateTemplateExtensionFormattedText1NoDisplayName
                }

                (Get-CertificateTemplateInformation @params).Name | Should -Be 'DisplayName1'
            }
            It 'Should return the Template Name "DisplayName2"' {
                $params = @{
                    FormattedTemplate = $certificateTemplateExtensionFormattedText2NoDisplayName
                }

                (Get-CertificateTemplateInformation @params).Name | Should -Be 'DisplayName2'
            }
            It 'Should write a warning when there is no match in Active Directory' {
                $templateValues = [Regex]::Match($certificateTemplateExtensionFormattedText3, $RegexTemplatePattern)

                $templateText = '{0}({1})' -f $templateValues.Groups['Name'].Value, $templateValues.Groups['Oid'].Value

                $warningMessage = $localizedData.TemplateNameResolutionError -f $templateText

                $params = @{
                    FormattedTemplate = $certificateTemplateExtensionFormattedText3
                }

                (Get-CertificateTemplateInformation @params 3>&1)[0].Message | Should -Be $warningMessage
            }
        }

        Context 'When FormattedTemplate contains a the Template Name' {
            It 'Should return the FormattedText' {
                $templateName = 'TemplateName'

                (Get-CertificateTemplateInformation -FormattedTemplate $templateName).Name | Should -Be $templateName
            }
            It 'Should return the FormattedText Without a Trailing Carriage Return' {
                $templateName = 'TemplateName' + [Char]13

                (Get-CertificateTemplateInformation -FormattedTemplate $templateName).Name | Should -Be $templateName.TrimEnd([Char]13)
            }
        }

        Context 'When FormattedTemplate does not contain a recognised format' {
            It 'Should write a warning when there is no match in Active Directory' {
                $formattedTemplate = 'Unrecognized Format'

                $warningMessage = $localizedData.TemplateNameNotFound -f $formattedTemplate

                (Get-CertificateTemplateInformation -FormattedTemplate $formattedTemplate 3>&1)[0].Message | Should -Be $warningMessage
            }
        }
    }

    Describe 'CertificateDsc.Common\Get-CertificateExtension' {
        Context 'When a certificate contains an extension that matches the Oid parameter and First is not specified' {
            It 'Should return the extension with Oid ''2.5.29.17''' {
                $extension = Get-CertificateExtension -Certificate $testCertificate -Oid '2.5.29.17'
                $extension | Should -BeOfType [System.Security.Cryptography.X509Certificates.X509Extension]
                $extension | Should -HaveCount 1
                $extension.Oid.Value | Should -Be '2.5.29.17'
            }
        }

        Context 'When a certificate does not contain an extension that matches the Oid parameter and First is not specified' {
            It 'Should return no extension' {
                $extension = Get-CertificateExtension -Certificate $testCertificate -Oid '2.9.9.9'
                $extension | Should -BeNullOrEmpty
            }
        }

        Context 'When a certificate does not contain an extension that matches the Oid parameter and First is set to 2' {
            It 'Should return no extension' {
                $extension = Get-CertificateExtension -Certificate $testCertificate -Oid '2.9.9.9' -First 2
                $extension | Should -BeNullOrEmpty
            }
        }

        Context 'When a certificate contains an extension that matches only one of the Oid parameter values and First is not specified' {
            It 'Should return the extension with Oid ''2.5.29.17''' {
                $extension = Get-CertificateExtension -Certificate $testCertificate -Oid '2.5.29.17', '2.9.9.9'
                $extension | Should -BeOfType [System.Security.Cryptography.X509Certificates.X509Extension]
                $extension | Should -HaveCount 1
                $extension.Oid.Value | Should -Be '2.5.29.17'
            }
        }

        Context 'When a certificate contains an extension that matches both of the Oid parameter values and First is not specified' {
            It 'Should return the extension with Oid ''2.5.29.17''' {
                $extension = Get-CertificateExtension -Certificate $testCertificate -Oid '2.5.29.17', '2.5.29.31'
                $extension | Should -BeOfType [System.Security.Cryptography.X509Certificates.X509Extension]
                $extension | Should -HaveCount 1
                $extension.Oid.Value | Should -Contain '2.5.29.17'
            }
        }

        Context 'When a certificate contains an extension that matches both of the Oid parameter values but First is set to 2' {
            It 'Should return the extension with Oid ''2.5.29.17'' and ''2.5.29.31''' {
                $extension = Get-CertificateExtension -Certificate $testCertificate -Oid '2.5.29.17', '2.5.29.31' -First 2
                $extension | Should -BeOfType [System.Security.Cryptography.X509Certificates.X509Extension]
                $extension | Should -HaveCount 2
                $extension.Oid.Value | Should -Contain '2.5.29.17'
                $extension.Oid.Value | Should -Contain '2.5.29.31'
            }
        }

        Context 'When a certificate contains an extension that matches both of the Oid parameter values but First is set to 3' {
            It 'Should return the extension with Oid ''2.5.29.17'' and ''2.5.29.31''' {
                $extension = Get-CertificateExtension -Certificate $testCertificate -Oid '2.5.29.17', '2.5.29.31' -First 3
                $extension | Should -BeOfType [System.Security.Cryptography.X509Certificates.X509Extension]
                $extension | Should -HaveCount 2
                $extension.Oid.Value | Should -Contain '2.5.29.17'
                $extension.Oid.Value | Should -Contain '2.5.29.31'
            }
        }
    }

    Describe 'CertificateDsc.Common\Get-CertificateTemplateExtensionText' {
        Context 'When a certificate contains Certificate Template Name extension' {
            It 'Should return the Name of the Certificate Template' {
                $params = @{
                    Certificate = $testCertificateWithAltTemplateName
                }

                # Template Names have a trailing carriage return and linefeed.
                Get-CertificateTemplateExtensionText @params | Should -Be ('WebServer' + [Char]13 + [Char]10)
            }
        }

        Context 'When a certificate contains Certificate Template Information extension' {
            It 'Should return the Oid, Major and Minor Version of the Certificate Template' {
                $CertificateTemplateInformation = @'
Template=1.3.6.1.4.1.311.21.8.5734392.6195358.14893705.12992936.3444946.62.1.16
Major Version Number=100
Minor Version Number=5

'@

                $params = @{
                    Certificate = $testCertificateWithAltTemplateInformation
                }

                # Template Names have a trailing carriage return and linefeed.
                Get-CertificateTemplateExtensionText @params | Should -Be $CertificateTemplateInformation
            }
        }

        Context 'When a certificate does not contain a Certificate Template extension' {
            It 'Should not return anything' {
                $params = @{
                    Certificate = $testCertificateWithoutSan
                }

                # Template Names have a trailing carriage return and linefeed.
                Get-CertificateTemplateExtensionText @params | Should -Be $null
            }
        }
    }

    Describe 'CertificateDsc.Common\Get-CertificateSubjectAlternativeName' {
        Context 'When a certificate with a SAN is used' {
            It 'Should return the SAN' {
                Get-CertificateSubjectAlternativeName -Certificate $testCertificate | Should -Be 'firstsan'
            }
        }

        Context 'When a certificate without SAN is used' {
            It 'Should return null' {
                Get-CertificateSubjectAlternativeName -Certificate $testCertificateWithoutSan | Should -BeNullOrEmpty
            }
        }
    }

    Describe 'CertificateDsc.Common\Get-CertificateSubjectAlternativeNameList' {
        Context 'When a certificate with a Subject Alternative Name is used' {
            It 'Should return the list of Subject Alternative Name entries' {
                $global:certificate = $testCertificate
                $result = Get-CertificateSubjectAlternativeNameList -Certificate $testCertificate
                $result | Should -HaveCount 3
                $result | Should -Contain 'DNS Name=firstsan'
                $result | Should -Contain 'DNS Name=secondsan'
                $result | Should -Contain 'DNS Name=thirdsan'
            }
        }

        Context 'When a certificate without Subject Alternative Name is used' {
            It 'Should return null' {
                $result = Get-CertificateSubjectAlternativeNameList -Certificate $testCertificateWithoutSan
                $result | Should -BeNullOrEmpty
            }
        }
    }

    Describe 'CertificateDsc.Common\Test-CommandExists' {
        $testCommandName = 'TestCommandName'

        Mock -CommandName 'Get-Command' -MockWith { return $Name }

        Context 'When Get-Command returns' {
            It 'Should not throw exception' {
                { $null = Test-CommandExists -Name $testCommandName } | Should -Not -Throw
            }

            It 'Should retrieve the command with the specified name' {
                $getCommandParameterFilter = {
                    return $Name -eq $testCommandName
                }

                Assert-MockCalled -CommandName 'Get-Command' -ParameterFilter $getCommandParameterFilter -Exactly -Times 1 -Scope 'Context'
            }

            It 'Should return true' {
                Test-CommandExists -Name $testCommandName | Should -Be $true
            }
        }

        Context 'When Get-Command returns null' {
            Mock -CommandName 'Get-Command' -MockWith { return $null }

            It 'Should not throw exception' {
                { $null = Test-CommandExists -Name $testCommandName } | Should -Not -Throw
            }

            It 'Should retrieve the command with the specified name' {
                $getCommandParameterFilter = {
                    return $Name -eq $testCommandName
                }

                Assert-MockCalled -CommandName 'Get-Command' -ParameterFilter $getCommandParameterFilter -Exactly -Times 1 -Scope 'Context'
            }

            It 'Should return false' {
                Test-CommandExists -Name $testCommandName | Should -Be $false
            }
        }
    }

    Describe 'CertificateDsc.Common\Get-CertificateStorePath' {
        Context 'When called with a Store and Location that exists' {
            Mock -CommandName Test-Path -MockWith { $true }

            It 'Should not throw exception' {
                {
                    $script:getCertificateStorePathResult = Get-CertificateStorePath `
                        -Location 'LocalMachine' `
                        -Store 'TestStore'
                } | Should -Not -Throw
            }

            It 'Should return the expected path' {
                $script:getCertificateStorePathResult = 'Cert:\LocalMachine\TestStore'
            }
        }

        Context 'When called with a Store and Location that does not exist' {
            Mock -CommandName Test-Path -MockWith { $false }

            It 'Should throw expected exception' {
                {
                    Get-CertificateStorePath `
                        -Location 'LocalMachine' `
                        -Store 'TestStore'
                } | Should -Throw ($script:localizedData.CertificateStoreNotFoundError -f 'Cert:\LocalMachine\TestStore')
            }
        }
    }

    Describe 'CertificateDsc.Common\Get-CertificatePath' {
        Context 'When called with Thumbprint, Store and Location' {
            Mock -CommandName Test-Path -MockWith { $true }

            It 'Should not throw exception' {
                {
                    $script:getCertificatePathResult = Get-CertificatePath `
                        -Thumbprint '627b268587e95099e72aab831a81f887d7a20578' `
                        -Location 'LocalMachine' `
                        -Store 'TestStore'
                } | Should -Not -Throw
            }

            It 'Should return the expected path' {
                $script:getCertificateStorePathResult = 'Cert:\LocalMachine\TestStore\627b268587e95099e72aab831a81f887d7a2057'
            }
        }
    }

    Describe 'CertificateDsc.Common\Get-CertificateFromCertificateStore' {
        Context 'When the certificate exists in the store' {
            Mock -CommandName Test-Path -MockWith { $true }
            Mock -CommandName Get-ChildItem -MockWith {
                @(
                    [PSCustomObject] @{
                        PSPath = 'Microsoft.PowerShell.Security\Certificate::LocalMachine\TestStore\627b268587e95099e72aab831a81f887d7a20578'
                    }
                )
            }

            It 'Should not throw exception' {
                {
                    $script:getCertificateFromCertificateStoreResult = Get-CertificateFromCertificateStore `
                        -Thumbprint '627b268587e95099e72aab831a81f887d7a20578' `
                        -Location 'LocalMachine' `
                        -Store 'TestStore' `
                        -Verbose
                } | Should -Not -Throw
            }

            It 'Should return the expected certificate' {
                $script:getCertificateFromCertificateStoreResult.PSPath | Should -Be 'Microsoft.PowerShell.Security\Certificate::LocalMachine\TestStore\627b268587e95099e72aab831a81f887d7a20578'
            }

            It 'Should call expected mocks' {
                Assert-MockCalled -CommandName Get-ChildItem -ParameterFilter {
                    $Path -eq 'Cert:\LocalMachine\TestStore\627b268587e95099e72aab831a81f887d7a20578'
                } -Exactly -Times 1
            }
        }

        Context 'When the certificate does not exist in the store' {
            Mock -CommandName Test-Path -MockWith { $true }
            Mock -CommandName Get-ChildItem

            It 'Should not throw exception' {
                {
                    $script:getCertificateFromCertificateStoreResult = Get-CertificateFromCertificateStore `
                        -Thumbprint '627b268587e95099e72aab831a81f887d7a20578' `
                        -Location 'LocalMachine' `
                        -Store 'TestStore' `
                        -Verbose
                } | Should -Not -Throw
            }

            It 'Should not return any certificates' {
                $script:getCertificateFromCertificateStoreResult.PSPath | Should -BeNullOrEmpty
            }

            It 'Should call expected mocks' {
                Assert-MockCalled -CommandName Get-ChildItem -ParameterFilter {
                    $Path -eq 'Cert:\LocalMachine\TestStore\627b268587e95099e72aab831a81f887d7a20578'
                } -Exactly -Times 1
            }
        }
    }

    Describe 'CertificateDsc.Common\Remove-CertificateFromCertificateStore' {
        Context 'When the certificate exists in the store' {
            Mock -CommandName Test-Path -MockWith { $true }
            Mock -CommandName Get-ChildItem -MockWith {
                @(
                    [PSCustomObject] @{
                        PSPath = 'Microsoft.PowerShell.Security\Certificate::LocalMachine\TestStore\627b268587e95099e72aab831a81f887d7a20578'
                    }
                )
            }
            Mock -CommandName Remove-Item

            It 'Should not throw exception' {
                {
                    Remove-CertificateFromCertificateStore `
                        -Thumbprint '627b268587e95099e72aab831a81f887d7a20578' `
                        -Location 'LocalMachine' `
                        -Store 'TestStore' `
                        -Verbose
                } | Should -Not -Throw
            }

            It 'Should call expected mocks' {
                Assert-MockCalled -CommandName Get-ChildItem -ParameterFilter {
                    $Path -eq 'Cert:\LocalMachine\TestStore\627b268587e95099e72aab831a81f887d7a20578'
                } -Exactly -Times 1

                Assert-MockCalled -CommandName Remove-Item -ParameterFilter {
                    $Path -eq 'Microsoft.PowerShell.Security\Certificate::LocalMachine\TestStore\627b268587e95099e72aab831a81f887d7a20578' `
                    -and $Force -eq $true
                } -Exactly -Times 1
            }
        }

        Context 'When the certificate exists in the store twice' {
            Mock -CommandName Test-Path -MockWith { $true }
            Mock -CommandName Get-ChildItem -MockWith {
                @(
                    [PSCustomObject] @{
                        PSPath = 'Microsoft.PowerShell.Security\Certificate::LocalMachine\TestStore\627b268587e95099e72aab831a81f887d7a20578'
                    },
                    [PSCustomObject] @{
                        PSPath = 'Microsoft.PowerShell.Security\Certificate::LocalMachine\TestStore\627b268587e95099e72aab831a81f887d7a20578'
                    }
                )
            }
            Mock -CommandName Remove-Item

            It 'Should not throw exception' {
                {
                    Remove-CertificateFromCertificateStore `
                        -Thumbprint '627b268587e95099e72aab831a81f887d7a20578' `
                        -Location 'LocalMachine' `
                        -Store 'TestStore' `
                        -Verbose
                } | Should -Not -Throw
            }

            It 'Should call expected mocks' {
                Assert-MockCalled -CommandName Get-ChildItem -ParameterFilter {
                    $Path -eq 'Cert:\LocalMachine\TestStore\627b268587e95099e72aab831a81f887d7a20578'
                } -Exactly -Times 1

                Assert-MockCalled -CommandName Remove-Item -ParameterFilter {
                    $Path -eq 'Microsoft.PowerShell.Security\Certificate::LocalMachine\TestStore\627b268587e95099e72aab831a81f887d7a20578' `
                    -and $Force -eq $true
                } -Exactly -Times 2
            }
        }

        Context 'When the certificate does not exist in the store' {
            Mock -CommandName Test-Path -MockWith { $true }
            Mock -CommandName Get-ChildItem
            Mock -CommandName Remove-Item

            It 'Should not throw exception' {
                {
                    Remove-CertificateFromCertificateStore `
                        -Thumbprint '627b268587e95099e72aab831a81f887d7a20578' `
                        -Location 'LocalMachine' `
                        -Store 'TestStore' `
                        -Verbose
                } | Should -Not -Throw
            }

            It 'Should call expected mocks' {
                Assert-MockCalled -CommandName Get-ChildItem -ParameterFilter {
                    $Path -eq 'Cert:\LocalMachine\TestStore\627b268587e95099e72aab831a81f887d7a20578'
                } -Exactly -Times 1

                Assert-MockCalled -CommandName Remove-Item -Exactly -Times 0
            }
        }
    }

    Describe 'CertificateDsc.Common\Set-CertificateFriendlyNameInCertificateStore' {
        Context 'When the certificate exists in the store' {
            Mock -CommandName Test-Path -MockWith { $true }
            Mock -CommandName Get-ChildItem -MockWith {
                @(
                    [PSCustomObject] @{
                        PSPath = 'Microsoft.PowerShell.Security\Certificate::LocalMachine\TestStore\627b268587e95099e72aab831a81f887d7a20578'
                        FriendlyName = 'Nothing'
                    }
                )
            }

            It 'Should not throw exception' {
                {
                    Set-CertificateFriendlyNameInCertificateStore `
                        -Thumbprint '627b268587e95099e72aab831a81f887d7a20578' `
                        -Location 'LocalMachine' `
                        -Store 'TestStore' `
                        -FriendlyName 'New Name' `
                        -Verbose
                } | Should -Not -Throw
            }

            It 'Should call expected mocks' {
                Assert-MockCalled -CommandName Get-ChildItem -ParameterFilter {
                    $Path -eq 'Cert:\LocalMachine\TestStore\627b268587e95099e72aab831a81f887d7a20578'
                } -Exactly -Times 1
            }
        }

        Context 'When the certificate does not exist in the store' {
            Mock -CommandName Test-Path -MockWith { $true }
            Mock -CommandName Get-ChildItem

            It 'Should not throw exception' {
                {
                    Set-CertificateFriendlyNameInCertificateStore `
                        -Thumbprint '627b268587e95099e72aab831a81f887d7a20578' `
                        -Location 'LocalMachine' `
                        -Store 'TestStore' `
                        -FriendlyName 'New Name' `
                        -Verbose
                } | Should -Not -Throw
            }

            It 'Should call expected mocks' {
                Assert-MockCalled -CommandName Get-ChildItem -ParameterFilter {
                    $Path -eq 'Cert:\LocalMachine\TestStore\627b268587e95099e72aab831a81f887d7a20578'
                } -Exactly -Times 1
            }
        }
    }
}
