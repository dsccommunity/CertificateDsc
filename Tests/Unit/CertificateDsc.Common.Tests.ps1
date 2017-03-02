$script:ModuleName = 'CertificateDsc.Common'

#region HEADER
# Unit Test Template Version: 1.1.0
[string] $script:moduleRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $Script:MyInvocation.MyCommand.Path))
if ( (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
     (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone','https://github.com/PowerShell/DscResource.Tests.git',(Join-Path -Path $script:moduleRoot -ChildPath '\DSCResource.Tests\'))
}

Import-Module -Name (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1') -Force
Import-Module -Name (Join-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath (Join-Path -Path 'Modules' -ChildPath $script:ModuleName)) -ChildPath "$script:ModuleName.psm1") -Force
Import-Module -Name (Join-Path -Path (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'TestHelpers') -ChildPath 'CommonTestHelper.psm1') -Global
#endregion HEADER

# Begin Testing
try
{
    InModuleScope $script:ModuleName {
        $DSCResourceName = 'CertificateDsc.Common'
        $invalidThumbprint = 'Zebra'
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

        $invalidPath = 'TestDrive:'
        $validPath = "TestDrive:\$testFile"

        Describe "$DSCResourceName\Test-CertificatePath" {

            $null | Set-Content -Path $validPath

            Context 'a single existing file by parameter' {
                $result = Test-CertificatePath -Path $validPath
                It 'should return true' {
                    ($result -is [bool]) | Should Be $true
                    $result | Should Be $true
                }
            }

            Context 'a single missing file by parameter' {
                It 'should throw an exception' {
                    # directories are not valid
                    { Test-CertificatePath -Path $invalidPath } | Should Throw
                }
            }

            Context 'a single missing file by parameter with -Quiet' {
                $result = Test-CertificatePath -Path $invalidPath -Quiet
                It 'should return false' {
                    ($result -is [bool]) | Should Be $true
                    $result | Should Be $false
                }
            }

            Context 'a single existing file by pipeline' {
                $result = $validPath | Test-CertificatePath
                It 'should return true' {
                    ($result -is [bool]) | Should Be $true
                    $result | Should Be $true
                }
            }

            Context 'a single missing file by pipeline' {
                It 'should throw an exception' {
                    # directories are not valid
                    { $invalidPath | Test-CertificatePath } | Should Throw
                }
            }

            Context 'a single missing file by pipeline with -Quiet' {
                $result =  $invalidPath | Test-CertificatePath -Quiet
                It 'should return false' {
                    ($result -is [bool]) | Should Be $true
                    $result | Should Be $false
                }
            }
        }

        Describe "$DSCResourceName\Test-Thumbprint" {

            Context 'a single valid thumbrpint by parameter' {
                $result = Test-Thumbprint -Thumbprint $validThumbprint
                It 'should return true' {
                    ($result -is [bool]) | Should Be $true
                    $result | Should Be $true
                }
            }

            Context 'a single invalid thumbprint by parameter' {
                It 'should throw an exception' {
                    # directories are not valid
                    { Test-Thumbprint -Thumbprint $invalidThumbprint } | Should Throw
                }
            }

            Context 'a single invalid thumbprint by parameter with -Quiet' {
                $result = Test-Thumbprint $invalidThumbprint -Quiet
                It 'should return false' {
                    ($result -is [bool]) | Should Be $true
                    $result | Should Be $false
                }
            }

            Context 'a single valid thumbprint by pipeline' {
                $result = $validThumbprint | Test-Thumbprint
                It 'should return true' {
                    ($result -is [bool]) | Should Be $true
                    $result | Should Be $true
                }
            }

            Context 'a single invalid thumborint by pipeline' {
                It 'should throw an exception' {
                    # directories are not valid
                    { $invalidThumbprint | Test-Thumbprint } | Should Throw
                }
            }

            Context 'a single invalid thumbprint by pipeline with -Quiet' {
                $result =  $invalidThumbprint | Test-Thumbprint -Quiet
                It 'should return false' {
                    ($result -is [bool]) | Should Be $true
                    $result | Should Be $false
                }
            }
        }

        Describe "$DSCResourceName\Find-Certificate" {

            # Download and dot source the New-SelfSignedCertificateEx script
            . (Install-NewSelfSignedCertificateExScript)

            # Generate the Valid certificate for testing but remove it from the store straight away
            $certDNSNames = @('www.fabrikam.com', 'www.contoso.com')
            $certDNSNamesReverse = @('www.contoso.com', 'www.fabrikam.com')
            $certDNSNamesNoMatch = $certDNSNames + @('www.nothere.com')
            $certKeyUsage = @('DigitalSignature','DataEncipherment')
            $certKeyUsageReverse = @('DataEncipherment','DigitalSignature')
            $certKeyUsageNoMatch = $certKeyUsage + @('KeyEncipherment')
            $certEKU = @('Server Authentication','Client authentication')
            $certEKUReverse = @('Client authentication','Server Authentication')
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
                It 'should not throw exception' {
                    { $script:result = Find-Certificate -Thumbprint $validThumbprint } | Should Not Throw
                }

                It 'should return expected certificate' {
                    $script:result.Thumbprint | Should Be $validThumbprint
                }

                It 'should call expected mocks' {
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
                }
            }

            Context 'Thumbprint only is passed and matching certificate does not exist' {
                It 'should not throw exception' {
                    { $script:result = Find-Certificate -Thumbprint $nocertThumbprint } | Should Not Throw
                }

                It 'should return null' {
                    $script:result | Should BeNullOrEmpty
                }

                It 'should call expected mocks' {
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
                }
            }

            Context 'FriendlyName only is passed and matching certificate exists' {
                It 'should not throw exception' {
                    { $script:result = Find-Certificate -FriendlyName $certFriendlyName } | Should Not Throw
                }

                It 'should return expected certificate' {
                    $script:result.Thumbprint | Should Be $validThumbprint
                }

                It 'should call expected mocks' {
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
                }
            }

            Context 'FriendlyName only is passed and matching certificate does not exist' {
                It 'should not throw exception' {
                    { $script:result = Find-Certificate -FriendlyName 'Does Not Exist' } | Should Not Throw
                }

                It 'should return null' {
                    $script:result | Should BeNullOrEmpty
                }

                It 'should call expected mocks' {
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
                }
            }

            Context 'Subject only is passed and matching certificate exists' {
                It 'should not throw exception' {
                    { $script:result = Find-Certificate -Subject $certSubject } | Should Not Throw
                }

                It 'should return expected certificate' {
                    $script:result.Thumbprint | Should Be $validThumbprint
                }

                It 'should call expected mocks' {
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
                }
            }

            Context 'Subject only is passed and matching certificate does not exist' {
                It 'should not throw exception' {
                    { $script:result = Find-Certificate -Subject 'CN=Does Not Exist' } | Should Not Throw
                }

                It 'should return null' {
                    $script:result | Should BeNullOrEmpty
                }

                It 'should call expected mocks' {
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
                }
            }

            Context 'Issuer only is passed and matching certificate exists' {
                It 'should not throw exception' {
                    { $script:result = Find-Certificate -Issuer $certSubject } | Should Not Throw
                }

                It 'should return expected certificate' {
                    $script:result.Thumbprint | Should Be $validThumbprint
                }

                It 'should call expected mocks' {
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
                }
            }

            Context 'Issuer only is passed and matching certificate does not exist' {
                It 'should not throw exception' {
                    { $script:result = Find-Certificate -Issuer 'CN=Does Not Exist' } | Should Not Throw
                }

                It 'should return null' {
                    $script:result | Should BeNullOrEmpty
                }

                It 'should call expected mocks' {
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
                }
            }

            Context 'DNSName only is passed and matching certificate exists' {
                It 'should not throw exception' {
                    { $script:result = Find-Certificate -DnsName $certDNSNames } | Should Not Throw
                }

                It 'should return expected certificate' {
                    $script:result.Thumbprint | Should Be $validThumbprint
                }

                It 'should call expected mocks' {
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
                }
            }

            Context 'DNSName only is passed in reversed order and matching certificate exists' {
                It 'should not throw exception' {
                    { $script:result = Find-Certificate -DnsName $certDNSNamesReverse } | Should Not Throw
                }

                It 'should return expected certificate' {
                    $script:result.Thumbprint | Should Be $validThumbprint
                }

                It 'should call expected mocks' {
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
                }
            }

            Context 'DNSName only is passed with only one matching DNS name and matching certificate exists' {
                It 'should not throw exception' {
                    { $script:result = Find-Certificate -DnsName $certDNSNames[0] } | Should Not Throw
                }

                It 'should return expected certificate' {
                    $script:result.Thumbprint | Should Be $validThumbprint
                }

                It 'should call expected mocks' {
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
                }
            }

            Context 'DNSName only is passed but an entry is missing and matching certificate does not exist' {
                It 'should not throw exception' {
                    { $script:result = Find-Certificate -DnsName $certDNSNamesNoMatch } | Should Not Throw
                }

                It 'should return null' {
                    $script:result | Should BeNullOrEmpty
                }

                It 'should call expected mocks' {
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
                }
            }

            Context 'KeyUsage only is passed and matching certificate exists' {
                It 'should not throw exception' {
                    { $script:result = Find-Certificate -KeyUsage $certKeyUsage } | Should Not Throw
                }

                It 'should return expected certificate' {
                    $script:result.Thumbprint | Should Be $validThumbprint
                }

                It 'should call expected mocks' {
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
                }
            }

            Context 'KeyUsage only is passed in reversed order and matching certificate exists' {
                It 'should not throw exception' {
                    { $script:result = Find-Certificate -KeyUsage $certKeyUsageReverse } | Should Not Throw
                }

                It 'should return expected certificate' {
                    $script:result.Thumbprint | Should Be $validThumbprint
                }

                It 'should call expected mocks' {
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
                }
            }

            Context 'KeyUsage only is passed with only one matching DNS name and matching certificate exists' {
                It 'should not throw exception' {
                    { $script:result = Find-Certificate -KeyUsage $certKeyUsage[0] } | Should Not Throw
                }

                It 'should return expected certificate' {
                    $script:result.Thumbprint | Should Be $validThumbprint
                }

                It 'should call expected mocks' {
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
                }
            }

            Context 'KeyUsage only is passed but an entry is missing and matching certificate does not exist' {
                It 'should not throw exception' {
                    { $script:result = Find-Certificate -KeyUsage $certKeyUsageNoMatch } | Should Not Throw
                }

                It 'should return null' {
                    $script:result | Should BeNullOrEmpty
                }

                It 'should call expected mocks' {
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
                }
            }

            Context 'EnhancedKeyUsage only is passed and matching certificate exists' {
                It 'should not throw exception' {
                    { $script:result = Find-Certificate -EnhancedKeyUsage $certEKU } | Should Not Throw
                }

                It 'should return expected certificate' {
                    $script:result.Thumbprint | Should Be $validThumbprint
                }

                It 'should call expected mocks' {
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
                }
            }

            Context 'EnhancedKeyUsage only is passed in reversed order and matching certificate exists' {
                It 'should not throw exception' {
                    { $script:result = Find-Certificate -EnhancedKeyUsage $certEKUReverse } | Should Not Throw
                }

                It 'should return expected certificate' {
                    $script:result.Thumbprint | Should Be $validThumbprint
                }

                It 'should call expected mocks' {
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
                }
            }

            Context 'EnhancedKeyUsage only is passed with only one matching DNS name and matching certificate exists' {
                It 'should not throw exception' {
                    { $script:result = Find-Certificate -EnhancedKeyUsage $certEKU[0] } | Should Not Throw
                }

                It 'should return expected certificate' {
                    $script:result.Thumbprint | Should Be $validThumbprint
                }

                It 'should call expected mocks' {
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
                }
            }

            Context 'EnhancedKeyUsage only is passed but an entry is missing and matching certificate does not exist' {
                It 'should not throw exception' {
                    { $script:result = Find-Certificate -EnhancedKeyUsage $certEKUNoMatch } | Should Not Throw
                }

                It 'should return null' {
                    $script:result | Should BeNullOrEmpty
                }

                It 'should call expected mocks' {
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
                }
            }

            Context 'Thumbprint only is passed and matching certificate does not exist in the store' {
                It 'should not throw exception' {
                    { $script:result = Find-Certificate -Thumbprint $validThumbprint -Store 'NoCert'} | Should Not Throw
                }

                It 'should return null' {
                    $script:result | Should BeNullOrEmpty
                }

                It 'should call expected mocks' {
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
                }
            }

            Context 'FriendlyName only is passed and both valid and expired certificates exist' {
                It 'should not throw exception' {
                    { $script:result = Find-Certificate -FriendlyName $certFriendlyName -Store 'TwoCerts' } | Should Not Throw
                }

                It 'should return expected certificate' {
                    $script:result.Thumbprint | Should Be $validThumbprint
                }

                It 'should call expected mocks' {
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
                }
            }

            Context 'FriendlyName only is passed and only expired certificates exist' {
                It 'should not throw exception' {
                    { $script:result = Find-Certificate -FriendlyName $certFriendlyName -Store 'Expired' } | Should Not Throw
                }

                It 'should return expected certificate' {
                    $script:result | Should BeNullOrEmpty
                }

                It 'should call expected mocks' {
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
                }
            }

            Context 'FriendlyName only is passed and only expired certificates exist but allowexpired passed' {
                It 'should not throw exception' {
                    { $script:result = Find-Certificate -FriendlyName $certFriendlyName -Store 'Expired' -AllowExpired:$true } | Should Not Throw
                }

                It 'should return expected certificate' {
                    $script:result.Thumbprint | Should Be $expiredThumbprint
                }

                It 'should call expected mocks' {
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-ChildItem -Exactly -Times 1
                }
            }
        }
    }
}
finally
{
    #region FOOTER
    #endregion
}
