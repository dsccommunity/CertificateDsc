#region HEADER
$script:dscModuleName = 'CertificateDsc'
$script:dscResourceName = 'MSFT_CertificateExport'

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
        $certificatePath = Join-Path -Path $env:Temp -ChildPath 'CertificateExportTestCert.cer'
        $pfxPath = Join-Path -Path $env:Temp -ChildPath 'CertificateExportTestCert.pfx'
        $certificateDNSNames = @('www.fabrikam.com', 'www.contoso.com')
        $certificateKeyUsage = @('DigitalSignature', 'DataEncipherment')
        $certificateEKU = @('Server Authentication', 'Client authentication')
        $certificateSubject = 'CN=contoso, DC=com'
        $certificateFriendlyName = 'Contoso Test Cert'
        $certificateThumbprint = '1111111111111111111111111111111111111111'
        $certificateNotFoundThumbprint = '2222222222222222222222222222222222222222'
        $certificateStore = 'My'

        $validCertificate = New-Object -TypeName PSObject -Property @{
            Thumbprint        = $certificateThumbprint
            Subject           = "CN=$certificateSubject"
            Issuer            = "CN=$certificateSubject"
            FriendlyName      = $certificateFriendlyName
            DnsNameList       = @(
                @{ Unicode = $certificateDNSNames[0] }
                @{ Unicode = $certificateDNSNames[1] }
            )
            Extensions        = @(
                @{ EnhancedKeyUsages = ($certificateKeyUsage -join ', ') }
            )
            EnhancedKeyUsages = @(
                @{ FriendlyName = $certificateEKU[0] }
                @{ FriendlyName = $certificateEKU[1] }
            )
            NotBefore         = (Get-Date).AddDays(-30) # Issued on
            NotAfter          = (Get-Date).AddDays(31) # Expires after
        }

        $validCertificateParameters = @{
            Path             = $certificatePath
            Thumbprint       = $certificateThumbprint
            FriendlyName     = $certificateFriendlyName
            Subject          = $certificateSubject
            DNSName          = $certificateDNSNames
            Issuer           = $certificateSubject
            KeyUsage         = $certificateKeyUsage
            EnhancedKeyUsage = $certificateEKU
            Store            = $certificateStore
            AllowExpired     = $false
            MatchSource      = $false
            Type             = 'Cert'
        }

        $validCertificateNotFoundParameters = @{ } + $validCertificateParameters
        $validCertificateNotFoundParameters.Thumbprint = $certificateNotFoundThumbprint

        $validCertificateMatchSourceParameters = @{ } + $validCertificateParameters
        $validCertificateMatchSourceParameters.MatchSource = $true

        $pfxPlainTextPassword = 'P@ssword!1'
        $pfxPassword = ConvertTo-SecureString -String $pfxPlainTextPassword -AsPlainText -Force
        $pfxCredential = New-Object -TypeName System.Management.Automation.PSCredential `
            -ArgumentList ('Dummy', $pfxPassword)

        $validPfxParameters = @{
            Path             = $PfxPath
            Thumbprint       = $certificateThumbprint
            FriendlyName     = $certificateFriendlyName
            Subject          = $certificateSubject
            DNSName          = $certificateDNSNames
            Issuer           = $certificateSubject
            KeyUsage         = $certificateKeyUsage
            EnhancedKeyUsage = $certificateEKU
            Store            = $certificateStore
            AllowExpired     = $false
            MatchSource      = $false
            Password         = $pfxCredential
            ProtectTo        = 'Administrators'
            Type             = 'PFX'
        }

        $validPfxMatchSourceParameters = @{ } + $validPfxParameters
        $validPfxMatchSourceParameters.MatchSource = $true

        # This is so we can mock the Import method in Set-TargetResource
        class X509Certificate2CollectionDummyMatch:System.Object
        {
            [String] $Thumbprint = '1111111111111111111111111111111111111111'
            X509Certificate2CollectionDummyMatch()
            {
            }
            Import($Path)
            {
            }
            Import($Path, $Password, $Flags)
            {
            }
        }

        class X509Certificate2CollectionDummyNoMatch:System.Object
        {
            [String] $Thumbprint = '2222222222222222222222222222222222222222'
            X509Certificate2CollectionDummyNoMatch()
            {
            }
            Import($Path)
            {
            }
            Import($Path, $Password, $Flags)
            {
            }
        }

        $importedCertificateMatch = New-Object -Type X509Certificate2CollectionDummyMatch
        $importedCertificateNoMatch = New-Object -Type X509Certificate2CollectionDummyNoMatch

        # MockWith content for Export-Certificate
        $mockExportCertificate = {
            if ($FilePath -ne $certificatePath)
            {
                throw 'Expected mock to be called with {0}, but was {1}' -f $certificatePath, $FilePath
            }
        }

        # MockWith content for Export-PfxCertificate
        $mockExportPfxCertificate = {
            if ($FilePath -ne $pfxPath)
            {
                throw 'Expected mock to be called with {0}, but was {1}' -f $pfxPath, $FilePath
            }
        }

        # MockWith content for Find-Certifciate
        $mockFindCertificate = {
            if ($Thumbprint -eq $certificateThumbprint)
            {
                $validCertificate
            }
        }

        Describe 'MSFT_CertificateExport\Get-TargetResource' -Tag 'Get' {
            Context 'Certificate has been exported' {
                Mock `
                    -CommandName Test-Path `
                    -MockWith { $true } `
                    -ParameterFilter { $Path -eq $certificatePath }

                It 'should return IsExported true' {
                    $Result = Get-TargetResource -Path $certificatePath -Verbose
                    $Result.IsExported | Should -Be $true
                }

                It 'should call the expected mocks' {
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                }
            }

            Context 'Certificate has not been exported' {
                Mock `
                    -CommandName Test-Path `
                    -MockWith { $false } `
                    -ParameterFilter { $Path -eq $certificatePath }

                It 'should return IsExported false' {
                    $Result = Get-TargetResource -Path $certificatePath -Verbose
                    $Result.IsExported | Should -Be $false
                }

                It 'should call the expected mocks' {
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                }
            }
        }

        Describe 'MSFT_CertificateExport\Set-TargetResource' -Tag 'Set' {
            BeforeEach {
                Mock `
                    -CommandName Find-Certificate `
                    -MockWith $mockFindCertificate
            }

            Context 'Certificate is not found' {
                Mock `
                    -CommandName Export-Certificate

                Mock `
                    -CommandName Export-PfxCertificate

                It 'should not throw exception' {
                    { Set-TargetResource @validCertificateNotFoundParameters -Verbose } | Should -Not -Throw
                }

                It 'should call the expected mocks' {
                    Assert-MockCalled -CommandName Find-Certificate -Exactly -Times 1
                    Assert-MockCalled -CommandName Export-Certificate -Exactly -Times 0
                    Assert-MockCalled -CommandName Export-PfxCertificate -Exactly -Times 0
                }
            }

            Context 'Certificate is found and needs to be exported as Cert' {
                # Needs to be done because real Export-Certificate $cert parameter requires an actual [X509Certificate2] object
                function Export-Certificate
                {
                    [CmdletBinding()]
                    param
                    (
                        $FilePath,
                        $Cert,
                        $Force,
                        $Type
                    )
                }

                Mock `
                    -CommandName Export-Certificate `
                    -MockWith $mockExportCertificate

                Mock `
                    -CommandName Export-PfxCertificate

                It 'should not throw exception' {
                    { Set-TargetResource @validCertificateParameters -Verbose } | Should -Not -Throw
                }

                It 'should call the expected mocks' {
                    Assert-MockCalled -CommandName Find-Certificate -Exactly -Times 1
                    Assert-MockCalled -CommandName Export-Certificate -Exactly -Times 1
                    Assert-MockCalled -CommandName Export-PfxCertificate -Exactly -Times 0
                }
            }

            Context 'Certificate is found and needs to be exported as PFX' {
                # Needs to be done because real Export-PfxCertificate $cert parameter requires an actual [X509Certificate2] object
                function Export-PfxCertificate
                {
                    [CmdletBinding()]
                    param
                    (
                        $FilePath,
                        $Cert,
                        $Force,
                        $Type,
                        $Password,
                        $ChainOption,
                        $ProtectTo
                    )
                }

                Mock `
                    -CommandName Export-Certificate

                Mock `
                    -CommandName Export-PfxCertificate `
                    -MockWith $mockExportPfxCertificate

                It 'should not throw exception' {
                    { Set-TargetResource @validPfxParameters -Verbose } | Should -Not -Throw
                }

                It 'should call the expected mocks' {
                    Assert-MockCalled -CommandName Find-Certificate -Exactly -Times 1
                    Assert-MockCalled -CommandName Export-Certificate -Exactly -Times 0
                    Assert-MockCalled -CommandName Export-PfxCertificate -Exactly -Times 1
                }
            }
        }

        Describe 'MSFT_CertificateExport\Test-TargetResource' -Tag 'Test' {
            BeforeEach {
                Mock `
                    -CommandName Find-Certificate `
                    -MockWith $mockFindCertificate
            }

            Context 'Certificate is not found' {
                Mock `
                    -CommandName Test-Path

                Mock `
                    -CommandName New-Object

                It 'should return true' {
                    Test-TargetResource @validCertificateNotFoundParameters -Verbose | Should -Be $true
                }

                It 'should call the expected mocks' {
                    Assert-MockCalled -CommandName Find-Certificate -Exactly -Times 1
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 0
                    Assert-MockCalled -CommandName New-Object -Exactly -Times 0
                }
            }

            Context 'Certificate is found and needs to be exported as Cert and has not been exported' {
                Mock `
                    -CommandName Test-Path `
                    -MockWith { $false }

                Mock `
                    -CommandName New-Object

                It 'should return false' {
                    Test-TargetResource @validCertificateParameters -Verbose | Should -Be $false
                }

                It 'should call the expected mocks' {
                    Assert-MockCalled -CommandName Find-Certificate -Exactly -Times 1
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                    Assert-MockCalled -CommandName New-Object -Exactly -Times 0
                }
            }

            Context 'Certificate is found and needs to be exported as Cert but already exported and MatchSource False' {
                Mock `
                    -CommandName Test-Path `
                    -MockWith { $true }

                Mock `
                    -CommandName New-Object

                It 'should return true' {
                    Test-TargetResource @validCertificateParameters -Verbose | Should -Be $true
                }

                It 'should call the expected mocks' {
                    Assert-MockCalled -CommandName Find-Certificate -Exactly -Times 1
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                    Assert-MockCalled -CommandName New-Object -Exactly -Times 0
                }
            }

            Context 'Certificate is found and needs to be exported as Cert but already exported and MatchSource True and matches' {
                Mock `
                    -CommandName Test-Path `
                    -MockWith { $true }

                Mock `
                    -CommandName New-Object `
                    -MockWith { $importedCertificateMatch }

                It 'should return true' {
                    Test-TargetResource @validCertificateMatchSourceParameters -Verbose | Should -Be $true
                }

                It 'should call the expected mocks' {
                    Assert-MockCalled -CommandName Find-Certificate -Exactly -Times 1
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                    Assert-MockCalled -CommandName New-Object -Exactly -Times 1
                }
            }

            Context 'Certificate is found and needs to be exported as Cert but already exported and MatchSource True but no match' {
                Mock `
                    -CommandName Test-Path `
                    -MockWith { $true }

                Mock `
                    -CommandName New-Object `
                    -MockWith { $importedCertificateNoMatch }

                It 'should return false' {
                    Test-TargetResource @validCertificateMatchSourceParameters -Verbose | Should -Be $false
                }

                It 'should call the expected mocks' {
                    Assert-MockCalled -CommandName Find-Certificate -Exactly -Times 1
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                    Assert-MockCalled -CommandName New-Object -Exactly -Times 1
                }
            }

            Context 'Certificate is found and needs to be exported as Pfx but already exported and MatchSource True and matches' {
                Mock `
                    -CommandName Test-Path `
                    -MockWith { $true }

                Mock `
                    -CommandName New-Object `
                    -MockWith { $importedCertificateMatch }

                It 'should return true' {
                    Test-TargetResource @validPfxMatchSourceParameters -Verbose | Should -Be $true
                }

                It 'should call the expected mocks' {
                    Assert-MockCalled -CommandName Find-Certificate -Exactly -Times 1
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                    Assert-MockCalled -CommandName New-Object -Exactly -Times 1
                }
            }

            Context 'Certificate is found and needs to be exported as Pfx but already exported and MatchSource True but no match' {
                Mock `
                    -CommandName Test-Path `
                    -MockWith { $true }

                Mock `
                    -CommandName New-Object `
                    -MockWith { $importedCertificateNoMatch }

                It 'should return false' {
                    Test-TargetResource @validPfxMatchSourceParameters -Verbose | Should -Be $false
                }

                It 'should call the expected mocks' {
                    Assert-MockCalled -CommandName Find-Certificate -Exactly -Times 1
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                    Assert-MockCalled -CommandName New-Object -Exactly -Times 1
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
