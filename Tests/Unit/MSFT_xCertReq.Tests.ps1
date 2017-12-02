[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
param ()

$script:DSCModuleName      = 'xCertificate'
$script:DSCResourceName    = 'MSFT_xCertReq'

#region HEADER
# Integration Test Template Version: 1.1.0
[String] $script:moduleRoot = Join-Path -Path $(Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $Script:MyInvocation.MyCommand.Path))) -ChildPath 'Modules\xCertificate'
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
        $dscResourceName = $script:DSCResourceName
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
        $caServerFQDN          = 'rootca.contoso.com'
        $caRootName            = 'contoso-CA'
        $validSubject          = 'Test Subject'
        $validIssuer           = "CN=$caRootName, DC=contoso, DC=com"
        $keyLength             = '2048'
        $exportable            = $true
        $providerName          = '"Microsoft RSA SChannel Cryptographic Provider"'
        $oid                   = '1.3.6.1.5.5.7.3.1'
        $keyUsage              = '0xa0'
        $certificateTemplate   = 'WebServer'
        $subjectAltUrl         = 'contoso.com'
        $subjectAltName        = "dns=$subjectAltUrl"
        $friendlyName          = "Test Certificate"

        $validCert = New-Object -TypeName PSObject -Property @{
            Thumbprint   = $validThumbprint
            Subject      = "CN=$validSubject"
            Issuer       = $validIssuer
            NotBefore    = (Get-Date).AddDays(-30) # Issued on
            NotAfter     = (Get-Date).AddDays(31) # Expires after
            FriendlyName = $friendlyName
        }
        Add-Member -InputObject $validCert -MemberType ScriptMethod -Name Verify -Value {
            return $true
        }

        $expiringCert = New-Object -TypeName PSObject -Property @{
            Thumbprint   = $validThumbprint
            Subject      = "CN=$validSubject"
            Issuer       = $validIssuer
            NotBefore    = (Get-Date).AddDays(-30) # Issued on
            NotAfter     = (Get-Date).AddDays(30) # Expires after
            FriendlyName = $friendlyName
        }
        Add-Member -InputObject $expiringCert -MemberType ScriptMethod -Name Verify -Value {
            return $true
        }

        $expiredCert = New-Object -TypeName PSObject -Property @{
            Thumbprint   = $validThumbprint
            Subject      = "CN=$validSubject"
            Issuer       = $validIssuer
            NotBefore    = (Get-Date).AddDays(-30) # Issued on
            NotAfter     = (Get-Date).AddDays(-1) # Expires after
            FriendlyName = $friendlyName
        }
        Add-Member -InputObject $expiredCert -MemberType ScriptMethod -Name Verify -Value {
            return $true
        }

        $sanOid = New-Object -TypeName System.Security.Cryptography.Oid -Property @{FriendlyName = 'Subject Alternative Name'}
        $sanExt = @{
            oid      = $(,$sanOid)
            Critical = $false
        }
        Add-Member -InputObject $sanExt -MemberType ScriptMethod -Name Format -Force -Value {
            return "DNS Name=$subjectAltUrl"
        }
        $validSANCert = New-Object -TypeName PSObject -Property @{
            Thumbprint   = $validThumbprint
            Subject      = "CN=$validSubject"
            Issuer       = $validIssuer
            NotBefore    = (Get-Date).AddDays(-30) # Issued on
            NotAfter     = (Get-Date).AddDays(31) # Expires after
            Extensions   = $sanExt
            FriendlyName = $friendlyName
        }
        Add-Member -InputObject $validSANCert -MemberType ScriptMethod -Name Verify -Value {
            return $true
        }

        $incorrectSanExt = @{
            oid      = $(,$sanOid)
            Critical = $false
        }
        Add-Member -InputObject $incorrectSanExt -MemberType ScriptMethod -Name Format -Force -Value {
            return "DNS Name=incorrect.com"
        }
        $incorrectSANCert = New-Object -TypeName PSObject -Property @{
            Thumbprint   = $validThumbprint
            Subject      = "CN=$validSubject"
            Issuer       = $validIssuer
            NotBefore    = (Get-Date).AddDays(-30) # Issued on
            NotAfter     = (Get-Date).AddDays(31) # Expires after
            Extensions   = $incorrectSanExt
            FriendlyName = $friendlyName
        }
        Add-Member -InputObject $incorrectSANCert -MemberType ScriptMethod -Name Verify -Value {
            return $true
        }

        $emptySANCert    = New-Object -TypeName PSObject -Property @{
            Thumbprint   = $validThumbprint
            Subject      = "CN=$validSubject"
            Issuer       = $validIssuer
            NotBefore    = (Get-Date).AddDays(-30) # Issued on
            NotAfter     = (Get-Date).AddDays(31) # Expires after
            Extensions   = @()
            FriendlyName = $friendlyName
        }
        Add-Member -InputObject $emptySANCert -MemberType ScriptMethod -Name Verify -Value {
            return $true
        }

        $incorrectFriendlyName = New-Object -TypeName PSObject -Property @{
            Thumbprint   = $validThumbprint
            Subject      = "CN=$validSubject"
            Issuer       = $validIssuer
            NotBefore    = (Get-Date).AddDays(-30) # Issued on
            NotAfter     = (Get-Date).AddDays(31) # Expires after
            FriendlyName = 'This name will not match'
        }
        Add-Member -InputObject $incorrectFriendlyName -MemberType ScriptMethod -Name Verify -Value {
            return $true
        }

        $caType         = 'Enterprise'
        $cepURL         = 'DummyURL'
        $cesURL         = 'DummyURL'

        $testUsername   = 'DummyUsername'
        $testPassword   = 'DummyPassword'
        $testCredential = New-Object System.Management.Automation.PSCredential $testUsername, (ConvertTo-SecureString $testPassword -AsPlainText -Force)

        $paramsStandard = @{
            Subject               = $validSubject
            CAServerFQDN          = $caServerFQDN
            CARootName            = $caRootName
            KeyLength             = $keyLength
            Exportable            = $exportable
            ProviderName          = $providerName
            OID                   = $oid
            KeyUsage              = $keyUsage
            CertificateTemplate   = $certificateTemplate
            Credential            = $testCredential
            AutoRenew             = $False
            FriendlyName          = $friendlyName
        }

        $paramsAutoDiscovery = @{
            Subject               = $validSubject
            KeyLength             = $keyLength
            Exportable            = $exportable
            ProviderName          = $providerName
            OID                   = $oid
            KeyUsage              = $keyUsage
            CertificateTemplate   = $certificateTemplate
            Credential            = $testCredential
            AutoRenew             = $False
            FriendlyName          = $friendlyName
        }

        $paramsAutoRenew = @{
            Subject               = $validSubject
            CAServerFQDN          = $caServerFQDN
            CARootName            = $caRootName
            KeyLength             = $keyLength
            Exportable            = $exportable
            ProviderName          = $providerName
            OID                   = $oid
            KeyUsage              = $keyUsage
            CertificateTemplate   = $certificateTemplate
            Credential            = $testCredential
            AutoRenew             = $True
            FriendlyName          = $friendlyName
        }

        $paramsNoCred = @{
            Subject               = $validSubject
            CAServerFQDN          = $caServerFQDN
            CARootName            = $caRootName
            KeyLength             = $keyLength
            Exportable            = $exportable
            ProviderName          = $providerName
            OID                   = $oid
            KeyUsage              = $keyUsage
            CertificateTemplate   = $certificateTemplate
            Credential            = $null
            AutoRenew             = $False
            FriendlyName          = $friendlyName
        }

        $paramsAutoRenewNoCred = @{
            Subject               = $validSubject
            CAServerFQDN          = $caServerFQDN
            CARootName            = $caRootName
            KeyLength             = $keyLength
            Exportable            = $exportable
            ProviderName          = $providerName
            OID                   = $oid
            KeyUsage              = $keyUsage
            CertificateTemplate   = $certificateTemplate
            Credential            = $null
            AutoRenew             = $True
            FriendlyName          = $friendlyName
        }

        $paramsKeyLength4096AutoRenewNoCred = @{
            Subject               = $validSubject
            CAServerFQDN          = $caServerFQDN
            CARootName            = $caRootName
            KeyLength             = '4096'
            Exportable            = $exportable
            ProviderName          = $providerName
            OID                   = $oid
            KeyUsage              = $keyUsage
            CertificateTemplate   = $certificateTemplate
            Credential            = $null
            AutoRenew             = $True
            FriendlyName          = $friendlyName
        }

        $paramsSubjectAltName = @{
            Subject               = $validSubject
            CAServerFQDN          = $caServerFQDN
            CARootName            = $caRootName
            KeyLength             = $keyLength
            Exportable            = $exportable
            ProviderName          = $providerName
            OID                   = $oid
            KeyUsage              = $keyUsage
            CertificateTemplate   = $certificateTemplate
            Credential            = $testCredential
            SubjectAltName        = $subjectAltName
            AutoRenew             = $False
            FriendlyName          = $friendlyName
        }

        $paramsSubjectAltNameNoCred = @{
            Subject               = $validSubject
            CAServerFQDN          = $caServerFQDN
            CARootName            = $caRootName
            KeyLength             = $keyLength
            Exportable            = $exportable
            ProviderName          = $providerName
            OID                   = $oid
            KeyUsage              = $keyUsage
            CertificateTemplate   = $certificateTemplate
            Credential            = $null
            SubjectAltName        = $subjectAltName
            AutoRenew             = $False
            FriendlyName          = $friendlyName
        }

        $paramsStandaloneWebEnrollment = @{
            Subject               = $validSubject
            CAServerFQDN          = $caServerFQDN
            CARootName            = $caRootName
            KeyLength             = $keyLength
            Exportable            = $exportable
            ProviderName          = $providerName
            OID                   = $oid
            KeyUsage              = $keyUsage
            CertificateTemplate   = $certificateTemplate
            Credential            = $testCredential
            AutoRenew             = $False
            CAType                = 'Standalone'
            CepURL                = $cepURL
            CesURL                = $cesURL
            FriendlyName          = $friendlyName
        }

        $paramsEnterpriseWebEnrollment = @{
            Subject               = $validSubject
            CAServerFQDN          = $caServerFQDN
            CARootName            = $caRootName
            KeyLength             = $keyLength
            Exportable            = $exportable
            ProviderName          = $providerName
            OID                   = $oid
            KeyUsage              = $keyUsage
            CertificateTemplate   = $certificateTemplate
            Credential            = $testCredential
            AutoRenew             = $False
            CAType                = $caType
            CepURL                = $cepURL
            CesURL                = $cesURL
            FriendlyName          = $friendlyName
        }

        $certInf = @"
[NewRequest]
Subject = "CN=$validSubject"
KeySpec = 1
KeyLength = $keyLength
Exportable = $($exportable.ToString().ToUpper())
MachineKeySet = TRUE
SMIME = FALSE
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = $providerName
ProviderType = 12
RequestType = CMC
KeyUsage = $keyUsage
FriendlyName = "$friendlyName"
[RequestAttributes]
CertificateTemplate = `"$certificateTemplate`"
[EnhancedKeyUsageExtension]
OID = $oid
"@

        $certInfNoTemplate = $certInf.Replace(@"
[RequestAttributes]
CertificateTemplate = `"$certificateTemplate`"
[EnhancedKeyUsageExtension]
"@, '[EnhancedKeyUsageExtension]')

        $certInfRenew = $certInf
        $certInfRenew += @"

RenewalCert = $validThumbprint
"@
        $certInfKeyRenew = $certInfRenew -Replace 'KeyLength = ([0-z]*)', 'KeyLength = 4096'
        $certInfSubjectAltName = $certInf
        $certInfSubjectAltName += @"

[Extensions]
2.5.29.17 = "{text}$subjectAltName"
"@

        Describe "$dscResourceName\Get-TargetResource" {
            Mock Get-ChildItem -ParameterFilter { $Path -eq 'Cert:\LocalMachine\My' } `
                -Mockwith { $validCert }

            Mock Get-CertificateTemplateName -MockWith { $certificateTemplate }

            Mock Get-CertificateSan -MockWith { $subjectAltName }

            Mock -CommandName Find-CertificateAuthority -MockWith {
                    return New-Object -TypeName psobject -Property @{
                        CAServerFQDN = 'rootca.contoso.com'
                        CARootName = 'contoso-CA'
                    }
                }

            Context 'Called without auto discovery' {
                $result = Get-TargetResource @paramsStandard -Verbose

                It 'Should return a hashtable' {
                    $result | Should -BeOfType System.Collections.Hashtable
                }

                It 'Should contain the input values' {
                    $result.Subject              | Should -BeExactly $validSubject
                    $result.CAServerFQDN         | Should -BeNullOrEmpty
                    $result.CARootName           | Should -BeExactly $caRootName
                    $result.KeyLength            | Should -BeNullOrEmpty
                    $result.Exportable           | Should -BeNullOrEmpty
                    $result.ProviderName         | Should -BeNullOrEmpty
                    $result.OID                  | Should -BeNullOrEmpty
                    $result.KeyUsage             | Should -BeNullOrEmpty
                    $result.CertificateTemplate  | Should -BeExactly $certificateTemplate
                    $result.SubjectAltName       | Should -BeNullOrEmpty
                    $result.FriendlyName         | Should -BeExactly $friendlyName
                }
            }

            Context 'Called with auto discovery' {
                $result = Get-TargetResource @paramsAutoDiscovery -Verbose

                It 'Should return a hashtable' {
                    $result | Should -BeOfType System.Collections.Hashtable
                }

                It 'Should contain the input values and the CA should be auto-discovered' {
                    $result.Subject              | Should -BeExactly $validSubject
                    $result.CAServerFQDN         | Should -BeExactly $caServerFQDN
                    $result.CARootName           | Should -BeExactly $caRootName
                    $result.KeyLength            | Should -BeNullOrEmpty
                    $result.Exportable           | Should -BeNullOrEmpty
                    $result.ProviderName         | Should -BeNullOrEmpty
                    $result.OID                  | Should -BeNullOrEmpty
                    $result.KeyUsage             | Should -BeNullOrEmpty
                    $result.CertificateTemplate  | Should -BeExactly $certificateTemplate
                    $result.SubjectAltName       | Should -BeNullOrEmpty
                    $result.FriendlyName         | Should -BeExactly $friendlyName
                }

                It 'Should call the mocked function Find-CertificateAuthority once' {
                    Assert-MockCalled -CommandName Find-CertificateAuthority -Exactly -Times 1
                }
            }
        }
        #endregion

        #region Set-TargetResource
        Describe "$dscResourceName\Set-TargetResource" {
            Mock -CommandName Join-Path -MockWith { 'xCertReq-Test' } `
                -ParameterFilter { $Path -eq $env:Temp }

            Mock -CommandName Test-Path -MockWith { $true } `
                -ParameterFilter { $Path -eq 'xCertReq-Test.req' }

            Mock -CommandName Test-Path -MockWith { $true } `
                -ParameterFilter { $Path -eq 'xCertReq-Test.cer' }

            Mock -CommandName CertReq.exe

            Mock -CommandName Set-Content `
                -ParameterFilter {
                    $Path -eq 'xCertReq-Test.inf' -and `
                    $Value -eq $certInf
                }

            Context 'autorenew is false, credentials not passed' {
                Mock -CommandName Get-ChildItem -Mockwith { } `
                    -ParameterFilter { $Path -eq 'Cert:\LocalMachine\My' }

                It 'Should not throw' {
                    { Set-TargetResource @paramsNoCred  -Verbose } | Should -Not -Throw
                }

                It 'Should call expected mocks' {
                    Assert-MockCalled -CommandName Join-Path -Exactly 1

                    Assert-MockCalled -CommandName Test-Path -Exactly 1 `
                        -ParameterFilter { $Path -eq 'xCertReq-Test.req' }

                    Assert-MockCalled -CommandName Test-Path  -Exactly 1 `
                        -ParameterFilter { $Path -eq 'xCertReq-Test.cer' }

                    Assert-MockCalled -CommandName Set-Content -Exactly 1 `
                        -ParameterFilter {
                            $Path -eq 'xCertReq-Test.inf' -and `
                            $Value -eq $certInf
                        }

                    Assert-MockCalled -CommandName CertReq.exe -Exactly 3
                }
            }

            Context 'autorenew is true, credentials not passed and certificate does not exist' {
                Mock -CommandName Get-ChildItem -Mockwith { } `
                    -ParameterFilter { $Path -eq 'Cert:\LocalMachine\My' }

                It 'Should not throw' {
                    { Set-TargetResource @paramsAutoRenewNoCred -Verbose } | Should -Not -Throw
                }

                It 'Should call expected mocks' {
                    Assert-MockCalled -CommandName Join-Path -Exactly 1

                    Assert-MockCalled -CommandName Test-Path -Exactly 1 `
                        -ParameterFilter { $Path -eq 'xCertReq-Test.req' }

                    Assert-MockCalled -CommandName Test-Path  -Exactly 1 `
                        -ParameterFilter { $Path -eq 'xCertReq-Test.cer' }

                    Assert-MockCalled -CommandName Get-ChildItem -Exactly 1 `
                        -ParameterFilter { $Path -eq 'Cert:\LocalMachine\My' }

                    Assert-MockCalled -CommandName Set-Content -Exactly 1 `
                        -ParameterFilter {
                            $Path -eq 'xCertReq-Test.inf' -and `
                            $Value -eq $certInf
                        }

                    Assert-MockCalled -CommandName CertReq.exe -Exactly 3
                }
            }

            Context 'autorenew is true, credentials not passed and valid certificate exists' {
                Mock -CommandName Get-ChildItem -Mockwith { $validCert } `
                    -ParameterFilter { $Path -eq 'Cert:\LocalMachine\My' }

                It 'Should not throw' {
                    { Set-TargetResource @paramsAutoRenewNoCred -Verbose } | Should -Not -Throw
                }

                It 'Should call expected mocks' {
                    Assert-MockCalled -CommandName Join-Path -Exactly 1

                    Assert-MockCalled -CommandName Test-Path -Exactly 1 `
                        -ParameterFilter { $Path -eq 'xCertReq-Test.req' }

                    Assert-MockCalled -CommandName Test-Path  -Exactly 1 `
                        -ParameterFilter { $Path -eq 'xCertReq-Test.cer' }

                    Assert-MockCalled -CommandName Get-ChildItem -Exactly 1 `
                        -ParameterFilter { $Path -eq 'Cert:\LocalMachine\My' }

                    Assert-MockCalled -CommandName Set-Content -Exactly 1 `
                        -ParameterFilter {
                            $Path -eq 'xCertReq-Test.inf' -and `
                            $Value -eq $certInf
                        }

                    Assert-MockCalled -CommandName CertReq.exe -Exactly 3
                }
            }

            Mock -CommandName Set-Content `
                -ParameterFilter {
                    $Path -eq 'xCertReq-Test.inf' -and `
                    $Value -eq $certInfRenew
                }
            Context 'autorenew is true, credentials not passed and expiring certificate exists' {
                Mock -CommandName Get-ChildItem -Mockwith { $expiringCert } `
                    -ParameterFilter { $Path -eq 'Cert:\LocalMachine\My' }

                It 'Should not throw' {
                    { Set-TargetResource @paramsAutoRenewNoCred -Verbose } | Should -Not -Throw
                }

                It 'Should call expected mocks' {
                    Assert-MockCalled -CommandName Join-Path -Exactly 1

                    Assert-MockCalled -CommandName Test-Path -Exactly 1 `
                        -ParameterFilter { $Path -eq 'xCertReq-Test.req' }

                    Assert-MockCalled -CommandName Test-Path  -Exactly 1 `
                        -ParameterFilter { $Path -eq 'xCertReq-Test.cer' }

                    Assert-MockCalled -CommandName Get-ChildItem -Exactly 1 `
                        -ParameterFilter { $Path -eq 'Cert:\LocalMachine\My' }

                    Assert-MockCalled -CommandName Set-Content -Exactly 1 `
                        -ParameterFilter {
                            $Path -eq 'xCertReq-Test.inf' -and `
                            $Value -eq $certInfRenew
                        }

                    Assert-MockCalled -CommandName CertReq.exe -Exactly 3
                }
            }

            Context 'autorenew is true, credentials not passed and expired certificate exists' {
                Mock -CommandName Get-ChildItem -Mockwith { $expiredCert } `
                    -ParameterFilter { $Path -eq 'Cert:\LocalMachine\My' }

                It 'Should not throw' {
                    { Set-TargetResource @paramsAutoRenewNoCred -Verbose } | Should -Not -Throw
                }

                It 'Should call expected mocks' {
                    Assert-MockCalled -CommandName Join-Path -Exactly 1

                    Assert-MockCalled -CommandName Test-Path -Exactly 1 `
                        -ParameterFilter { $Path -eq 'xCertReq-Test.req' }

                    Assert-MockCalled -CommandName Test-Path  -Exactly 1 `
                        -ParameterFilter { $Path -eq 'xCertReq-Test.cer' }

                    Assert-MockCalled -CommandName Get-ChildItem -Exactly 1 `
                        -ParameterFilter { $Path -eq 'Cert:\LocalMachine\My' }

                    Assert-MockCalled -CommandName Set-Content -Exactly 1 `
                        -ParameterFilter {
                            $Path -eq 'xCertReq-Test.inf' -and `
                            $Value -eq $certInfRenew
                        }

                    Assert-MockCalled -CommandName CertReq.exe -Exactly 3
                }
            }

            Mock -CommandName Set-Content `
                -ParameterFilter {
                    $Path -eq 'xCertReq-Test.inf' -and `
                    $Value -eq $certInfKeyRenew
                }

            Context 'autorenew is true, credentials not passed, keylength passed and expired certificate exists' {
                Mock -CommandName Get-ChildItem -Mockwith { $expiredCert } `
                    -ParameterFilter { $Path -eq 'Cert:\LocalMachine\My' }

                It 'Should not throw' {
                    { Set-TargetResource @paramsKeyLength4096AutoRenewNoCred -Verbose } | Should -Not -Throw
                }

                It 'Should call expected mocks' {
                    Assert-MockCalled -CommandName Join-Path -Exactly 1

                    Assert-MockCalled -CommandName Test-Path -Exactly 1 `
                        -ParameterFilter { $Path -eq 'xCertReq-Test.req' }
                    Assert-MockCalled -CommandName Test-Path  -Exactly 1 `
                        -ParameterFilter { $Path -eq 'xCertReq-Test.cer' }

                    Assert-MockCalled -CommandName Get-ChildItem -Exactly 1 `
                        -ParameterFilter { $Path -eq 'Cert:\LocalMachine\My' }

                    Assert-MockCalled -CommandName Set-Content -Exactly 1 `
                        -ParameterFilter { $Path -eq 'xCertReq-Test.inf' }

                    Assert-MockCalled -CommandName CertReq.exe -Exactly 3

                    Assert-MockCalled -CommandName Set-Content -Exactly 1 `
                        -ParameterFilter {
                            $Path -eq 'xCertReq-Test.inf' -and `
                            $Value -eq $certInfKeyRenew
                        }
                }
            }

            Mock -CommandName Test-Path -MockWith { $false } `
                -ParameterFilter { $Path -eq 'xCertReq-Test.req' }

            Mock -CommandName Set-Content `
                -ParameterFilter {
                    $Path -eq 'xCertReq-Test.inf' -and `
                    $Value -eq $certInf
                }

            Context 'autorenew is false, credentials not passed, certificate request creation failed' {
                Mock -CommandName Get-ChildItem -Mockwith { } `
                    -ParameterFilter { $Path -eq 'Cert:\LocalMachine\My' }

                $errorRecord = Get-InvalidOperationRecord `
                    -Message ($LocalizedData.CertificateReqNotFoundError -f 'xCertReq-Test.req')

                It 'Should throw CertificateReqNotFoundError exception' {
                    { Set-TargetResource @paramsNoCred -Verbose } | Should -Throw $errorRecord
                }

                It 'Should call expected mocks' {
                    Assert-MockCalled -CommandName Join-Path -Exactly 1

                    Assert-MockCalled -CommandName Test-Path -Exactly 1 `
                        -ParameterFilter { $Path -eq 'xCertReq-Test.req' }

                    Assert-MockCalled -CommandName Test-Path -Exactly 0 `
                        -ParameterFilter { $Path -eq 'xCertReq-Test.cer' }

                    Assert-MockCalled -CommandName Set-Content -Exactly 1 `
                        -ParameterFilter {
                            $Path -eq 'xCertReq-Test.inf' -and `
                            $Value -eq $certInf
                        }

                    Assert-MockCalled -CommandName CertReq.exe -Exactly 1
                }
            }

            Mock -CommandName Test-Path -MockWith { $true } `
                -ParameterFilter { $Path -eq 'xCertReq-Test.req' }

            Mock -CommandName Test-Path -MockWith { $false } `
                -ParameterFilter { $Path -eq 'xCertReq-Test.cer' }

            Context 'Autorenew is false, credentials not passed, certificate creation failed' {
                Mock -CommandName Get-ChildItem -Mockwith { } `
                    -ParameterFilter { $Path -eq 'Cert:\LocalMachine\My' }

                $errorRecord = Get-InvalidOperationRecord `
                    -Message ($LocalizedData.CertificateCerNotFoundError -f 'xCertReq-Test.cer')

                It 'Should throw CertificateCerNotFoundError exception' {
                    { Set-TargetResource @paramsNoCred -Verbose } | Should -Throw $errorRecord
                }

                It 'Should call expected mocks' {
                    Assert-MockCalled -CommandName Join-Path -Exactly 1

                    Assert-MockCalled -CommandName Test-Path -Exactly 1 `
                        -ParameterFilter { $Path -eq 'xCertReq-Test.req' }

                    Assert-MockCalled -CommandName Test-Path -Exactly 1 `
                        -ParameterFilter { $Path -eq 'xCertReq-Test.cer' }

                    Assert-MockCalled -CommandName Set-Content -Exactly 1 `
                        -ParameterFilter {
                            $Path -eq 'xCertReq-Test.inf' -and `
                            $Value -eq $certInf
                        }

                    Assert-MockCalled -CommandName CertReq.exe -Exactly 2
                }
            }

            Mock -CommandName Test-Path -MockWith { $true } `
                -ParameterFilter { $Path -eq 'xCertReq-Test.req' }

            Mock -CommandName Test-Path -MockWith { $true } `
                -ParameterFilter { $Path -eq 'xCertReq-Test.cer' }

            Mock -CommandName Test-Path -MockWith { $true } `
                -ParameterFilter { $Path -eq 'xCertReq-Test.out' }

            Context 'autorenew is false, credentials passed' {
                Mock -CommandName Get-ChildItem -Mockwith { } `
                    -ParameterFilter { $Path -eq 'Cert:\LocalMachine\My' }

                Mock -CommandName Get-Content -Mockwith { 'Output' } `
                    -ParameterFilter { $Path -eq 'xCertReq-Test.out' }

                Mock -CommandName Remove-Item `
                    -ParameterFilter { $Path -eq 'xCertReq-Test.out' }

                Mock -CommandName Import-Module

                function Start-Win32Process {
                    param (
                        [Parameter()]
                        $Path,

                        [Parameter()]
                        $Arguments,

                        [Parameter()]
                        $Credential
                    )
                }

                function Wait-Win32ProcessStop {
                    param (
                        [Parameter()]
                        $Path,

                        [Parameter()]
                        $Arguments,

                        [Parameter()]
                        $Credential
                    )
                }

                Mock -CommandName Start-Win32Process -ModuleName MSFT_xCertReq

                Mock -CommandName Wait-Win32ProcessStop -ModuleName MSFT_xCertReq

                It 'Should not throw' {
                    { Set-TargetResource @paramsStandard -Verbose } | Should -Not -Throw
                }

                It 'Should call expected mocks' {
                    Assert-MockCalled -CommandName Join-Path -Exactly 1

                    Assert-MockCalled -CommandName Test-Path -Exactly 1 `
                        -ParameterFilter { $Path -eq 'xCertReq-Test.req' }

                    Assert-MockCalled -CommandName Test-Path  -Exactly 1 `
                        -ParameterFilter { $Path -eq 'xCertReq-Test.cer' }

                    Assert-MockCalled -CommandName Set-Content -Exactly 1 `
                        -ParameterFilter {
                            $Path -eq 'xCertReq-Test.inf' -and `
                            $Value -eq $certInf
                        }

                    Assert-MockCalled -CommandName CertReq.exe -Exactly 2

                    Assert-MockCalled -CommandName Start-Win32Process -ModuleName MSFT_xCertReq -Exactly 1

                    Assert-MockCalled -CommandName Wait-Win32ProcessStop -ModuleName MSFT_xCertReq -Exactly 1

                    Assert-MockCalled -CommandName Test-Path  -Exactly 1 `
                        -ParameterFilter { $Path -eq 'xCertReq-Test.out' }

                    Assert-MockCalled -CommandName Get-Content -Exactly 1 `
                        -ParameterFilter { $Path -eq 'xCertReq-Test.out' }

                    Assert-MockCalled -CommandName Remove-Item -Exactly 1 `
                        -ParameterFilter { $Path -eq 'xCertReq-Test.out' }
                }
            }

            Mock -CommandName Set-Content `
                -ParameterFilter {
                    $Path -eq 'xCertReq-Test.inf' -and `
                    $Value -eq $certInfSubjectAltName
                }

            Context 'autorenew is false, subject alt name passed, credentials not passed' {
                Mock -CommandName Get-ChildItem -Mockwith { } `
                    -ParameterFilter { $Path -eq 'Cert:\LocalMachine\My' }

                It 'Should not throw' {
                    { Set-TargetResource @paramsSubjectAltNameNoCred -Verbose } | Should -Not -Throw
                }

                It 'Should call expected mocks' {
                    Assert-MockCalled -CommandName Join-Path -Exactly 1

                    Assert-MockCalled -CommandName Test-Path -Exactly 1 `
                        -ParameterFilter { $Path -eq 'xCertReq-Test.req' }

                    Assert-MockCalled -CommandName Test-Path  -Exactly 1 `
                        -ParameterFilter { $Path -eq 'xCertReq-Test.cer' }

                    Assert-MockCalled -CommandName Set-Content -Exactly 1 `
                        -ParameterFilter {
                            $Path -eq 'xCertReq-Test.inf' -and `
                            $Value -eq $certInfSubjectAltName
                        }

                    Assert-MockCalled -CommandName CertReq.exe -Exactly 3
                }
            }

            Context 'standalone CA, URL for CEP and CES passed, credentials passed, inf not containing template' {
                Mock -CommandName Set-Content -ParameterFilter {
                    $Path -eq 'xCertReq-Test.inf' -and `
                    $Value -eq $certInfNoTemplate
                }

                Mock -CommandName Get-ChildItem -Mockwith { } `
                    -ParameterFilter { $Path -eq 'Cert:\LocalMachine\My' }

                It 'Should not throw' {
                    { Set-TargetResource @paramsStandaloneWebEnrollment -Verbose } | Should -Not -Throw
                }

                It 'Should call expected mocks' {
                    Assert-MockCalled -CommandName Join-Path -Exactly 1

                    Assert-MockCalled -CommandName Test-Path -Exactly 1 `
                        -ParameterFilter { $Path -eq 'xCertReq-Test.req' }

                    Assert-MockCalled -CommandName Test-Path  -Exactly 1 `
                        -ParameterFilter { $Path -eq 'xCertReq-Test.cer' }

                    Assert-MockCalled -CommandName Set-Content -Exactly 1 `
                        -ParameterFilter {
                            $Path -eq 'xCertReq-Test.inf' -and `
                            $Value -eq $certInfNoTemplate
                        }

                    Assert-MockCalled -CommandName CertReq.exe -Exactly 3
                }
            }

            Context 'enterprise CA, URL for CEP and CES passed, credentials passed' {
                Mock -CommandName Set-Content -ParameterFilter {
                    $Path -eq 'xCertReq-Test.inf' -and `
                    $Value -eq $certInf
                }

                Mock -CommandName Get-ChildItem -Mockwith { } `
                    -ParameterFilter { $Path -eq 'Cert:\LocalMachine\My' }

                It 'Should not throw' {
                    { Set-TargetResource @paramsEnterpriseWebEnrollment -Verbose } | Should -Not -Throw
                }

                It 'Should call expected mocks' {
                    Assert-MockCalled -CommandName Join-Path -Exactly 1

                    Assert-MockCalled -CommandName Test-Path -Exactly 1 `
                        -ParameterFilter { $Path -eq 'xCertReq-Test.req' }

                    Assert-MockCalled -CommandName Test-Path  -Exactly 1 `
                        -ParameterFilter { $Path -eq 'xCertReq-Test.cer' }

                    Assert-MockCalled -CommandName Set-Content -Exactly 1 `
                        -ParameterFilter {
                            $Path -eq 'xCertReq-Test.inf' -and `
                            $Value -eq $certInf
                        }

                    Assert-MockCalled -CommandName CertReq.exe -Exactly 3
                }
            }

            Context 'Auto-discovered CA, autorenew is false, credentials passed' {
                Mock -CommandName Get-ChildItem -Mockwith { } `
                    -ParameterFilter { $Path -eq 'Cert:\LocalMachine\My' }

                Mock -CommandName Get-Content -Mockwith { 'Output' } `
                    -ParameterFilter { $Path -eq 'xCertReq-Test.out' }

                Mock -CommandName Remove-Item `
                    -ParameterFilter { $Path -eq 'xCertReq-Test.out' }

                Mock -CommandName Import-Module

                Mock -CommandName Start-Win32Process

                Mock -CommandName Wait-Win32ProcessStop

                Mock -CommandName Find-CertificateAuthority -MockWith {
                    return New-Object -TypeName psobject -Property @{
                        CARootName = "ContosoCA"
                        CAServerFQDN = "ContosoVm.contoso.com"
                    }
                }

                It 'Should not throw' {
                    { Set-TargetResource @paramsAutoDiscovery -Verbose } | Should -Not -Throw
                }

                It 'Should call expected mocks' {
                    Assert-MockCalled -CommandName Join-Path -Exactly 1

                    Assert-MockCalled -CommandName Test-Path -Exactly 1 `
                        -ParameterFilter { $Path -eq 'xCertReq-Test.req' }

                    Assert-MockCalled -CommandName Test-Path  -Exactly 1 `
                        -ParameterFilter { $Path -eq 'xCertReq-Test.cer' }

                    Assert-MockCalled -CommandName Set-Content -Exactly 1 `
                        -ParameterFilter {
                            $Path -eq 'xCertReq-Test.inf' -and `
                            $Value -eq $certInf
                        }

                    Assert-MockCalled -CommandName CertReq.exe -Exactly 2

                    Assert-MockCalled -CommandName Start-Win32Process -ModuleName MSFT_xCertReq -Exactly 1

                    Assert-MockCalled -CommandName Wait-Win32ProcessStop -ModuleName MSFT_xCertReq -Exactly 1

                    Assert-MockCalled -CommandName Test-Path  -Exactly 1 `
                        -ParameterFilter { $Path -eq 'xCertReq-Test.out' }

                    Assert-MockCalled -CommandName Get-Content -Exactly 1 `
                        -ParameterFilter { $Path -eq 'xCertReq-Test.out' }

                    Assert-MockCalled -CommandName Remove-Item -Exactly 1 `
                        -ParameterFilter { $Path -eq 'xCertReq-Test.out' }

                    Assert-MockCalled -CommandName Find-CertificateAuthority -Exactly -Times 1
                }
            }
        }
        #endregion

        Describe "$dscResourceName\Test-TargetResource" {
            Mock -CommandName Find-CertificateAuthority -MockWith {
                    return New-Object -TypeName psobject -Property @{
                        CARootName = "ContosoCA"
                        CAServerFQDN = "ContosoVm.contoso.com"
                    }
                }

            It 'Should return a bool' {
                Test-TargetResource @paramsStandard -Verbose | Should -BeOfType Boolean
            }

            Context 'A valid certificate does not exist' {
                It 'Should return false' {
                    Mock Get-ChildItem -ParameterFilter { $Path -eq 'Cert:\LocalMachine\My' } `
                        -Mockwith { }

                    Test-TargetResource @paramsStandard -Verbose | Should -Be $false
                }
            }

            Context 'A valid certificate already exists and is not about to expire' {
                It 'Should return true' {
                    Mock Get-ChildItem -ParameterFilter { $Path -eq 'Cert:\LocalMachine\My' } `
                        -Mockwith { $validCert }

                    Mock Get-CertificateTemplateName -MockWith { $certificateTemplate }

                    Mock Get-CertificateSan -MockWith { $subjectAltName }

                    Test-TargetResource @paramsStandard -Verbose | Should -Be $true
                }
            }

            Context 'A valid certificate already exists and is about to expire and autorenew set' {
                It 'Should return true' {
                    Mock Get-ChildItem -ParameterFilter { $Path -eq 'Cert:\LocalMachine\My' } `
                        -Mockwith { $expiringCert }

                    Mock Get-CertificateTemplateName -MockWith { $certificateTemplate }

                    Mock Get-CertificateSan -MockWith { $subjectAltName }

                    Test-TargetResource @paramsAutoRenew -Verbose | Should -Be $true
                }
            }

            Context 'A valid certificate already exists and DNS SANs match' {
                It 'Should return true' {
                    Mock Get-ChildItem -ParameterFilter { $Path -eq 'Cert:\LocalMachine\My' } `
                        -Mockwith { $validSANCert }

                    Mock Get-CertificateTemplateName -MockWith { $certificateTemplate }

                    Test-TargetResource @paramsSubjectAltName -Verbose | Should -Be $true
                }
            }

            Context 'A certificate exists but contains incorrect DNS SANs' {
                It 'Should return false' {
                    Mock Get-ChildItem -ParameterFilter { $Path -eq 'Cert:\LocalMachine\My' } `
                        -Mockwith { $incorrectSANCert }

                    Mock Get-CertificateTemplateName -MockWith { $certificateTemplate }

                    Test-TargetResource @paramsSubjectAltName -Verbose | Should -Be $false
                }
            }

            Context 'A certificate exists but does not contain specified DNS SANs' {
                It 'Should return false' {
                    Mock Get-ChildItem -ParameterFilter { $Path -eq 'Cert:\LocalMachine\My' } `
                        -Mockwith { $emptySANCert }

                    Mock Get-CertificateTemplateName -MockWith { $certificateTemplate }

                    Test-TargetResource @paramsSubjectAltName -Verbose | Should -Be $false
                }
            }

            Context 'A certificate exists but does not match the Friendly Name' {
                It 'Should return false' {
                    Mock Get-ChildItem -ParameterFilter { $Path -eq 'Cert:\LocalMachine\My' } `
                        -Mockwith { $incorrectFriendlyName }

                    Mock Get-CertificateTemplateName -MockWith { $certificateTemplate }

                    Test-TargetResource @paramsStandard -Verbose | Should -Be $false
                }
            }

            Context 'When Auto auto-discover of the CA is enabled' {
                It 'Should return false' {
                    Test-TargetResource @paramsAutoDiscovery -Verbose | Should -Be $false
                }

                It 'Should execute the auto-discovery function' {
                    Assert-MockCalled -CommandName Find-CertificateAuthority -Exactly -Times 1
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
