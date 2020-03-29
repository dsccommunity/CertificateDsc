<#
    IMPORTANT INFORMATION:
    Running these tests requires access to a AD CS Certificate Authority.
    These integration tests are configured to use credentials to connect to the CA.
    Therefore, automation of these tests shouldn't be performed using a production CA.
#>

$script:DSCModuleName = 'CertificateDsc'
$script:DSCResourceName = 'MSFT_CertReq'

<#
    These tests can only be run if a CA is available and configured to be used on the
    computer running these tests. This is usually required to be a domain joined computer.
#>
$CertUtilResult = & "$env:SystemRoot\system32\certutil.exe" @('-dump')
$Result = ([regex]::matches($CertUtilResult, 'Name:[ \t]+`([\sA-Za-z0-9._-]+)''', 'IgnoreCase'))
if ([String]::IsNullOrEmpty($Result))
{
    Describe "$($script:DSCResourceName)_Integration" {
        It 'should complete integration tests' {
        } -Skip
    }
    return
} # if

#region HEADER
# Integration Test Template Version: 1.1.1
[System.String] $script:moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ( (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
    (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone', 'https://github.com/PowerShell/DscResource.Tests.git', (Join-Path -Path $script:moduleRoot -ChildPath '\DSCResource.Tests\'))
}

Import-Module -Name (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1') -Force
$TestEnvironment = Initialize-TestEnvironment `
    -DSCModuleName $script:DSCModuleName `
    -DSCResourceName $script:DSCResourceName `
    -TestType Integration
#endregion

# Using try/finally to always cleanup even if something awful happens.
try
{
    Describe "$($script:DSCResourceName)_Integration" {
        BeforeAll {
            $configFile = Join-Path -Path $PSScriptRoot -ChildPath "$($script:DSCResourceName).config.ps1"
            . $configFile

            # This will fail if the machine does not have a CA Configured.
            $certUtilResult = & "$env:SystemRoot\system32\certutil.exe" @('-dump')
            $caServerFQDN = ([regex]::matches($certUtilResult, 'Server:[ \t]+`([A-Za-z0-9._-]+)''', 'IgnoreCase')).Groups[1].Value
            $caRootName = ([regex]::matches($certUtilResult, 'Name:[ \t]+`([\sA-Za-z0-9._-]+)''', 'IgnoreCase')).Groups[1].Value
            $exportable = $true
            $providerName = '"Microsoft RSA SChannel Cryptographic Provider"'
            $oid = '1.3.6.1.5.5.7.3.1'
            $keyUsage = '0xa0'
            $dns1 = 'contoso.com'
            $dns2 = 'fabrikam.com'
            $subjectAltName = "dns=$dns1&dns=$dns2"
            $friendlyName = "$($script:DSCResourceName) Integration Test"

            $paramsRsaCmcRequest = @{
                keyLength           = '2048'
                subject             = "$($script:DSCResourceName)_Test"
                certificateTemplate = 'WebServer'
                keyType             = 'RSA'
                RequestType         = 'CMC'
            }

            $paramsEcdhPkcs10Request = @{
                keyLength            = '521'
                subject              = "$($script:DSCResourceName)_Test2"
                providerName         = 'Microsoft Software Key Storage Provider'
                certificateTemplate  = 'WebServer'
                keyType              = 'ECDH'
                RequestType          = 'PKCS10'
            }

            <#
                If automated testing with a real CA can be performed then the credentials should be
                obtained non-interactively. Do not do this in a production environment.
            #>
            $credential = Get-Credential
        }

        AfterAll {
            # Cleanup
            $CertificateNew = Get-Childitem -Path Cert:\LocalMachine\My |
            Where-Object -FilterScript {
                $_.Subject -eq "CN=$($paramsRsaCmcRequest.subject)" -and `
                    $_.Issuer.split(',')[0] -eq "CN=$($caRootName)"
            }
            $CertificateNew2 = Get-Childitem -Path Cert:\LocalMachine\My |
            Where-Object -FilterScript {
                $_.Subject -eq "CN=$($paramsEcdhPkcs10Request.subject)" -and `
                    $_.Issuer.split(',')[0] -eq "CN=$($caRootName)"
            }

            Remove-Item `
                -Path $CertificateNew.PSPath `
                -Force `
                -ErrorAction SilentlyContinue

            Remove-Item `
                -Path $CertificateNew2.PSPath `
                -Force `
                -ErrorAction SilentlyContinue
        }

        Context 'When WebServer certificate does not exist, Testing with RSA KeyType and CMC RequestType' {
            $configData = @{
                AllNodes = @(
                    @{
                        NodeName                    = 'localhost'
                        Subject                     = $paramsRsaCmcRequest.subject
                        CAServerFQDN                = $caServerFQDN
                        CARootName                  = $caRootName
                        Credential                  = $credential
                        KeyLength                   = $paramsRsaCmcRequest.keyLength
                        Exportable                  = $exportable
                        ProviderName                = $providerName
                        OID                         = $oid
                        KeyUsage                    = $keyUsage
                        CertificateTemplate         = $paramsRsaCmcRequest.certificateTemplate
                        SubjectAltName              = $subjectAltName
                        FriendlyName                = $friendlyName
                        KeyType                     = $paramsRsaCmcRequest.keyType
                        RequestType                 = $paramsRsaCmcRequest.requestType
                        PsDscAllowDomainUser        = $true
                        PsDscAllowPlainTextPassword = $true
                    }
                )
            }

            It 'Should compile the MOF without throwing an exception' {
                {
                    & "$($script:DSCResourceName)_Config" `
                        -OutputPath $TestDrive `
                        -ConfigurationData $configData
                } | Should -Not -Throw
            }

            It 'Should apply the MOF without throwing an exception' {
                {
                    Start-DscConfiguration `
                        -Path $TestDrive `
                        -ComputerName localhost `
                        -Wait `
                        -Verbose `
                        -Force `
                        -ErrorAction Stop
                } | Should -Not -Throw
            }

            It 'Should be able to call Get-DscConfiguration without throwing' {
                { Get-DscConfiguration -Verbose -ErrorAction Stop } | Should -Not -Throw
            }

            It 'Should have set the resource and all the parameters should match' {
                # Get the Certificate details
                $CertificateNew = Get-Childitem -Path Cert:\LocalMachine\My |
                Where-Object -FilterScript {
                    $_.Subject -eq "CN=$($paramsRsaCmcRequest.subject)" -and `
                        $_.Issuer.split(',')[0] -eq "CN=$($caRootName)"
                }
                $CertificateNew.Subject | Should -Be "CN=$($paramsRsaCmcRequest.subject)"
                $CertificateNew.Issuer.split(',')[0] | Should -Be "CN=$($caRootName)"
                $CertificateNew.Publickey.Key.KeySize | Should -Be $paramsRsaCmcRequest.keyLength
                $CertificateNew.FriendlyName | Should -Be $friendlyName
                $CertificateNew.DnsNameList[0] | Should -Be $dns1
                $CertificateNew.DnsNameList[1] | Should -Be $dns2
                $CertificateNew.EnhancedKeyUsageList.ObjectId | Should -Be $oid
            }
        }

        Context 'When WebServer certificate does not exist, Testing with ECDH KeyType and PKCS10 RequestType' {
            $configData = @{
                AllNodes = @(
                    @{
                        NodeName                    = 'localhost'
                        Subject                     = $paramsEcdhPkcs10Request.subject
                        CAServerFQDN                = $caServerFQDN
                        CARootName                  = $caRootName
                        Credential                  = $credential
                        KeyLength                   = $paramsEcdhPkcs10Request.keyLength
                        Exportable                  = $exportable
                        ProviderName                = $paramsEcdhPkcs10Request.providerName
                        OID                         = $oid
                        KeyUsage                    = $keyUsage
                        CertificateTemplate         = $paramsEcdhPkcs10Request.certificateTemplate
                        SubjectAltName              = $subjectAltName
                        FriendlyName                = $friendlyName
                        KeyType                     = $paramsEcdhPkcs10Request.keyType
                        RequestType                 = $paramsEcdhPkcs10Request.requestType
                        PsDscAllowDomainUser        = $true
                        PsDscAllowPlainTextPassword = $true
                    }
                )
            }

            It 'Should compile the MOF without throwing an exception' {
                {
                    & "$($script:DSCResourceName)_Config" `
                        -OutputPath $TestDrive `
                        -ConfigurationData $configData
                } | Should -Not -Throw
            }

            It 'Should apply the MOF without throwing an exception' {
                {
                    Start-DscConfiguration `
                        -Path $TestDrive `
                        -ComputerName localhost `
                        -Wait `
                        -Verbose `
                        -Force `
                        -ErrorAction Stop
                } | Should -Not -Throw
            }

            It 'Should be able to call Get-DscConfiguration without throwing' {
                { Get-DscConfiguration -Verbose -ErrorAction Stop } | Should -Not -Throw
            }

            It 'Should have set the resource and all the parameters should match' {
                # Get the Certificate details
                $CertificateNew = Get-Childitem -Path Cert:\LocalMachine\My |
                Where-Object -FilterScript {
                    $_.Subject -eq "CN=$($paramsEcdhPkcs10Request.subject)" -and `
                        $_.Issuer.split(',')[0] -eq "CN=$($caRootName)"
                }

                # Removed check for key length becuase in the ECDH certificate PowerShell cannot see the length
                $CertificateNew.Subject | Should -Be "CN=$($paramsEcdhPkcs10Request.subject)"
                $CertificateNew.Issuer.split(',')[0] | Should -Be "CN=$($caRootName)"
                $CertificateNew.FriendlyName | Should -Be $friendlyName
                $CertificateNew.DnsNameList[0] | Should -Be $dns1
                $CertificateNew.DnsNameList[1] | Should -Be $dns2
                $CertificateNew.EnhancedKeyUsageList.ObjectId | Should -Be $oid
            }
        }
    }
}
finally
{
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
}

