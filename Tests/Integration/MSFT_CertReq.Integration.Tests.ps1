<#
 IMPORTANT INFORMATION:
 Running these tests requires access to a AD CS Certificate Authority.
 These integration tests are configured to use credentials to connect to the CA.
 Therefore, automation of these tests shouldn't be performed using a production CA.
#>

$script:DSCModuleName   = 'CertificateDsc'
$script:DSCResourceName = 'MSFT_CertReq'

<#
 These tests can only be run if a CA is available and configured to be used on the
 computer running these tests. This is usually required to be a domain joined computer.
#>
$CertUtilResult = & "$env:SystemRoot\system32\certutil.exe" @('-dump')
$Result = ([regex]::matches($CertUtilResult,'Name:[ \t]+`([\sA-Za-z0-9._-]+)''','IgnoreCase'))
if ([String]::IsNullOrEmpty($Result))
{
    Describe "$($script:DSCResourceName)_Integration" {
        It 'should complete integration tests' {
        } -Skip
    }
    return
} # if

#region HEADER
# Integration Test Template Version: 1.1.0
[System.String] $script:moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ( (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
     (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone','https://github.com/PowerShell/DscResource.Tests.git',(Join-Path -Path $script:moduleRoot -ChildPath '\DSCResource.Tests\'))
}

Import-Module (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1') -Force
$TestEnvironment = Initialize-TestEnvironment `
    -DSCModuleName $script:DSCModuleName `
    -DSCResourceName $script:DSCResourceName `
    -TestType Integration
#endregion

# Using try/finally to always cleanup even if something awful happens.
try
{
    #region Integration Tests
    $ConfigFile = Join-Path -Path $PSScriptRoot -ChildPath "$($script:DSCResourceName).config.ps1"
    . $ConfigFile

    Describe "$($script:DSCResourceName)_Integration" {
        BeforeAll {
            # This will fail if the machine does not have a CA Configured.
            $certUtilResult       = & "$env:SystemRoot\system32\certutil.exe" @('-dump')
            $caServerFQDN         = ([regex]::matches($certUtilResult,'Server:[ \t]+`([A-Za-z0-9._-]+)''','IgnoreCase')).Groups[1].Value
            $caRootName           = ([regex]::matches($certUtilResult,'Name:[ \t]+`([\sA-Za-z0-9._-]+)''','IgnoreCase')).Groups[1].Value
            $keyLength            = '2048'
            $exportable           = $true
            $providerName         = '"Microsoft RSA SChannel Cryptographic Provider"'
            $oid                  = '1.3.6.1.5.5.7.3.1'
            $keyUsage             = '0xa0'
            $certificateTemplate  = 'WebServer'
            $subject              = "$($script:DSCResourceName)_Test"
            $dns1                 = 'contoso.com'
            $dns2                 = 'fabrikam.com'
            $subjectAltName       = "dns=$dns1&dns=$dns2"
            $friendlyName         = "$($script:DSCResourceName) Integration Test"

            <#
                If automated testing with a real CA can be performed then the credentials should be
                obtained non-interactively. Do not do this in a production environment.
            #>
            $Credential = Get-Credential

            # This is to allow the testing of certreq with domain credentials
            $configData = @{
                AllNodes = @(
                    @{
                        NodeName                    = 'localhost'
                        Subject                     = $subject
                        CAServerFQDN                = $caServerFQDN
                        CARootName                  = $caRootName
                        Credential                  = $credential
                        KeyLength                   = $keyLength
                        Exportable                  = $exportable
                        ProviderName                = $providerName
                        OID                         = $oid
                        KeyUsage                    = $keyUsage
                        CertificateTemplate         = $certificateTemplate
                        SubjectAltName              = $subjectAltName
                        FriendlyName                = $friendlyName
                        PsDscAllowDomainUser        = $true
                        PsDscAllowPlainTextPassword = $true
                    }
                )
            }
        }

        #region DEFAULT TESTS
        Context 'WebServer certificate does not exist' {
            It 'Should compile and apply the MOF without throwing' {
                {
                    & "$($script:DSCResourceName)_Config" `
                        -OutputPath $TestDrive `
                        -ConfigurationData $configData

                    Start-DscConfiguration -Path $TestDrive -ComputerName localhost -Wait -Verbose -Force
                } | Should -Not -Throw
            }

            It 'Should be able to call Get-DscConfiguration without throwing' {
                { Get-DscConfiguration -Verbose -ErrorAction Stop } | Should -Not -Throw
            }

            It 'Should have set the resource and all the parameters should match' {
                # Get the Certificate details
                $CertificateNew = Get-Childitem -Path Cert:\LocalMachine\My |
                    Where-Object -FilterScript {
                        $_.Subject -eq "CN=$($subject)" -and `
                        $_.Issuer.split(',')[0] -eq "CN=$($caRootName)"
                    }
                $CertificateNew.Subject                        | Should -Be "CN=$($subject)"
                $CertificateNew.Issuer.split(',')[0]           | Should -Be "CN=$($caRootName)"
                $CertificateNew.Publickey.Key.KeySize          | Should -Be $keyLength
                $CertificateNew.FriendlyName                   | Should -Be $friendlyName
                $CertificateNew.DnsNameList[0]                 | Should -Be $dns1
                $CertificateNew.DnsNameList[1]                 | Should -Be $dns2
                $CertificateNew.EnhancedKeyUsageList.ObjectId  | Should -Be $oid
            }
        }
        #endregion

        AfterAll {
            # Cleanup
            $CertificateNew = Get-Childitem -Path Cert:\LocalMachine\My |
                Where-Object -FilterScript {
                    $_.Subject -eq "CN=$($subject)" -and `
                    $_.Issuer.split(',')[0] -eq "CN=$($caRootName)"
                }

            Remove-Item `
                -Path $CertificateNew.PSPath `
                -Force `
                -ErrorAction SilentlyContinue
        }
    }
    #endregion
}
finally
{
    #region FOOTER
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
    #endregion
}
