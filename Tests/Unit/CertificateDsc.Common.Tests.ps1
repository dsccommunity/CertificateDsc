$script:ModuleName = 'CertificateDsc.Common'

#region HEADER
# Unit Test Template Version: 1.1.0
[System.String] $script:moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ( (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
    (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone', 'https://github.com/PowerShell/DscResource.Tests.git', (Join-Path -Path $script:moduleRoot -ChildPath '\DSCResource.Tests\'))
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

        # This thumbprint is valid (but not FIPS valid)
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

        # This thumbprint is valid for FIPS
        $validFipsThumbprint = (
            [System.AppDomain]::CurrentDomain.GetAssemblies().GetTypes() | Where-Object {
                $_.BaseType.BaseType -eq [System.Security.Cryptography.HashAlgorithm] -and
                ($_.Name -cmatch 'Provider$' -and $_.Name -cnotmatch 'MD5')
            } | Select-Object -First 1 | ForEach-Object {
                (New-Object $_).ComputeHash([String]::Empty) | ForEach-Object {
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

        $cerFileWithAltTemplate = "
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
        $cerBytesWithAltTemplate = [System.Text.Encoding]::ASCII.GetBytes($cerFileWithAltTemplate)

        $testCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cerBytes)
        $testCertificateWithoutSan = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cerBytesWithoutSan)
        $testCertificateWithAltTemplate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cerBytesWithAltTemplate)

        Describe "$DSCResourceName\Test-CertificatePath" {
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

        Describe "$DSCResourceName\Test-Thumbprint" {
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

        Describe "$DSCResourceName\Find-Certificate" {
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
                    { $script:result = Find-Certificate -Thumbprint $validThumbprint -Store 'NoCert'} | Should -Not -Throw
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

        Describe "$DSCResourceName\Find-CertificateAuthority" {
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

                It 'Should not throw' {
                    $script:result = Find-CertificateAuthority -DomainName contoso.com -Verbose
                }

                It 'Should return the expected CA' {
                    $script:result.CARootName   | Should -Be 'LabRootCA1'
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

        Describe "$DSCResourceName\Test-CertificateAuthority" {
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
                        Add-Member -MemberType ScriptMethod -Name Start -Value {} -PassThru |
                        Add-Member -MemberType ScriptMethod -Name WaitForExit -Value {}

                    return $retObj
                }

                It 'Should not throw' {
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
                        Add-Member -MemberType ScriptMethod -Name Start -Value {} -PassThru |
                        Add-Member -MemberType ScriptMethod -Name WaitForExit -Value {}

                    return $retObj
                }

                It 'Should not throw' {
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

        Describe "$DSCResourceName\Get-CertificateTemplateName" {
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
                    Get-CertificateTemplateName -Certificate $testCertificateWithAltTemplate | Should -Be 'WebServer'
                }

                Mock -CommandName Get-CertificateTemplateText -MockWith {
@'
Template=Web Server(1.3.6.1.4.1.311.21.8.5734392.6195358.14893705.12992936.3444946.62.1.16)
Major Version Number=100
Minor Version Number=5
'@
                }

                It 'Should return the template name when there is a display name' {
                    Get-CertificateTemplateName -Certificate $testCertificateWithAltTemplate | Should -Be 'WebServer'
                }
            }

            Context 'When a certificate with no template name is used' {
                It 'Should return null' {
                    Get-CertificateTemplateName -Certificate $testCertificateWithoutSan | Should -BeNullOrEmpty
                }
            }
        }

        Describe "$DSCResourceName\Get-CertificateSan" {
            Context 'When a certificate with a SAN is used' {
                It 'Should return the SAN' {
                    Get-CertificateSan -Certificate $testCertificate | Should -Be 'firstsan'
                }
            }

            Context 'When a certificate without SAN is used' {
                It 'Should return null' {
                    Get-CertificateSan -Certificate $testCertificateWithoutSan | Should -BeNullOrEmpty
                }
            }
        }
        Describe 'Test-CommandExists' {
            $testCommandName = 'TestCommandName'

            Mock -CommandName 'Get-Command' -MockWith { return $Name }

            Context 'When Get-Command returns' {
                It 'Should not throw' {
                    { $null = Test-CommandExists -Name $testCommandName } | Should -Not -Throw
                }

                It 'Should retrieve the command with the specified name' {
                    $getCommandParameterFilter = {
                        return $Name -eq $testCommandName
                    }

                    Assert-MockCalled -CommandName 'Get-Command' -ParameterFilter $getCommandParameterFilter -Exactly 1 -Scope 'Context'
                }

                It 'Should return true' {
                    Test-CommandExists -Name $testCommandName | Should -Be $true
                }
            }

            Context 'When Get-Command returns null' {
                Mock -CommandName 'Get-Command' -MockWith { return $null }

                It 'Should not throw' {
                    { $null = Test-CommandExists -Name $testCommandName } | Should -Not -Throw
                }

                It 'Should retrieve the command with the specified name' {
                    $getCommandParameterFilter = {
                        return $Name -eq $testCommandName
                    }

                    Assert-MockCalled -CommandName 'Get-Command' -ParameterFilter $getCommandParameterFilter -Exactly 1 -Scope 'Context'
                }

                It 'Should return false' {
                    Test-CommandExists -Name $testCommandName | Should -Be $false
                }
            }
        }

        Describe 'Get-CertificateStorePath' {
            Context 'When Get-CertificateStorePath called with Store and Location' {
                It 'Should not throw' {
                    { $script:getCertificateStorePathResult = Get-CertificateStorePath -Location 'LocalMachine' -Store 'TestStore' } | Should -Not -Throw
                }

                It 'Should return the expected path' {
                    $script:getCertificateStorePathResult = 'Cert:\TestLocation\TestStore'
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
