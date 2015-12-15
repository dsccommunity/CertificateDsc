<#
.Summary
    Tests for xCertificateImport
#>


$moduleName = ($PSCommandPath | Split-Path -Leaf) -replace '\..*$',''
Import-Module ($PSScriptRoot | Split-Path -Parent | Join-Path -ChildPath DSCResources | Join-Path -ChildPath $moduleName | Join-Path -ChildPath "$moduleName.psm1") -DisableNameChecking -Force

InModuleScope $moduleName {
    $invalidThumbprint = 'Zebra'
    $validThumbprint = (
        [System.AppDomain]::CurrentDomain.GetAssemblies().GetTypes() | Where-Object {
            $_.BaseType.BaseType -eq [System.Security.Cryptography.HashAlgorithm] -and
            $_.Name -cmatch 'Managed$'
        } | Select-Object -First 1 | ForEach-Object { 
            (New-Object $_).ComputeHash([String]::Empty) | ForEach-Object {
                '{0:x2}' -f $_
            }
        }
    ) -join ''

    $testFile = 'test.cer'

    $invalidPath = 'TestDrive:'
    $validPath = "TestDrive:\$testFile"
    
    Describe 'Validate-CertificatePath' {

        $null | Set-Content -Path $validPath

        Context 'a single existing file by parameter' {
            $result = Validate-CertificatePath -Path $validPath
            It 'should return true' {
                ($result -is [bool]) | Should Be $true
                $result | Should Be $true
            }
        }
        Context 'a single missing file by parameter' {
            It 'should throw an exception' {
                # directories are not valid
                { Validate-CertificatePath -Path $invalidPath } | Should Throw
            }
        }
        Context 'a single missing file by parameter with -Quiet' {
            $result = Validate-CertificatePath -Path $invalidPath -Quiet
            It 'should return false' {
                ($result -is [bool]) | Should Be $true
                $result | Should Be $false
            }
        }
        Context 'a single existing file by pipeline' {
            $result = $validPath | Validate-CertificatePath
            It 'should return true' {
                ($result -is [bool]) | Should Be $true
                $result | Should Be $true
            }
        }
        Context 'a single missing file by pipeline' {
            It 'should throw an exception' {
                # directories are not valid
                { $invalidPath | Validate-CertificatePath } | Should Throw
            }
        }
        Context 'a single missing file by pipeline with -Quiet' {
            $result =  $invalidPath | Validate-CertificatePath -Quiet
            It 'should return false' {
                ($result -is [bool]) | Should Be $true
                $result | Should Be $false
            }
        }
    }
    Describe 'Validate-Thumbprint' {

        Context 'a single valid thumbrpint by parameter' {
            $result = Validate-Thumbprint -Thumbprint $validThumbprint
            It 'should return true' {
                ($result -is [bool]) | Should Be $true
                $result | Should Be $true
            }
        }
        Context 'a single invalid thumbprint by parameter' {
            It 'should throw an exception' {
                # directories are not valid
                { Validate-Thumbprint -Thumbprint $invalidThumbprint } | Should Throw
            }
        }
        Context 'a single invalid thumbprint by parameter with -Quiet' {
            $result = Validate-Thumbprint $invalidThumbprint -Quiet
            It 'should return false' {
                ($result -is [bool]) | Should Be $true
                $result | Should Be $false
            }
        }
        Context 'a single valid thumbprint by pipeline' {
            $result = $validThumbprint | Validate-Thumbprint
            It 'should return true' {
                ($result -is [bool]) | Should Be $true
                $result | Should Be $true
            }
        }
        Context 'a single invalid thumborint by pipeline' {
            It 'should throw an exception' {
                # directories are not valid
                { $invalidThumbprint | Validate-Thumbprint } | Should Throw
            }
        }
        Context 'a single invalid thumbprint by pipeline with -Quiet' {
            $result =  $invalidThumbprint | Validate-Thumbprint -Quiet
            It 'should return false' {
                ($result -is [bool]) | Should Be $true
                $result | Should Be $false
            }
        }
    }
    Describe 'Get-TargetResource' {
        $null | Set-Content -Path $validPath

        $result = Get-TargetResource -Thumbprint $validThumbprint -Path $validPath
        It 'should return a hashtable' {
            ($result -is [hashtable]) | Should Be $true
        }
        It 'should contain the input values' {
            $result.Thumbprint | Should BeExactly $validThumbprint
            $result.Path | Should BeExactly $validPath
        }
    }
    Describe 'Test-TargetResource' {
        $null | Set-Content -Path $validPath

        It 'should return a bool' {
            ((Test-TargetResource -Thumbprint $validThumbprint -Path $validPath) -is [bool]) | Should Be $true
        }
    }
    Describe 'Set-TargetResource' {
        $null | Set-Content -Path $validPath
        
        Mock Import-Certificate {} -Verifiable

        Set-TargetResource -Thumbprint $validThumbprint -Path $validPath -Store "My" -Location LocalMachine
        
        It 'calls Import-Certificate' {
            Assert-VerifiableMocks
        }
        It 'uses the parameters supplied' {
            Assert-MockCalled Import-Certificate -Exactly -Times 1 -ParameterFilter {
                $CertStoreLocation -eq "Cert:\LocalMachine\My" -and
                $FilePath -eq $validPath
            }
        }
    }
}