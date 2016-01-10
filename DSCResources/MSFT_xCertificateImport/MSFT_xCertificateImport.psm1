#Requires -Version 4.0

<#
.SYNOPSIS
    Validates the existence of a file at a specific path.

.PARAMETER Path
    The location of the file. Supports any path that Test-Path supports.

.PARAMETER Quiet
    Returns $false if the file does not exist. By default this function throws an exception if the file is missing.

.EXAMPLE
    Validate-CertificatePath -Path '\\server\share\Certificates\mycert.cer'

.EXAMPLE
    Validate-CertificatePath -Path 'C:\certs\my_missing.cer' -Quiet

.EXAMPLE
    'D:\CertRepo\a_cert.cer' | Validate-CertificatePath

.EXAMPLE
    Get-ChildItem D:\CertRepo\*.cer | Validate-CertificatePath
#>
function Validate-CertificatePath 
{
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipeline
        )]
        [String[]]
        $Path ,

        [Parameter()]
        [Switch]
        $Quiet
    )

    Process 
    {
        foreach($p in $Path) 
        {
            if ($p | Test-Path -PathType Leaf) 
            {
                $true
            } 
            elseif ($Quiet) 
            {
                $false
            } 
            else 
            {
                throw [System.ArgumentException]"File '$p' not found."
            } 
        }
    }
}

<#
.SYNOPSIS
    Validates whether a given certificate is valid based on the hash algoritms available on the system.

.PARAMETER Thumbprint
    One or more thumbprints to validate.

.PARAMETER Quiet
    Returns $false if the thumbprint is not valid. By default this function throws an exception if validation fails.

.EXAMPLE
    Validate-Thumbprint fd94e3a5a7991cb6ed3cd5dd01045edf7e2284de

.EXAMPLE
    Validate-Thumbprint fd94e3a5a7991cb6ed3cd5dd01045edf7e2284de,0000e3a5a7991cb6ed3cd5dd01045edf7e220000 -Quiet

.EXAMPLE
    gci Cert:\LocalMachine -Recurse | ? { $_.Thumbprint } | select -exp Thumbprint | Validate-Thumbprint -Verbose
#>
function Validate-Thumbprint 
{
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipeline
        )]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Thumbprint ,

        [Parameter()]
        [Switch]
        $Quiet
    )

    Begin 
    {
        $validHashes = [System.AppDomain]::CurrentDomain.GetAssemblies().GetTypes() | Where-Object {
            $_.BaseType.BaseType -eq [System.Security.Cryptography.HashAlgorithm] -and
            $_.Name -cmatch 'Managed$'
        } | ForEach-Object {
            New-Object PSObject -Property @{
                Hash = $_.BaseType.Name
                BitSize = (New-Object $_).HashSize
            } | Add-Member -MemberType ScriptProperty -Name HexLength -Value { 
                $this.BitSize / 4 
            } -PassThru
        }
    }

    Process 
    {
        foreach($hash in $Thumbprint) 
        {
            $isValid = $false

            foreach($algorithm in $validHashes)
            {
                if ($hash -cmatch "^[a-fA-F0-9]{$($algorithm.HexLength)}$")
                {
                    Write-Verbose -Message "'$hash' is a valid $($algorithm.Hash) hash."
                    $isValid = $true
                }
            }
            
            if ($Quiet -or $isValid)
            {
                $isValid
            }
            else
            {
                throw [System.ArgumentException]"'$hash' is not a valid hash."
            }
        }
    }
}

function Get-TargetResource 
{
    [CmdletBinding()]
    [OutputType([Hashtable])]
    param(
        [Parameter(
            Mandatory
        )]
        [ValidateScript( {
            $_ | Validate-Thumbprint
        } )]
        [String]
        $Thumbprint ,

        [Parameter(
            Mandatory
        )]
        [ValidateScript( {
            $_ | Validate-CertificatePath
        } )]
        [String]
        $Path ,

        [Parameter()]
        [ValidateSet(
             'LocalMachine'
        )]
        [String]
        $Location = 'LocalMachine' ,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [String]
        $Store = 'My'
    )

    @{
        Thumbprint = $Thumbprint
        Path = $Path
    }
}

function Test-TargetResource 
{
    [CmdletBinding()]
    [OutputType([Bool])]
    param(
        [Parameter(
            Mandatory
        )]
        [ValidateScript( {
            $_ | Validate-Thumbprint
        } )]
        [String]
        $Thumbprint ,

        [Parameter(
            Mandatory
        )]
        [ValidateScript( {
            $_ | Validate-CertificatePath
        } )]
        [String]
        $Path ,

        [Parameter()]
        [ValidateSet(
             'LocalMachine'
        )]
        [String]
        $Location = 'LocalMachine' ,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [String]
        $Store = 'My'
    )

    [Bool](
        'Cert:' | 
        Join-Path -ChildPath $Location | 
        Join-Path -ChildPath $Store | 
        Get-ChildItem | 
        Where-Object { $_.Thumbprint -ieq $Thumbprint }
     )
}

function Set-TargetResource 
{
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(
            Mandatory
        )]
        [ValidateScript( {
            $_ | Validate-Thumbprint
        } )]
        [String]
        $Thumbprint ,

        [Parameter(
            Mandatory
        )]
        [ValidateScript( {
            $_ | Validate-CertificatePath
        } )]
        [String]
        $Path ,

        [Parameter()]
        [ValidateSet(
             'LocalMachine'
        )]
        [String]
        $Location = 'LocalMachine' ,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [String]
        $Store = 'My'
    )

    $certPath = 'Cert:' | Join-Path -ChildPath $Location | Join-Path -ChildPath $Store
    if ($PSCmdlet.ShouldProcess("Importing certificate '$Path' into '$certPath'")) 
    {
        Import-Certificate -CertStoreLocation $certPath -FilePath $Path
    }
}

Export-ModuleMember *-TargetResource