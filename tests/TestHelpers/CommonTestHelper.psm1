<#
    .SYNOPSIS
        Returns an invalid argument exception object

    .PARAMETER Message
        The message explaining why this error is being thrown

    .PARAMETER ArgumentName
        The name of the invalid argument that is causing this error to be thrown
#>
function Get-InvalidArgumentRecord
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Message,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ArgumentName
    )

    $argumentException = New-Object -TypeName 'ArgumentException' -ArgumentList @( $Message,
        $ArgumentName )
    $newObjectParams = @{
        TypeName = 'System.Management.Automation.ErrorRecord'
        ArgumentList = @( $argumentException, $ArgumentName, 'InvalidArgument', $null )
    }
    return New-Object @newObjectParams
}

<#
    .SYNOPSIS
        Returns an invalid operation exception object

    .PARAMETER Message
        The message explaining why this error is being thrown

    .PARAMETER ErrorRecord
        The error record containing the exception that is causing this terminating error
#>
function Get-InvalidOperationRecord
{
    [CmdletBinding()]
    param
    (
        [ValidateNotNullOrEmpty()]
        [String]
        $Message,

        [ValidateNotNull()]
        [System.Management.Automation.ErrorRecord]
        $ErrorRecord
    )

    if ($null -eq $Message)
    {
        $invalidOperationException = New-Object -TypeName 'InvalidOperationException'
    }
    elseif ($null -eq $ErrorRecord)
    {
        $invalidOperationException =
        New-Object -TypeName 'InvalidOperationException' -ArgumentList @( $Message )
    }
    else
    {
        $invalidOperationException =
        New-Object -TypeName 'InvalidOperationException' -ArgumentList @( $Message,
            $ErrorRecord.Exception )
    }

    $newObjectParams = @{
        TypeName = 'System.Management.Automation.ErrorRecord'
        ArgumentList = @( $invalidOperationException.ToString(), 'MachineStateIncorrect',
            'InvalidOperation', $null )
    }
    return New-Object @newObjectParams
}


<#
    .SYNOPSIS
        Generates a valid certificate thumprint for use in testing

    .PARAMETER Fips
        Returns a certificate thumbprint that is FIPS compliant.
#>
function New-CertificateThumbprint
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter()]
        [switch]
        $Fips
    )

    # To ensure the FIPS hash algorithms are loaded by .NET Core load the assembly
    if ($IsCoreCLR)
    {
        Add-Type -AssemblyName System.Security.Cryptography.Csp
    }

    <#
        Get a list of Hash Providers, but exclude assemblies that set DefinedTypes
        to null instead of an empty array. Otherwise, the call to GetTypes() fails.
    #>
    $allRuntimeTypes = ([System.AppDomain]::CurrentDomain.GetAssemblies() |
        Where-Object -FilterScript {
            $null -ne $_.DefinedTypes
        }).GetTypes()

    if ($Fips)
    {
        # This thumbprint is valid for FIPS
        $validThumbprint = (
            $allRuntimeTypes | Where-Object -FilterScript {
                $_.BaseType.BaseType -eq [System.Security.Cryptography.HashAlgorithm] -and
                ($_.Name -cmatch 'Provider$' -and $_.Name -cnotmatch 'MD5')
            } | Select-Object -First 1 | ForEach-Object -Process {
                (New-Object -TypeName $_).ComputeHash([System.String]::Empty) | ForEach-Object -Process {
                    '{0:x2}' -f $_
                }
            }
        ) -join ''
    }
    else
    {
        # This thumbprint is valid (but not FIPS valid)
        $validThumbprint = (
            $allRuntimeTypes | Where-Object -FilterScript {
                $_.BaseType.BaseType -eq [System.Security.Cryptography.HashAlgorithm] -and
                ($_.Name -cmatch 'Managed$' -or $_.Name -cmatch 'Provider$')
            } | Select-Object -First 1 | ForEach-Object -Process {
                (New-Object -TypeName $_).ComputeHash([System.String]::Empty) | ForEach-Object -Process {
                    '{0:x2}' -f $_
                }
            }
        ) -join ''
    }

    return $validThumbprint
}

Export-ModuleMember -Function `
    New-CertificateThumbprint, `
    Get-InvalidArgumentRecord, `
    Get-InvalidOperationRecord
