$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'
Import-Module -Name (Join-Path -Path $modulePath -ChildPath 'DscResource.Common')

# Import Localization Strings
$script:localizedData = Get-LocalizedData -DefaultUICulture 'en-US'

$script:supportedHashAlgorithms = $null

<#
    .SYNOPSIS
        Validates the existence of a file at a specific path.

    .PARAMETER Path
        The location of the file. Supports any path that Test-Path supports.

    .PARAMETER Quiet
        Returns $false if the file does not exist. By default this function throws
        an exception if the file is missing.

    .EXAMPLE
        Test-CertificatePath -Path '\\server\share\Certificates\mycert.cer'

    .EXAMPLE
        Test-CertificatePath -Path 'C:\certs\my_missing.cer' -Quiet

    .EXAMPLE
        'D:\CertRepo\a_cert.cer' | Test-CertificatePath

    .EXAMPLE
        Get-ChildItem -Path D:\CertRepo\*.cer |
            Test-CertificatePath
#>
function Test-CertificatePath
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline)]
        [System.String[]]
        $Path,

        [Parameter()]
        [Switch]
        $Quiet
    )

    process
    {
        foreach ($pathNode in $Path)
        {
            if ($pathNode | Test-Path -PathType Leaf)
            {
                $true
            }
            elseif ($Quiet)
            {
                $false
            }
            else
            {
                New-InvalidArgumentException `
                    -Message ($script:localizedData.FileNotFoundError -f $pathNode) `
                    -ArgumentName 'Path'
            }
        }
    }
} # end function Test-CertificatePath

<#
    .SYNOPSIS
        This function clears the script variable supportedHashAlgorithms. It is
        just used as by tests and not any of the resources.

    .EXAMPLE
        Clear-SupportedHashAlgorithmCache
#>
function Clear-SupportedHashAlgorithmCache
{
    [CmdletBinding()]
    param ()

    Write-Verbose -Message ($script:localizedData.ClearingSupportedHashAlgorithmsCache)

    $script:supportedHashAlgorithms = $null
}

<#
    .SYNOPSIS
        Returns an array of supported hash algorithms and sizes and caches it in the
        script variable supportedHashAlgorithms to increase performance.

    .EXAMPLE
        Get-SupportedHashAlgorithms
#>
function Get-SupportedHashAlgorithms
{
    [CmdletBinding()]
    [OutputType([System.Collections.ArrayList])]
    param ()

    if ($null -eq $script:supportedHashAlgorithms)
    {
        # Get FIPS registry key
        $fips = [System.Int32] (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy' -ErrorAction SilentlyContinue).Enabled

        Write-Verbose -Message ($script:localizedData.GettingAssemblyListForHashAlgorithms)

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

        if ($fips -eq $true)
        {
            Write-Verbose -Message ($script:localizedData.FindingSupportedFipsHashAlgorithms)

            # Support only FIPS compliant Hash Algorithms
            $supportedHashProviders = $allRuntimeTypes | Where-Object -FilterScript {
                $_.BaseType.BaseType -eq [System.Security.Cryptography.HashAlgorithm] -and
                ($_.Name -cmatch 'Provider$' -and $_.Name -cnotmatch 'MD5')
            }
        }
        else
        {
            Write-Verbose -Message ($script:localizedData.FindingSupportedHashAlgorithms)

            $supportedHashProviders = $allRuntimeTypes | Where-Object -FilterScript {
                $_.BaseType.BaseType -eq [System.Security.Cryptography.HashAlgorithm] -and
                ($_.Name -cmatch 'Managed$' -or $_.Name -cmatch 'Provider$')
            }
        }

        # Get a list of all Valid Hash types and lengths into an array list
        $supportedHashAlgorithms = New-Object -TypeName System.Collections.ArrayList

        Write-Verbose -Message ($script:localizedData.GeneratingSupportedHashAlgorithmsArray -f $supportedHashProviders.Count)

        foreach ($supportedHashProvider in $supportedHashProviders)
        {
            $bitSize = (New-Object -TypeName $supportedHashProvider).HashSize
            $validHash = New-Object `
                -TypeName PSObject `
                -Property @{
                    Hash      = $supportedHashProvider.BaseType.Name
                    BitSize   = $bitSize
                    HexLength = $bitSize / 4
                }
            $null = $supportedHashAlgorithms.Add($validHash)
        }

        Write-Verbose -Message ($script:localizedData.SettingSupportedHashAlgorithmsCache)

        $script:supportedHashAlgorithms = $supportedHashAlgorithms
    }

    return $script:supportedHashAlgorithms
}

<#
    .SYNOPSIS
        Validates whether a given certificate is valid based on the hash algoritms available on the
        system.

    .PARAMETER Thumbprint
        One or more thumbprints to Test.

    .PARAMETER Quiet
        Returns $false if the thumbprint is not valid. By default this function throws an exception if
        validation fails.

    .EXAMPLE
        Test-Thumbprint `
            -Thumbprint fd94e3a5a7991cb6ed3cd5dd01045edf7e2284de

    .EXAMPLE
        Test-Thumbprint `
            -Thumbprint fd94e3a5a7991cb6ed3cd5dd01045edf7e2284de,0000e3a5a7991cb6ed3cd5dd01045edf7e220000 `
            -Quiet

    .EXAMPLE
        Get-ChildItem -Path Cert:\LocalMachine -Recurse |
            Where-Object -FilterScript { $_.Thumbprint } |
            Select-Object -Expression Thumbprint |
            Test-Thumbprint -Verbose
#>
function Test-Thumbprint
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $Thumbprint,

        [Parameter()]
        [Switch]
        $Quiet
    )

    begin
    {
        $validHashAlgorithms = Get-SupportedHashAlgorithms
    }

    process
    {
        foreach ($hash in $Thumbprint)
        {
            $isValid = $false

            foreach ($algorithm in $validHashAlgorithms)
            {
                if ($hash -cmatch "^[a-fA-F0-9]{$($algorithm.HexLength)}$")
                {
                    $isValid = $true
                }
            }

            if ($Quiet -or $isValid)
            {
                $isValid
            }
            else
            {
                New-InvalidOperationException `
                    -Message ($script:localizedData.InvalidHashError -f $hash)
            }
        }
    }
} # end function [System.DateTime]mbprint

<#
    .SYNOPSIS
        Locates one or more certificates using the passed certificate selector parameters.

        If more than one certificate is found matching the selector criteria, they will be
        returned in order of descending expiration date.

    .PARAMETER Thumbprint
        The thumbprint of the certificate to find.

    .PARAMETER FriendlyName
        The friendly name of the certificate to find.

    .PARAMETER Subject
        The subject of the certificate to find.

    .PARAMETER DNSName
        The subject alternative name of the certificate to export must contain these values.

    .PARAMETER Issuer
        The issuer of the certificate to find.

    .PARAMETER KeyUsage
        The key usage of the certificate to find must contain these values.

    .PARAMETER EnhancedKeyUsage
        The enhanced key usage of the certificate to find must contain these values.

    .PARAMETER Store
        The Windows Certificate Store Name to search for the certificate in.
        Defaults to 'My'.

    .PARAMETER AllowExpired
        Allows expired certificates to be returned.
#>
function Find-Certificate
{
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2[]])]
    param
    (
        [Parameter()]
        [System.String]
        $Thumbprint,

        [Parameter()]
        [System.String]
        $FriendlyName,

        [Parameter()]
        [System.String]
        $Subject,

        [Parameter()]
        [System.String[]]
        $DNSName,

        [Parameter()]
        [System.String]
        $Issuer,

        [Parameter()]
        [System.String[]]
        $KeyUsage,

        [Parameter()]
        [System.String[]]
        $EnhancedKeyUsage,

        [Parameter()]
        [System.String]
        $Store = 'My',

        [Parameter()]
        [Boolean]
        $AllowExpired = $false
    )

    $certPath = Join-Path -Path 'Cert:\LocalMachine' -ChildPath $Store

    if (-not (Test-Path -Path $certPath))
    {
        # The Certificte Path is not valid
        New-InvalidArgumentException `
            -Message ($script:localizedData.CertificatePathError -f $certPath) `
            -ArgumentName 'Store'
    } # if

    # Assemble the filter to use to select the certificate
    $certFilters = @()

    if ($PSBoundParameters.ContainsKey('Thumbprint'))
    {
        $certFilters += @('($_.Thumbprint -eq $Thumbprint)')
    } # if

    if ($PSBoundParameters.ContainsKey('FriendlyName'))
    {
        $certFilters += @('($_.FriendlyName -eq $FriendlyName)')
    } # if

    if ($PSBoundParameters.ContainsKey('Subject'))
    {
        $certFilters += @('($_.Subject -eq $Subject)')
    } # if

    if ($PSBoundParameters.ContainsKey('Issuer'))
    {
        $certFilters += @('($_.Issuer -eq $Issuer)')
    } # if

    if (-not $AllowExpired)
    {
        $certFilters += @('(((Get-Date) -le $_.NotAfter) -and ((Get-Date) -ge $_.NotBefore))')
    } # if

    if ($PSBoundParameters.ContainsKey('DNSName'))
    {
        $certFilters += @('(@(Compare-Object -ReferenceObject $_.DNSNameList.Unicode -DifferenceObject $DNSName | Where-Object -Property SideIndicator -eq "=>").Count -eq 0)')
    } # if

    if ($PSBoundParameters.ContainsKey('KeyUsage'))
    {
        $certFilters += @('(@(Compare-Object -ReferenceObject ($_.Extensions.KeyUsages -split ", ") -DifferenceObject $KeyUsage | Where-Object -Property SideIndicator -eq "=>").Count -eq 0)')
    } # if

    if ($PSBoundParameters.ContainsKey('EnhancedKeyUsage'))
    {
        $certFilters += @('(@(Compare-Object -ReferenceObject ($_.EnhancedKeyUsageList.FriendlyName) -DifferenceObject $EnhancedKeyUsage | Where-Object -Property SideIndicator -eq "=>").Count -eq 0)')
    } # if

    # Join all the filters together
    $certFilterScript = '(' + ($certFilters -join ' -and ') + ')'

    Write-Verbose `
        -Message ($script:localizedData.SearchingForCertificateUsingFilters -f $store, $certFilterScript) `
        -Verbose

    $certs = Get-ChildItem -Path $certPath |
        Where-Object -FilterScript ([ScriptBlock]::Create($certFilterScript))

    # Sort the certificates
    if ($certs.count -gt 1)
    {
        $certs = $certs | Sort-Object -Descending -Property 'NotAfter'
    } # if

    return $certs
} # end function Find-Certificate

<#
    .SYNOPSIS
        Get CDP container.

    .DESCRIPTION
        Gets the configuration data partition from the active directory configuration
        naming context.

    .PARAMETER DomainName
        The domain name.
#>
function Get-CdpContainer
{
    [cmdletBinding()]
    [OutputType([psobject])]
    param
    (
        [Parameter()]
        [System.String]
        $DomainName
    )

    if (-not $DomainName)
    {
        $configContext = ([ADSI]'LDAP://RootDSE').configurationNamingContext

        if (-not $configContext)
        {
            # The computer is not domain joined
            New-InvalidOperationException `
                -Message ($script:localizedData.DomainNotJoinedError)
        }
    }
    else
    {
        $ctx = New-Object -TypeName System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $DomainName)
        $configContext = 'CN=Configuration,{0}' -f ([System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($ctx).GetDirectoryEntry().distinguishedName[0])
    }

    Write-Verbose `
        -Message ($script:localizedData.ConfigurationNamingContext -f $configContext.toString()) `
        -Verbose

    $cdpContainer = [ADSI]('LDAP://CN=CDP,CN=Public Key Services,CN=Services,{0}' -f $configContext.toString())

    return $cdpContainer
} # end function Get-CdpContainer

<#
    .SYNOPSIS
        Automatically locate a certificate authority in Active Directory

    .DESCRIPTION
        Automatically locates a certificate autority in Active Directory environments
        by leveraging ADSI to look inside the container CDP and subsequently trying to
        certutil -ping every located CA until one is found.

    .PARAMETER DomainName
        The domain name of the domain that will be used to locate the CA. Can be left
        empty to use the current domain.
#>
function Find-CertificateAuthority
{
    [cmdletBinding()]
    [OutputType([System.Management.Automation.PSObject])]
    param
    (
        [Parameter()]
        [System.String]
        $DomainName
    )

    Write-Verbose `
        -Message ($script:localizedData.StartLocateCAMessage) `
        -Verbose

    $cdpContainer = Get-CdpContainer @PSBoundParameters -ErrorAction Stop

    $caFound = $false

    foreach ($item in $cdpContainer.Children)
    {
        if (-not $caFound)
        {
            $caServerFQDN = ($item.distinguishedName -split '=|,')[1]
            $caRootName = ($item.Children.distinguishedName -split '=|,')[1]

            $certificateAuthority = [PSObject] @{
                CARootName   = $caRootName
                CAServerFQDN = $caServerFQDN
            }

            if (Test-CertificateAuthority `
                    -CARootName $caRootName `
                    -CAServerFQDN $caServerFQDN)
            {
                $caFound = $true
                break
            }
        }
    }

    if ($caFound)
    {
        Write-Verbose `
            -Message ($script:localizedData.CaFoundMessage -f $certificateAuthority.CAServerFQDN, $certificateAuthority.CARootName) `
            -Verbose

        return $certificateAuthority
    }
    else
    {
        New-InvalidOperationException `
            -Message ($script:localizedData.NoCaFoundError)
    }
} # end function Find-CertificateAuthority

<#
    .SYNOPSIS
        Wraps a single ADSI command to get the domain naming context so it can be mocked.
#>
function Get-DirectoryEntry
{
    [CmdletBinding()]
    param ()

    return ([adsi] 'LDAP://RootDSE').Get('rootDomainNamingContext')
}

<#
    .SYNOPSIS
        Test to see if the specified ADCS CA is available.

    .PARAMETER CAServerFQDN
        The FQDN of the ADCS CA to test for availability.

    .PARAMETER CARootName
        The name of the ADCS CA to test for availability.
#>
function Test-CertificateAuthority
{
    [cmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter()]
        [System.String]
        $CAServerFQDN,

        [Parameter()]
        [System.String]
        $CARootName
    )

    Write-Verbose `
        -Message ($script:localizedData.StartPingCAMessage) `
        -Verbose

    $locatorInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
    $locatorInfo.FileName = 'certutil.exe'
    $locatorInfo.Arguments = ('-ping "{0}\{1}"' -f $CAServerFQDN, $CARootName)

    # Certutil does not make use of standard error stream
    $locatorInfo.RedirectStandardError = $false
    $locatorInfo.RedirectStandardOutput = $true
    $locatorInfo.UseShellExecute = $false
    $locatorInfo.CreateNoWindow = $true

    $locatorProcess = New-Object -TypeName System.Diagnostics.Process
    $locatorProcess.StartInfo = $locatorInfo

    $null = $locatorProcess.Start()
    $locatorOut = $locatorProcess.StandardOutput.ReadToEnd()
    $null = $locatorProcess.WaitForExit()

    Write-Verbose `
        -Message ($script:localizedData.CaPingMessage -f $locatorProcess.ExitCode, $locatorOut) `
        -Verbose

    if ($locatorProcess.ExitCode -eq 0)
    {
        Write-Verbose `
            -Message ($script:localizedData.CaOnlineMessage -f $CAServerFQDN, $CARootName) `
            -Verbose

        return $true
    }
    else
    {
        Write-Verbose `
            -Message ($script:localizedData.CaOfflineMessage -f $CAServerFQDN, $CARootName) `
            -Verbose

        return $false
    }
} # end function Test-CertificateAuthority

<#
    .SYNOPSIS
        Get certificate template names from Active Directory for x509 certificates.

    .DESCRIPTION
        Gets the certificate templates from Active Directory by using a
        DirectorySearcher object to find all objects with an objectClass
        of pKICertificateTemplate from the search root of
        CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration

    .NOTES
        The domain variable is populated based on the domain of the user running the
        function. When run as System this will return the domain of computer.
        Normally this won't make any difference unless the user is from a foreign
        domain.
#>
function Get-CertificateTemplatesFromActiveDirectory
{
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param ()

    try
    {
        $domain   = Get-DirectoryEntry
        $searcher = New-Object -TypeName DirectoryServices.DirectorySearcher

        $searcher.Filter     = '(objectclass=pKICertificateTemplate)'
        $searcher.SearchRoot = 'LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{0}' -f $domain

        $searchResults = $searcher.FindAll()
    }
    catch
    {
        Write-Verbose -Message $_.Exception.Message
        Write-Warning -Message $script:localizedData.ActiveDirectoryTemplateSearch
    }

    $adTemplates = @()

    foreach ($searchResult in $searchResults)
    {
        $templateData = @{}
        $properties   =  New-Object -TypeName Object[] -ArgumentList $searchResult.Properties.Count

        $searchResult.Properties.CopyTo($properties, 0)
        $properties.ForEach({
            $templateData[$_.Name] = ($_.Value | Out-String).Trim()
        })

        $adTemplates += [PSCustomObject] $templateData
    }

    return $adTemplates
}

<#
    .SYNOPSIS
        Gets information about the certificate template.

    .DESCRIPTION
        This function returns the information about the certificate template by retreiving
        the available templates from Active Directory and matching the formatted certificate
        template name against this list.
        In addition to the template name the display name, template OID, the major version
        and minor version is also returned.

    .PARAMETER FormattedTemplate
        The text from the certificate template extension, retrieved from
        Get-CertificateTemplateText.
#>
function Get-CertificateTemplateInformation
{
    [OutputType([PSCustomObject])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $FormattedTemplate
    )

    $templateInformation = @{}

    switch -Regex ($FormattedTemplate)
    {
        <#
            Example of the certificate extension template text

            Template=Display Name 1(1.3.6.1.4.1.311.21.8.5734392.6195358.14893705.12992936.3444946.62.3384218.1234567)
            Major Version Number=100
            Minor Version Number=5

            If the Display Name of the template has not been found then FormattedText would like something like this.

            Template=1.3.6.1.4.1.311.21.8.5734392.6195358.14893705.12992936.3444946.62.3384218.1234567
            Major Version Number=100
            Minor Version Number=5

            The Name of the template is found by matching the OID or the Display Name against the list of temples in AD.
        #>

        'Template=(?:(?<DisplayName>.+)\((?<Oid>[\d.]+)\))|(?<Oid>[\d.]+)\s*Major\sVersion\sNumber=(?<MajorVersion>\d+)\s*Minor\sVersion\sNumber=(?<MinorVersion>\d+)'
        {
            [Array] $adTemplates = Get-CertificateTemplatesFromActiveDirectory

            if ([System.String]::IsNullOrEmpty($Matches.DisplayName))
            {
                $template = $adTemplates.Where({
                    $_.'msPKI-Cert-Template-OID' -eq $Matches.Oid
                })

                $Matches['DisplayName'] = $template.DisplayName
            }
            else
            {
                $template = $adTemplates.Where({
                    $_.'DisplayName' -eq $Matches.DisplayName
                })
            }

            $Matches['Name'] = $template.Name

            if ($template.Count -eq 0)
            {
                Write-Warning -Message ($script:localizedData.TemplateNameResolutionError -f ('{0}({1})' -f $Matches.DisplayName, $Matches.Oid))
            }

            $templateInformation['Name']         = $Matches.Name
            $templateInformation['DisplayName']  = $Matches.DisplayName
            $templateInformation['Oid']          = $Matches.Oid
            $templateInformation['MajorVersion'] = $Matches.MajorVersion
            $templateInformation['MinorVersion'] = $Matches.MinorVersion
        }

        # The certificate extension template text just contains the name of the template so return that.

        '^(?<TemplateName>\w+)\s?$'
        {
            $templateInformation['Name'] = $Matches.TemplateName
        }

        default
        {
            Write-Warning -Message ($script:localizedData.TemplateNameNotFound -f $FormattedTemplate)
        }
    }

    return [PSCustomObject] $templateInformation
}

<#
    .SYNOPSIS
        Returns one or more matching extensions matching the requested Oid.

    .DESCRIPTION
        This function finds all extensions matching one of the specified Oid values
        and returns one or more of them.

    .PARAMETER Certificate
        The X509 certificate to return the extensions from.

    .PARAMETER Oid
        The list of Oid's to extract extensions from.

    .PARAMETER First
        The number of matching extensions to return.
#>
function Get-CertificateExtension
{
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Extension[]])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Object]
        $Certificate,

        [Parameter(Mandatory = $true)]
        [System.String[]]
        $Oid,

        [Parameter()]
        [System.Int32]
        $First = 1
    )

    $extensions = $certificate.Extensions | Where-Object -FilterScript {
        $_.Oid.value -in $Oid
    } | Select-Object -First $First

    return $extensions
}

<#
    .SYNOPSIS
        Gets the formatted text output from an X509 certificate template extension.

    .DESCRIPTION
        Looks up the extensions with either the Oid "1.3.6.1.4.1.311.21.7" or
        "1.3.6.1.4.1.311.20.2" and returns the formatted extension value.

    .PARAMETER Certificate
        The x509 certificate to return the template extension from.
#>
function Get-CertificateTemplateExtensionText
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate
    )

    $templateOidNames = '1.3.6.1.4.1.311.21.7', '1.3.6.1.4.1.311.20.2'
    $firstTemplateExtension = Get-CertificateExtension @PSBoundParameters `
        -Oid $templateOidNames

    if ($null -ne $firstTemplateExtension)
    {
        return $firstTemplateExtension.Format($true)
    }
}

<#
    .SYNOPSIS
        Get a certificate template name from an x509 certificate.

    .DESCRIPTION
        Gets the name of the template used for the certificate that is passed to
        this cmdlet by translating the OIDs "1.3.6.1.4.1.311.21.7" or
        "1.3.6.1.4.1.311.20.2".

    .PARAMETER Certificate
        The x509 certificate to return the formatted template extension from.
#>
function Get-CertificateTemplateName
{
    [cmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Object]
        $Certificate
    )

    if ($Certificate -isnot [System.Security.Cryptography.X509Certificates.X509Certificate2])
    {
        return
    }

    $templateExtensionText = Get-CertificateTemplateExtensionText @PSBoundParameters

    if ($null -ne $templateExtensionText)
    {
        return Get-CertificateTemplateInformation -FormattedTemplate $templateExtensionText |
            Select-Object -ExpandProperty Name
    }
}

<#
    .SYNOPSIS
        Get the first Subject Alternative Name entry for a certificate.

    .DESCRIPTION
        Gets the first entry in the Subject Alternative Name extension from the
        certificate provided.

    .PARAMETER Certificate
        The certificate to return the Subject Alternative Name from.
#>
function Get-CertificateSubjectAlternativeName
{
    [cmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Object]
        $Certificate
    )

    if ($Certificate -isnot [System.Security.Cryptography.X509Certificates.X509Certificate2])
    {
        return
    }

    $list = Get-CertificateSubjectAlternativeNameList -Certificate $Certificate

    if ($null -ne $list)
    {
        $firstSubjectAlternativeName = Get-CertificateSubjectAlternativeNameList -Certificate $Certificate |
            Select-Object -First 1

        return $firstSubjectAlternativeName.Split('=')[1]
    }
}

<#
    .SYNOPSIS
        Get the list of Subject Alternative Name entries in a Certificate.

    .DESCRIPTION
        Gets the list of Subject Alternative Name entries in the extension
        with Oid 2.5.29.17 from the certificate provided.

    .PARAMETER Certificate
        The certificate to return the Subject Alternative Name entry list from.
#>
function Get-CertificateSubjectAlternativeNameList
{
    [cmdletBinding()]
    [OutputType([System.String[]])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Object]
        $Certificate
    )

    $subjectAlternateNameExtensions = Get-CertificateExtension -Certificate $Certificate -Oid '2.5.29.17'
    $subjectAlternateNames = @()

    if ($null -ne $subjectAlternateNameExtensions)
    {
        $subjectAlternateNames = ($subjectAlternateNameExtensions.Format($false) -split ',').Trim()
    }

    return $subjectAlternateNames
}

<#
    .SYNOPSIS
        Tests whether or not the command with the specified name exists.

    .PARAMETER Name
        The name of the command to test for.
#>
function Test-CommandExists
{
    [OutputType([System.Boolean])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Name
    )

    $command = Get-Command -Name $Name -ErrorAction 'SilentlyContinue'
    return ($null -ne $command)
}

<#
    .SYNOPSIS
        This function imports a 509 public key certificate to the specific Store.

    .PARAMETER FilePath
        The path to the certificate file to import.

    .PARAMETER Base64Content
        The base64 content of the certificate file to import.

    .PARAMETER CertStoreLocation
        The Certificate Store and Location Path to import the certificate to.
#>
function Import-CertificateEx
{
    [CmdletBinding()]
    param
    (
        [Parameter(ParameterSetName = 'Path', Mandatory = $true)]
        [System.String]
        $FilePath,

        [Parameter(ParameterSetName = 'Content', Mandatory = $true)]
        [System.String]
        $Base64Content,

        [Parameter(Mandatory = $true)]
        [System.String]
        $CertStoreLocation
    )

    $location = Split-Path -Path (Split-Path -Path $CertStoreLocation -Parent) -Leaf
    $store = Split-Path -Path $CertStoreLocation -Leaf

    $cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2Collection

    if ($PSCmdlet.ParameterSetName -eq 'Path')
    {
        $certificateData = $FilePath
    }
    else
    {
        $certificateData = [Convert]::FromBase64String($Base64Content)
    }

    $cert.Import($certificateData)
    $certStore = New-Object `
        -TypeName System.Security.Cryptography.X509Certificates.X509Store `
        -ArgumentList ($store, $location)

    $certStore.Open('MaxAllowed')
    $certStore.AddRange($cert)
    $certStore.Close()
}

<#
    .SYNOPSIS
        This function imports a Pfx public - private certificate to the specific
        Certificate Store Location.

    .PARAMETER FilePath
        The path to the certificate file to import.

    .PARAMETER Base64Content
        The base64 content of the certificate file to import.

    .PARAMETER CertStoreLocation
        The Certificate Store and Location Path to import the certificate to.

    .PARAMETER Exportable
        The parameter controls if certificate will be able to export the private key.

    .PARAMETER Password
        The password that the certificate located at the FilePath needs to be imported.
  #>
function Import-PfxCertificateEx
{
    [CmdletBinding()]
    param
    (
        [Parameter(ParameterSetName = 'Path', Mandatory = $true)]
        [System.String]
        $FilePath,

        [Parameter(ParameterSetName = 'Content', Mandatory = $true)]
        [System.String]
        $Base64Content,

        [Parameter(Mandatory = $true)]
        [System.String]
        $CertStoreLocation,

        [Parameter()]
        [Switch]
        $Exportable,

        [Parameter()]
        [System.Security.SecureString]
        $Password
    )

    $location = Split-Path -Path (Split-Path -Path $CertStoreLocation -Parent) -Leaf
    $store = Split-Path -Path $CertStoreLocation -Leaf

    $cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2

    $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet

    if ($location -eq 'LocalMachine')
    {
        $flags = $flags -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet
    }
    else
    {
        $flags = $flags -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet
    }

    if ($PSCmdlet.ParameterSetName -eq 'Path')
    {
        $importDataValue = $FilePath
    }
    else
    {
        $importDataValue = [Convert]::FromBase64String($Base64Content)
    }

    if ($Exportable)
    {
        $flags = $flags -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
    }

    if ($Password)
    {
        $cert.Import($importDataValue, $Password, $flags)
    }
    else
    {
        $cert.Import($importDataValue, "", $flags)
    }

    $certStore = New-Object `
        -TypeName System.Security.Cryptography.X509Certificates.X509Store `
        -ArgumentList @($store, $location)

    $certStore.Open('MaxAllowed')
    $certStore.Add($cert)
    $certStore.Close()
}

<#
    .SYNOPSIS
        This function generates the path to a Windows Certificate Store.

    .PARAMETER Location
        The Windows Certificate Store Location.

    .PARAMETER Store
        The Windows Certificate Store Name.
#>
function Get-CertificateStorePath
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('CurrentUser', 'LocalMachine')]
        [System.String]
        $Location,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Store
    )

    $certificateStore =  'Cert:' |
        Join-Path -ChildPath $Location |
        Join-Path -ChildPath $Store

    if (-not (Test-Path -Path $certificateStore))
    {
        New-InvalidArgumentException `
            -Message ($script:localizedData.CertificateStoreNotFoundError -f $certificateStore) `
            -ArgumentName 'Store'
    }

    return $certificateStore
}

<#
    .SYNOPSIS
        This function returns the full path to a certificate in the Windows
        Certificate Store.

    .PARAMETER Thumbprint
        The Thumbprint of the certificate.

    .PARAMETER Location
        The Windows Certificate Store Location.

    .PARAMETER Store
        The Windows Certificate Store Name.
#>
function Get-CertificatePath
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Thumbprint,

        [Parameter(Mandatory = $true)]
        [ValidateSet('CurrentUser', 'LocalMachine')]
        [System.String]
        $Location,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Store
    )

    return Get-CertificateStorePath -Location $Location -Store $Store |
        Join-Path -ChildPath $Thumbprint
}

<#
    .SYNOPSIS
        This function generates the path to a Windows Certificate Store.

    .PARAMETER Location
        The Windows Certificate Store Location.

    .PARAMETER Store
        The Windows Certificate Store Name.
#>
function Get-CertificateFromCertificateStore
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Thumbprint,

        [Parameter(Mandatory = $true)]
        [ValidateSet('CurrentUser', 'LocalMachine')]
        [System.String]
        $Location,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Store
    )

    $certificatePath = Get-CertificatePath @PSBoundParameters
    $certificates = Get-ChildItem -Path $certificatePath -ErrorAction SilentlyContinue

    return $certificates
}

<#
    .SYNOPSIS
        This function deletes all certificates from the specified Windows Certificate
        Store that match the thumbprint.

    .PARAMETER Thumbprint
        The Thumbprint of the certificates to remove.

    .PARAMETER Location
        The Windows Certificate Store Location.

    .PARAMETER Store
        The Windows Certificate Store Name.
#>
function Remove-CertificateFromCertificateStore
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Thumbprint,

        [Parameter(Mandatory = $true)]
        [ValidateSet('CurrentUser', 'LocalMachine')]
        [System.String]
        $Location,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Store
    )

    $certificates = Get-CertificateFromCertificateStore @PSBoundParameters

    foreach ($certificate in $certificates)
    {
        Write-Verbose -Message ( @(
            "$($MyInvocation.MyCommand): "
            $($script:localizedData.RemovingCertificateFromStoreMessage -f $Thumbprint, $Location, $Store)
        ) -join '' )

        Remove-Item -Path $certificate.PSPath -Force
    }
}

<#
    .SYNOPSIS
        This function sets the friendly name of a certificate in the
        Windows Certificate Store.

    .PARAMETER Thumbprint
        The Thumbprint of the certificates to set the friendly name of.

    .PARAMETER Location
        The Windows Certificate Store Location.

    .PARAMETER Store
        The Windows Certificate Store Name.

    .PARAMETER FriendlyName
        The Friendly Name to set for the certificate.
#>
function Set-CertificateFriendlyNameInCertificateStore
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Thumbprint,

        [Parameter(Mandatory = $true)]
        [ValidateSet('CurrentUser', 'LocalMachine')]
        [System.String]
        $Location,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Store,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $FriendlyName
    )

    $null = $PSBoundParameters.Remove('FriendlyName')

    $certificate = Get-CertificateFromCertificateStore @PSBoundParameters

    if ($null -ne $certificate)
    {
        $certificate.FriendlyName = $FriendlyName
    }
}

Export-ModuleMember -Function @(
    'Test-CertificatePath',
    'Test-Thumbprint',
    'Find-Certificate',
    'Get-CdpContainer',
    'Find-CertificateAuthority',
    'Get-DirectoryEntry',
    'Test-CertificateAuthority',
    'Get-CertificateTemplatesFromActiveDirectory',
    'Get-CertificateTemplateInformation',
    'Get-CertificateExtension',
    'Get-CertificateTemplateExtensionText',
    'Get-CertificateTemplateName',
    'Get-CertificateSubjectAlternativeName',
    'Get-CertificateSubjectAlternativeNameList',
    'Test-CommandExists',
    'Import-CertificateEx',
    'Import-PfxCertificateEx',
    'Get-CertificateStorePath',
    'Get-CertificatePath',
    'Get-CertificateFromCertificateStore',
    'Remove-CertificateFromCertificateStore',
    'Set-CertificateFriendlyNameInCertificateStore'
)
