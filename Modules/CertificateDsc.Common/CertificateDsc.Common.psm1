# Import the Networking Resource Helper Module
Import-Module -Name (Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) `
        -ChildPath (Join-Path -Path 'CertificateDsc.ResourceHelper' `
            -ChildPath 'CertificateDsc.ResourceHelper.psm1'))

# Import Localization Strings
$localizedData = Get-LocalizedData `
    -ResourceName 'CertificateDsc.Common' `
    -ResourcePath $PSScriptRoot

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
        [String[]]
        $Path,

        [Parameter()]
        [Switch]
        $Quiet
    )

    Process
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
                    -Message ($LocalizedData.FileNotFoundError -f $pathNode) `
                    -ArgumentName 'Path'
            }
        }
    }
} # end function Test-CertificatePath

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

    Begin
    {
        # Get FIPS registry key
        $fips = [System.Int32] (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy' -ErrorAction SilentlyContinue).Enabled

        # Get a list of Hash Providers
        $allHashProviders = [System.AppDomain]::CurrentDomain.GetAssemblies().GetTypes()

        if ($fips -eq $true)
        {
            # Support only FIPS compliant Hash Algorithms
            $hashProviders = $allHashProviders | Where-Object -FilterScript {
                    $_.BaseType.BaseType -eq [System.Security.Cryptography.HashAlgorithm] -and
                    ($_.Name -cmatch 'Provider$' -and $_.Name -cnotmatch 'MD5')
            }
        }
        else
        {
            $hashProviders = $allHashProviders | Where-Object -FilterScript {
                    $_.BaseType.BaseType -eq [System.Security.Cryptography.HashAlgorithm] -and
                    ($_.Name -cmatch 'Managed$' -or $_.Name -cmatch 'Provider$')
            }
        }

        # Get a list of all Valid Hash types and lengths into an array
        $validHashes = @()
        foreach ($hashProvider in $hashProviders)
        {
            $bitSize = ( New-Object -TypeName $hashProvider ).HashSize
            $validHash = New-Object `
                -TypeName PSObject `
                -Property @{
                Hash      = $hashProvider.BaseType.Name
                BitSize   = $bitSize
                HexLength = $bitSize / 4
            }
            $validHashes += @( $validHash )
        }
    }

    Process
    {
        foreach ($hash in $Thumbprint)
        {
            $isValid = $false

            foreach ($algorithm in $validHashes)
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
                    -Message ($LocalizedData.InvalidHashError -f $hash)
            }
        }
    }
} # end function Test-Thumbprint

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
        [String]
        $Thumbprint,

        [Parameter()]
        [String]
        $FriendlyName,

        [Parameter()]
        [String]
        $Subject,

        [Parameter()]
        [String[]]
        $DNSName,

        [Parameter()]
        [String]
        $Issuer,

        [Parameter()]
        [String[]]
        $KeyUsage,

        [Parameter()]
        [String[]]
        $EnhancedKeyUsage,

        [Parameter()]
        [String]
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
            -Message ($LocalizedData.CertificatePathError -f $certPath) `
            -ArgumnentName 'Store'
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
        -Message ($LocalizedData.SearchingForCertificateUsingFilters -f $store, $certFilterScript) `
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
    param(
        [Parameter()]
        [String]
        $DomainName
    )

    if (-not $DomainName)
    {
        $configContext = ([ADSI]'LDAP://RootDSE').configurationNamingContext

        if (-not $configContext)
        {
            # The computer is not domain joined
            New-InvalidOperationException `
                -Message ($LocalizedData.DomainNotJoinedError)
        }
    }
    else
    {
        $ctx = New-Object -TypeName System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $DomainName)
        $configContext = 'CN=Configuration,{0}' -f ([System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($ctx).GetDirectoryEntry().distinguishedName[0])
    }

    Write-Verbose `
        -Message ($LocalizedData.ConfigurationNamingContext -f $configContext.toString()) `
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
    [OutputType([psobject])]
    param(
        [Parameter()]
        [String]
        $DomainName
    )

    Write-Verbose `
        -Message ($LocalizedData.StartLocateCAMessage) `
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
            -Message ($LocalizedData.CaFoundMessage -f $certificateAuthority.CAServerFQDN, $certificateAuthority.CARootName) `
            -Verbose

        return $certificateAuthority
    }
    else
    {
        New-InvalidOperationException `
            -Message ($LocalizedData.NoCaFoundError)
    }
} # end function Find-CertificateAuthority

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
    [OutputType([Boolean])]
    param(
        [Parameter()]
        [System.String]
        $CAServerFQDN,

        [Parameter()]
        [System.String]
        $CARootName
    )

    Write-Verbose `
        -Message ($LocalizedData.StartPingCAMessage) `
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
        -Message ($LocalizedData.CaPingMessage -f $locatorProcess.ExitCode, $locatorOut) `
        -Verbose

    if ($locatorProcess.ExitCode -eq 0)
    {
        Write-Verbose `
            -Message ($LocalizedData.CaOnlineMessage -f $CAServerFQDN, $CARootName) `
            -Verbose

        return $true
    }
    else
    {
        Write-Verbose `
            -Message ($LocalizedData.CaOfflineMessage -f $CAServerFQDN, $CARootName) `
            -Verbose

        return $false
    }
} # end function Test-CertificateAuthority

<#
    .SYNOPSIS
    Gets the certificate templates from Active Directory

    .DESCRIPTION
    Gets the certificate templates from Active Directory by using a
    DirectorySearcher object to find all objects with a objectClass
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
        $domain   = ([adsi] 'LDAP://RootDSE').Get('rootDomainNamingContext')
        $searcher = New-Object -TypeName DirectoryServices.DirectorySearcher

        $searcher.Filter     = '(objectclass=pKICertificateTemplate)'
        $searcher.SearchRoot = 'LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{0}' -f $domain

        $searchResults = $searcher.FindAll()
    }
    catch
    {
        Write-Warning -Message ($LocalizedData.ActiveDirectoryTemplateSearch -f $_.Exception.InnerException.Message)
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
    If the certificate template is "1.3.6.1.4.1.311.20.2" then this function returns
    the name of the template from the formatted text of the extension.
    If the certificate template is "1.3.6.1.4.1.311.21.7" then this function returns
    the information about the certificate template by retreiving the available templates
    from Active Directory and matching the certificate template against this list.
    In addition to the template name the display name, template OID, the major version
    and minor version is also returned.

    .PARAMETER FormattedTemplate
    The text from the certificate template extension. The Format method should be called
    using the parameter $true.
#>
function Get-CertificateTemplateInformation
{
    [OutputType([PSCustomObject])]
    param
    (
        [Parameter(Mandatory)]
        [String]
        $FormattedTemplate
    )

    $templateInformation = @{}

    switch -Regex ($FormattedTemplate)
    {
        'Template=(?:(?<DisplayName>.+?)\((?<Oid>[\d.]+)\)|(?<Oid>[\d.]+))\s*Major\sVersion\sNumber=(?<MajorVersion>\d+)\s*Minor\sVersion\sNumber=(?<MinorVersion>\d+)'
        {
            [Array] $adTemplates = Get-CertificateTemplatesFromActiveDirectory

            if ([String]::IsNullOrEmpty($Matches.DisplayName))
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

            if ($null -eq $template)
            {
                Write-Warning -Message $LocalizedData.TemplateNameResolutionError
            }

            $templateInformation['Name']         = $Matches.Name
            $templateInformation['DisplayName']  = $Matches.DisplayName
            $templateInformation['Oid']          = $Matches.Oid
            $templateInformation['MajorVersion'] = $Matches.MajorVersion
            $templateInformation['MinorVersion'] = $Matches.MinorVersion
        }

        '^(?<TemplateName>\w+)\s?$'
        {
            $templateInformation['Name'] = $Matches.TemplateName
        }

        default
        {
            Write-Warning -Message 'Get-CertificateTemplateInformation: No template name found.'
        }
    }

    return [PSCustomObject] $templateInformation
}

<#
    .SYNOPSIS
    Gets the formatted text output from an X509 certificate template extension.

    .DESCRIPTION
    The supplied X509 Extension Collected is processed to find any Certificate
    Template extensions.
    If a template extension is found the Format method is called with the parameter
    $true and the text output is returned.

    .PARAMETER TemplateExtensions
    The X509 extensions collection from and X509 certificate to be searched for a
    certificate template extension.
#>
function Get-CertificateTemplateText
{
    [OutputType([String])]
    param
    (
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509ExtensionCollection]
        $TemplateExtensions
    )

    $templateOidNames = 'Certificate Template Information', 'Certificate Template Name'

    $templateExtension = $TemplateExtensions.Where({
        $_.Oid.FriendlyName -in $templateOidNames
    })[0]

    if ($null -ne $templateExtension)
    {
        return $templateExtension.Format($true)
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
    The certificate object the template name is needed for.
#>
function Get-CertificateTemplateName
{
    [cmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [object]
        $Certificate
    )

    if ($Certificate -isnot [System.Security.Cryptography.X509Certificates.X509Certificate2])
    {
        return
    }

    $templateExtensionText = Get-CertificateTemplateText -TemplateExtensions $Certificate.Extensions

    if ($null -ne $templateExtensionText)
    {
        return Get-CertificateTemplateInformation -FormattedTemplate $templateExtensionText | Select-Object -ExpandProperty Name
    }
}

<#
    .SYNOPSIS
    Get certificate SAN

    .DESCRIPTION
    Gets the first subject alternative name for the certificate that is passed to this cmdlet

    .PARAMETER Certificate
    The certificate object the subject alternative name is needed for
#>
function Get-CertificateSan
{
    [cmdletBinding()]
    [OutputType([System.String])]
    param
    (
        # The certificate for which the subject alternative names are needed
        [Parameter(Mandatory = $true)]
        [object]
        $Certificate
    )

    if ($Certificate -isnot [System.Security.Cryptography.X509Certificates.X509Certificate2])
    {
        return
    }

    $subjectAlternativeName = $null

    $sanExtension = $Certificate.Extensions | Where-Object { $_.Oid.FriendlyName -match 'subject alternative name' }

    if ($null -eq $sanExtension)
    {
        return $subjectAlternativeName
    }

    $sanObjects = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
    $altNamesStr = [System.Convert]::ToBase64String($sanExtension.RawData)
    $sanObjects.InitializeDecode(1, $altNamesStr)

    if ($sanObjects.AlternativeNames.Count -gt 0)
    {
        $subjectAlternativeName = $sanObjects.AlternativeNames[0].strValue
    }

    return $subjectAlternativeName
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

    .PARAMETER CertStoreLocation
    The Certificate Store and Location Path to import the certificate to.
#>
function Import-CertificateEx
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $FilePath,

        [Parameter(Mandatory = $true)]
        [System.String]
        $CertStoreLocation
    )

    $location = Split-Path -Path (Split-Path -Path $CertStoreLocation -Parent) -Leaf
    $store = Split-Path -Path $CertStoreLocation -Leaf

    $cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2
    $cert.Import($FilePath)

    $certStore = New-Object `
        -TypeName System.Security.Cryptography.X509Certificates.X509Store `
        -ArgumentList ($store, $location)

    $certStore.Open('MaxAllowed')
    $certStore.Add($cert)
    $certStore.Close()
}

<#
    .SYNOPSIS
    This function imports a Pfx public - private certificate to the specific
    Certificate Store Location.

    .PARAMETER FilePath
    The path to the certificate file to import.

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
        [Parameter(Mandatory = $true)]
        [System.String]
        $FilePath,

        [Parameter(Mandatory = $true)]
        [System.String]
        $CertStoreLocation,

        [Parameter(Mandatory = $false)]
        [Switch]
        $Exportable,

        [Parameter(Mandatory = $false)]
        [System.Security.SecureString]
        $Password
    )

    $location = Split-Path -Path (Split-Path -Path $CertStoreLocation -Parent) -Leaf
    $store = Split-Path -Path $CertStoreLocation -Leaf

    $cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2

    $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet

    if ($Exportable)
    {
        $flags = $flags -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
    }

    if ($Password)
    {
        $cert.Import($FilePath, $Password, $flags)
    }
    else
    {
        $cert.Import($FilePath, $flags)
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
function Get-CertificateStorePath {
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

    return 'Cert:' |
        Join-Path -ChildPath $Location |
        Join-Path -ChildPath $Store
}
