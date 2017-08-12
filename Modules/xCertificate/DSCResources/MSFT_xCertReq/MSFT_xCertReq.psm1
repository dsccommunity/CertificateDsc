#Requires -Version 4.0

$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the Certificate Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'CertificateDsc.Common' `
            -ChildPath 'CertificateDsc.Common.psm1'))

# Import the Certificate Resource Helper Module
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'CertificateDsc.ResourceHelper' `
            -ChildPath 'CertificateDsc.ResourceHelper.psm1'))

# Import the Certificate PDT Helper Module
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'CertificateDsc.PDT' `
            -ChildPath 'CertificateDsc.PDT.psm1'))

# Import Localization Strings
$localizedData = Get-LocalizedData `
    -ResourceName 'MSFT_xCertReq' `
    -ResourcePath (Split-Path -Parent $Script:MyInvocation.MyCommand.Path)

<#
    .SYNOPSIS
    Returns the current state of the certificate that may need to be requested.

    .PARAMETER Subject
    Provide the text string to use as the subject of the certificate.

    .PARAMETER CAServerFQDN
    The FQDN of the Active Directory Certificate Authority on the local area network.

    .PARAMETER CARootName
    The name of the certificate authority, by default this will be in format domain-servername-ca.

    .PARAMETER KeyLength
    The bit length of the encryption key to be used.

    .PARAMETER Exportable
    The option to allow the certificate to be exportable, by default it will be true.

    .PARAMETER ProviderName
    The selection of provider for the type of encryption to be used.

    .PARAMETER OID
    The Object Identifier that is used to name the object.

    .PARAMETER KeyUsage
    The Keyusage is a restriction method that determines what a certificate can be used for.

    .PARAMETER CertificateTemplate
    The template used for the definiton of the certificate.

    .PARAMETER SubjectAltName
    The subject alternative name used to createthe certificate.

    .PARAMETER Credential
    The credentials that will be used to access the template in the Certificate Authority.

    .PARAMETER AutoRenew
    Determines if the resource will also renew a certificate within 7 days of expiration.

    .PARAMETER CAType
    The type of CA in use, Standalone/Enterprise.

    .PARAMETER CepURL
    The URL to the Certification Enrollment Policy Service.

    .PARAMETER CesURL
    The URL to the Certification Enrollment Service.

    .PARAMETER UseMachineContext
    Determines if the machine should be impersonated for a request. Used for templates like Domain Controller Authentication

    .PARAMETER FriendlyName
    Specifies a friendly name for the certificate.
#>
function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Subject,

        [Parameter()]
        [System.String]
        $CAServerFQDN,

        [Parameter()]
        [System.String]
        $CARootName,

        [Parameter()]
        [ValidateSet("1024", "2048", "4096", "8192")]
        [System.String]
        $KeyLength = '2048',

        [Parameter()]
        [System.Boolean]
        $Exportable = $true,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ProviderName = '"Microsoft RSA SChannel Cryptographic Provider"',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $OID = '1.3.6.1.5.5.7.3.1',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $KeyUsage = '0xa0',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $CertificateTemplate = 'WebServer',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $SubjectAltName,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter()]
        [System.Boolean]
        $AutoRenew,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $CAType = 'Enterprise',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $CepURL,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $CesURL,

        [Parameter()]
        [System.Boolean]
        $UseMachineContext,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $FriendlyName
    )

    # The certificate authority, accessible on the local area network
    if ([string]::IsNullOrWhiteSpace($CAServerFQDN) -or [string]::IsNullOrWhiteSpace($CARootName))
    {
        $caObject = Find-CertificateAuthority
        $CARootName = $caObject.CARootName
        $CAServerFQDN = $caObject.CAServerFQDN
    }

    $ca = "$CAServerFQDN\$CARootName"

    Write-Verbose -Message ( @(
            "$($MyInvocation.MyCommand): "
            $($LocalizedData.GettingCertReqStatusMessage -f $Subject, $CA)
        ) -join '' )

    $cert = Get-Childitem -Path Cert:\LocalMachine\My |
        Where-Object -FilterScript {
        $_.Subject -eq "CN=$Subject" -and `
            $_.Issuer.split(',')[0] -eq "CN=$CARootName"
    }

    # If multiple certs have the same subject and were issued by the CA, return the newest
    $cert = $cert |
        Sort-Object -Property NotBefore -Descending |
        Select-Object -First 1

    if ($cert)
    {
        Write-Verbose -Message ( @(
                "$($MyInvocation.MyCommand): "
                $($LocalizedData.CertificateExistsMessage -f $Subject, $ca, $cert.Thumbprint)
            ) -join '' )

        $returnValue = @{
            Subject             = $Cert.Subject.split(',')[0].replace('CN=', '')
            CAServerFQDN        = $caObject.CAServerFQDN
            CARootName          = $Cert.Issuer.split(',')[0].replace('CN=', '')
            KeyLength           = $Cert.Publickey.Key.KeySize
            Exportable          = $Cert.PrivateKey.CspKeyContainerInfo.Exportable
            ProviderName        = $Cert.PrivateKey.CspKeyContainerInfo.ProviderName
            OID                 = $null # This value can't be determined from the cert
            KeyUsage            = $null # This value can't be determined from the cert
            CertificateTemplate = Get-CertificateTemplateName -Certificate $Cert
            SubjectAltName      = Get-CertificateSan -Certificate $Cert
            FriendlyName        = $Cert.FriendlyName
        }
    }
    else
    {
        $returnValue = @{}
    }

    $returnValue
} # end function Get-TargetResource

<#
    .SYNOPSIS
    Requests a new certificate based on the parameters provided.

    .PARAMETER Subject
    Provide the text string to use as the subject of the certificate.

    .PARAMETER CAServerFQDN
    The FQDN of the Active Directory Certificate Authority on the local area network.

    .PARAMETER CARootName
    The name of the certificate authority, by default this will be in format domain-servername-ca.

    .PARAMETER KeyLength
    The bit length of the encryption key to be used.

    .PARAMETER Exportable
    The option to allow the certificate to be exportable, by default it will be true.

    .PARAMETER ProviderName
    The selection of provider for the type of encryption to be used.

    .PARAMETER OID
    The Object Identifier that is used to name the object.

    .PARAMETER KeyUsage
    The Keyusage is a restriction method that determines what a certificate can be used for.

    .PARAMETER CertificateTemplate
    The template used for the definiton of the certificate.

    .PARAMETER SubjectAltName
    The subject alternative name used to createthe certificate.

    .PARAMETER Credential
    The credentials that will be used to access the template in the Certificate Authority.

    .PARAMETER AutoRenew
    Determines if the resource will also renew a certificate within 7 days of expiration.

    .PARAMETER CAType
    The type of CA in use, Standalone/Enterprise.

    .PARAMETER CepURL
    The URL to the Certification Enrollment Policy Service.

    .PARAMETER CesURL
    The URL to the Certification Enrollment Service.

    .PARAMETER UseMachineContext
    Determines if the machine should be impersonated for a request. Used for templates like Domain Controller Authentication

    .PARAMETER FriendlyName
    Specifies a friendly name for the certificate.
#>
function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Subject,

        [Parameter()]
        [System.String]
        $CAServerFQDN,

        [Parameter()]
        [System.String]
        $CARootName,

        [Parameter()]
        [ValidateSet("1024", "2048", "4096", "8192")]
        [System.String]
        $KeyLength = '2048',

        [Parameter()]
        [System.Boolean]
        $Exportable = $true,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ProviderName = '"Microsoft RSA SChannel Cryptographic Provider"',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $OID = '1.3.6.1.5.5.7.3.1',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $KeyUsage = '0xa0',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $CertificateTemplate = 'WebServer',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $SubjectAltName,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter()]
        [System.Boolean]
        $AutoRenew,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $CAType = 'Enterprise',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $CepURL,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $CesURL,

        [Parameter()]
        [System.Boolean]
        $UseMachineContext,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $FriendlyName
    )

    # The certificate authority, accessible on the local area network
    if ([string]::IsNullOrWhiteSpace($CAServerFQDN) -or [string]::IsNullOrWhiteSpace($CARootName))
    {
        $caObject = Find-CertificateAuthority
        $CARootName = $caObject.CARootName
        $CAServerFQDN = $caObject.CAServerFQDN
    }

    $ca = "$CAServerFQDN\$CARootName"

    Write-Verbose -Message ( @(
            "$($MyInvocation.MyCommand): "
            $($LocalizedData.StartingCertReqMessage -f $Subject, $ca)
        ) -join '' )

    # If the Subject does not contain a full X500 path, construct just the CN
    if (($Subject.split('=').Count) -eq 1)
    {
        $Subject = "CN=$Subject"
    } # if

    # If we should look for renewals, check for existing certs
    if ($AutoRenew)
    {
        $certs = Get-Childitem -Path Cert:\LocalMachine\My |
            Where-Object -FilterScript {
            $_.Subject -eq $Subject -and `
                $_.Issuer.split(',')[0] -eq "CN=$CARootName" -and `
                $_.NotAfter -lt (Get-Date).AddDays(30)
        }

        # If multiple certs have the same subject and were issued by the CA and are 30 days from expiration, return the newest
        $firstCert = $certs |
            Sort-Object -Property NotBefore -Descending |
            Select-Object -First 1
        $thumbprint = $firstCert |
            ForEach-Object -Process { $_.Thumbprint }
    } # if

    <#
        Information that will be used in the INF file to generate the certificate request
        In future versions, select variables from the list below could be moved to parameters!
    #>
    $Subject = "`"$Subject`""
    $keySpec = '1'
    $machineKeySet = 'TRUE'
    $smime = 'FALSE'
    $privateKeyArchive = 'FALSE'
    $userProtected = 'FALSE'
    $useExistingKeySet = 'FALSE'
    $providerType = '12'
    $requestType = 'CMC'

    # A unique identifier for temporary files that will be used when interacting with the command line utility
    $guid = [system.guid]::NewGuid().guid
    $workingPath = Join-Path -Path $env:Temp -ChildPath "xCertReq-$guid"
    $infPath = [System.IO.Path]::ChangeExtension($workingPath, '.inf')
    $reqPath = [System.IO.Path]::ChangeExtension($workingPath, '.req')
    $cerPath = [System.IO.Path]::ChangeExtension($workingPath, '.cer')
    $rspPath = [System.IO.Path]::ChangeExtension($workingPath, '.rsp')

    # Create INF file
    $requestDetails = @"
[NewRequest]
Subject = $Subject
KeySpec = $keySpec
KeyLength = $KeyLength
Exportable = $($Exportable.ToString().ToUpper())
MachineKeySet = $MachineKeySet
SMIME = $smime
PrivateKeyArchive = $privateKeyArchive
UserProtected = $userProtected
UseExistingKeySet = $useExistingKeySet
ProviderName = $ProviderName
ProviderType = $providerType
RequestType = $requestType
KeyUsage = $KeyUsage
"@
    if ($FriendlyName)
    {
        $requestDetails += @"

FriendlyName = "$FriendlyName"
"@
    }
    $requestDetails += @"

[RequestAttributes]
CertificateTemplate = $CertificateTemplate
[EnhancedKeyUsageExtension]
OID = $OID
"@
    # If a standalone CA is used certificate templates are not used.
    if ($CAType -ne 'Enterprise')
    {
        $requestDetails = $requestDetails.Replace(@"
[RequestAttributes]
CertificateTemplate = $CertificateTemplate
[EnhancedKeyUsageExtension]
"@, '[EnhancedKeyUsageExtension]')
    }

    if ($PSBoundParameters.ContainsKey('SubjectAltName'))
    {
        # If a Subject Alt Name was specified, add it.
        $requestDetails += @"

[Extensions]
2.5.29.17 = `"{text}$SubjectAltName`"
"@
    }
    if ($thumbprint)
    {
        $requestDetails += @"

RenewalCert = $Thumbprint
"@
    }
    Set-Content -Path $infPath -Value $requestDetails

    <#
        Certreq.exe is used to handle the request of the new certificate
        because of the lack of native PowerShell Certificate cmdlets.
        Syntax: https://technet.microsoft.com/en-us/library/cc736326.aspx
        Reference: https://support2.microsoft.com/default.aspx?scid=kb;EN-US;321051
    #>

    # NEW: Create a new request as directed by PolicyFileIn
    Write-Verbose -Message ( @(
            "$($MyInvocation.MyCommand): "
            $($LocalizedData.CreateRequestCertificateMessage -f $infPath, $reqPath)
        ) -join '' )

    <#
        If enrollment server is specified the request will be towards
        the specified URLs instead, using credentials for authentication.
    #>
    if ($Credential -and $CepURL -and $CesURL)
    {
        $credPW = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)
        $createRequest = & certreq.exe @(
            '-new', '-q',
            '-username', $Credential.UserName,
            '-p', [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($credPW),
            '-PolicyServer', $CepURL,
            '-config', $CesURL,
            $infPath,
            $reqPath
        )
    }
    else
    {
        $createRequest = & certreq.exe @('-new', '-q', $infPath, $reqPath)
    } # if

    Write-Verbose -Message ( @(
            "$($MyInvocation.MyCommand): "
            $($LocalizedData.CreateRequestResultCertificateMessage -f ($createRequest | Out-String))
        ) -join '' )

    <#
        SUBMIT: Submit a request to a Certification Authority.
        DSC runs in the context of LocalSystem, which uses the Computer account in Active Directory
        to authenticate to network resources
        The Credential paramter with PDT is used to impersonate a user making the request
    #>
    if (Test-Path -Path $reqPath)
    {
        Write-Verbose -Message ( @(
                "$($MyInvocation.MyCommand): "
                $($LocalizedData.SubmittingRequestCertificateMessage -f $reqPath, $cerPath, $ca)
            ) -join '' )

        if ($Credential)
        {
            <#
                If enrollment server is specified the request will be towards
                the specified URLs instead, using credentials for authentication.
            #>
            if ($CepURL -and $CesURL)
            {
                $credPW = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)
                $submitRequest = & certreq.exe @(
                    '-submit', '-q',
                    '-username', $Credential.UserName,
                    '-p', [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($credPW),
                    '-PolicyServer', $CepURL,
                    '-config', $CesURL,
                    $ReqPath,
                    $CerPath
                )
            }
            else
            {
                <#
                    Assemble the command and arguments to pass to the powershell process that
                    will request the certificate
                #>
                $certReqOutPath = [System.IO.Path]::ChangeExtension($workingPath, '.out')
                $command = "$PSHOME\PowerShell.exe"

                if ($UseMachineContext)
                {
                    $arguments = "-Command ""& $env:SystemRoot\system32\certreq.exe" + `
                        " @('-submit','-q','-adminforcemachine','-config','$ca','$reqPath','$cerPath')" + `
                        " | Set-Content -Path '$certReqOutPath'"""
                }
                else
                {
                    $arguments = "-Command ""& $env:SystemRoot\system32\certreq.exe" + `
                        " @('-submit','-q','-config','$ca','$reqPath','$cerPath')" + `
                        " | Set-Content -Path '$certReqOutPath'"""
                }

                <#
                    This may output a win32-process object, but it often does not because of
                    a timing issue in PDT (the process has often completed before the
                    process can be read in).
                #>
                $null = Start-Win32Process `
                    -Path $command `
                    -Arguments $arguments `
                    -Credential $Credential

                Write-Verbose -Message ( @(
                        "$($MyInvocation.MyCommand): "
                        $($LocalizedData.SubmittingRequestProcessCertificateMessage)
                    ) -join '' )

                $null = Wait-Win32ProcessStop `
                    -Path $command `
                    -Arguments $arguments `
                    -Credential $Credential

                if (Test-Path -Path $certReqOutPath)
                {
                    $submitRequest = Get-Content -Path $certReqOutPath
                    Remove-Item -Path $certReqOutPath -Force
                }
                else
                {
                    New-InvalidOperationException `
                        -Message ($LocalizedData.CertReqOutNotFoundError -f $certReqOutPath)
                } # if
            } # if
        }
        else
        {
            $submitRequest = & certreq.exe @('-submit', '-q', '-config', $CA, $ReqPath, $CerPath)
        } # if

        Write-Verbose -Message ( @(
                "$($MyInvocation.MyCommand): "
                $($LocalizedData.SubmittingRequestResultCertificateMessage -f ($submitRequest | Out-String))
            ) -join '' )
    }
    else
    {
        New-InvalidOperationException `
            -Message ($LocalizedData.CertificateReqNotFoundError -f $reqPath)
    } # if

    # ACCEPT: Accept the request
    if (Test-Path -Path $cerPath)
    {
        Write-Verbose -Message ( @(
                "$($MyInvocation.MyCommand): "
                $($LocalizedData.AcceptingRequestCertificateMessage -f $cerPath, $ca)
            ) -join '' )

        $acceptRequest = & certreq.exe @('-accept', '-machine', '-q', $cerPath)

        Write-Verbose -Message ( @(
                "$($MyInvocation.MyCommand): "
                $($LocalizedData.AcceptingRequestResultCertificateMessage -f ($acceptRequest | Out-String))
            ) -join '' )
    }
    else
    {
        New-InvalidOperationException `
            -Message ($LocalizedData.CertificateCerNotFoundError -f $cerPath)
    } # if

    Write-Verbose -Message ( @(
            "$($MyInvocation.MyCommand): "
            $($LocalizedData.CleaningUpRequestFilesMessage -f "$($workingPath).*")
        ) -join '' )
    Remove-Item -Path "$($workingPath).*" -Force
} # end function Set-TargetResource

<#
    .SYNOPSIS
    Tests if a new certificate should be requested.

    .PARAMETER Subject
    Provide the text string to use as the subject of the certificate.

    .PARAMETER CAServerFQDN
    The FQDN of the Active Directory Certificate Authority on the local area network.

    .PARAMETER CARootName
    The name of the certificate authority, by default this will be in format domain-servername-ca.

    .PARAMETER KeyLength
    The bit length of the encryption key to be used.

    .PARAMETER Exportable
    The option to allow the certificate to be exportable, by default it will be true.

    .PARAMETER ProviderName
    The selection of provider for the type of encryption to be used.

    .PARAMETER OID
    The Object Identifier that is used to name the object.

    .PARAMETER KeyUsage
    The Keyusage is a restriction method that determines what a certificate can be used for.

    .PARAMETER CertificateTemplate
    The template used for the definiton of the certificate.

    .PARAMETER SubjectAltName
    The subject alternative name used to createthe certificate.

    .PARAMETER Credential
    The credentials that will be used to access the template in the Certificate Authority.

    .PARAMETER AutoRenew
    Determines if the resource will also renew a certificate within 7 days of expiration.

    .PARAMETER CAType
    The type of CA in use, Standalone/Enterprise.

    .PARAMETER CepURL
    The URL to the Certification Enrollment Policy Service.

    .PARAMETER CesURL
    The URL to the Certification Enrollment Service.

    .PARAMETER UseMachineContext
    Determines if the machine should be impersonated for a request. Used for templates like Domain Controller Authentication

    .PARAMETER FriendlyName
    Specifies a friendly name for the certificate.
#>
function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Subject,

        [Parameter()]
        [System.String]
        $CAServerFQDN,

        [Parameter()]
        [System.String]
        $CARootName,

        [Parameter()]
        [ValidateSet("1024", "2048", "4096", "8192")]
        [System.String]
        $KeyLength = '2048',

        [Parameter()]
        [System.Boolean]
        $Exportable = $true,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ProviderName = '"Microsoft RSA SChannel Cryptographic Provider"',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $OID = '1.3.6.1.5.5.7.3.1',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $KeyUsage = '0xa0',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $CertificateTemplate = 'WebServer',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $SubjectAltName,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter()]
        [System.Boolean]
        $AutoRenew,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $CAType = 'Enterprise',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $CepURL,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $CesURL,

        [Parameter()]
        [System.Boolean]
        $UseMachineContext,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $FriendlyName
    )

    # The certificate authority, accessible on the local area network
    if ([string]::IsNullOrWhiteSpace($CAServerFQDN) -or [string]::IsNullOrWhiteSpace($CARootName))
    {
        $caObject = Find-CertificateAuthority
        $CARootName = $caObject.CARootName
        $CAServerFQDN = $caObject.CAServerFQDN
    }

    $ca = "$CAServerFQDN\$CARootName"

    # If the Subject does not contain a full X500 path, construct just the CN
    if (($Subject.split('=').count) -eq 1)
    {
        $Subject = "CN=$Subject"
    }

    Write-Verbose -Message ( @(
            "$($MyInvocation.MyCommand): "
            $($LocalizedData.TestingCertReqStatusMessage -f $Subject, $ca)
        ) -join '' )

    # Exception for standard template DomainControllerAuthentication
    $cert = Get-Childitem -Path Cert:\LocalMachine\My |
        Where-Object -FilterScript {
        $_.Subject -eq $Subject -and `
            $_.Issuer.split(',')[0] -eq "CN=$CARootName"
    }

    if ($CertificateTemplate -eq 'DomainControllerAuthentication')
    {
        $cert = Get-Childitem -Path Cert:\LocalMachine\My |
            Where-Object -FilterScript {
            (Get-CertificateTemplateName -Certificate $PSItem) -eq $CertificateTemplate -and `
                $_.Issuer.split(',')[0] -eq "CN=$CARootName"
        }
    }

    # If multiple certs have the same subject and were issued by the CA, return the newest
    $cert = $cert |
        Sort-Object -Property NotBefore -Descending |
        Select-Object -First 1

    if ($cert)
    {
        Write-Verbose -Message ( @(
                "$($MyInvocation.MyCommand): "
                $($LocalizedData.CertificateExistsMessage -f $Subject, $ca, $cert.Thumbprint)
            ) -join '' )

        if ($AutoRenew)
        {
            if ($Cert.NotAfter -le (Get-Date).AddDays(-30))
            {
                # The certificate was found but it is expiring within 30 days or has expired
                Write-Verbose -Message ( @(
                        "$($MyInvocation.MyCommand): "
                        $($LocalizedData.ExpiringCertificateMessage -f $Subject, $ca, $cert.Thumbprint)
                    ) -join '' )
                return $false
            } # if
        }
        else
        {
            if ($cert.NotAfter -le (Get-Date))
            {
                # The certificate has expired
                Write-Verbose -Message ( @(
                        "$($MyInvocation.MyCommand): "
                        $($LocalizedData.ExpiredCertificateMessage -f $Subject, $ca, $cert.Thumbprint)
                    ) -join '' )
                return $false
            } # if
        } # if

        if ($PSBoundParameters.ContainsKey('SubjectAltName'))
        {
            # Split the desired SANs into an array
            $sanList = $SubjectAltName.Split('&')
            $correctDNS = @()

            foreach ($san in $sanList)
            {
                if ($san -like 'dns*')
                {
                    # This SAN is a DNS name
                    $correctDNS += $san.split('=')[1]
                }
            }

            # Find out what SANs are on the current cert
            if ($cert.Extensions.Count -gt 0)
            {
                $currentSanList = ($cert.Extensions | Where-Object {$_.oid.FriendlyName -match 'Subject Alternative Name'}).Format(1).split("`n").TrimEnd()
                $currentDNS = @()
                foreach ($san in $currentSanList)
                {
                    if ($san -like 'dns*')
                    {
                        # This SAN is a DNS name
                        $currentDNS += $san.split('=')[1]
                    }
                }

                # Do the cert's DNS SANs and the desired DNS SANs match?
                if (@(Compare-Object -ReferenceObject $currentDNS -DifferenceObject $correctDNS).Count -gt 0)
                {
                    return $false
                }
            }
            else
            {
                # There are no SANs and there should be
                return $false
            }
        }

        if ($CertificateTemplate -ne (Get-CertificateTemplateName -Certificate $cert))
        {
            Write-Verbose -Message ( @(
                    "$($MyInvocation.MyCommand): "
                    $($LocalizedData.CertTemplateMismatch -f $Subject, $ca, $cert.Thumbprint, (Get-CertificateTemplateName -Certificate $cert))
                ) -join '' )
            return $false
        } # if

        # Check the friendly name of the certificate matches
        if ($FriendlyName -ne $cert.FriendlyName)
        {
            Write-Verbose -Message ( @(
                    "$($MyInvocation.MyCommand): "
                    $($LocalizedData.CertFriendlyNameMismatch -f $Subject, $ca, $cert.Thumbprint, $cert.FriendlyName)
                ) -join '' )
            return $false
        } # if

        # The certificate was found and is OK - so no change required.
        Write-Verbose -Message ( @(
                "$($MyInvocation.MyCommand): "
                $($LocalizedData.ValidCertificateExistsMessage -f $Subject, $ca, $cert.Thumbprint)
            ) -join '' )
        return $true
    } # if

    # A valid certificate was not found
    Write-Verbose -Message ( @(
            "$($MyInvocation.MyCommand): "
            $($LocalizedData.NoValidCertificateMessage -f $Subject, $ca)
        ) -join '' )
    return $false
} # end function Test-TargetResource
