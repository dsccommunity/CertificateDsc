$modules = 'C:\Program Files\WindowsPowerShell\Modules\'
$modulename = 'xCertificate'
$Description = 'This module includes DSC resources that simplify administration of certificates on a Windows Server'

if (!(test-path (join-path $modules $modulename))) {

    $modulefolder = mkdir (join-path $modules $modulename)
    New-ModuleManifest -Path (join-path $modulefolder "$modulename.psd1") -Guid $([system.guid]::newguid().guid) -Author 'PowerShell DSC' -CompanyName 'Microsoft Corporation' -Copyright '2015' -ModuleVersion '0.1.0.0' -Description $Description -PowerShellVersion '4.0'

    $standard = @{ModuleName = $modulename
                ClassVersion = '0.1.0.0'
                Path = $modules
                }

    $Resource1 = 'xCertReq'
    $P1 = @()
    $P1 += New-xDscResourceProperty -Name Subject -Type String -Attribute Key -Description 'Provide the text string to use as the subject of the certificate'
    $P1 += New-xDscResourceProperty -Name CAServerFQDN -Type String -Attribute Required -Description 'The FQDN of the Active Directory Certificate Authority on the local area network'
    $P1 += New-xDscResourceProperty -Name CARootName -Type String -Attribute Required -Description 'The name of the certificate authority, by default this will be in format domain-servername-ca'
    $P1 += New-xDscResourceProperty -Name Credential -Type PSCredential -Attribute Write -Description 'The credentials that will be used to access the template in the Certificate Authority'
    $P1 += New-xDscResourceProperty -Name AutoRenew -Type Boolean -Attribute Write -Description 'Determines if the resource will also renew a certificate within 7 days of expiration'
    New-xDscResource -Name MSFT_$Resource1 -Property $P1 -FriendlyName $Resource1 @standard
}


# Markdown Generator #
# This is a first draft.  Expected to become 100% efficient in future version.  Loop resources, import example from script, etc.

if (!(test-path "$modules\$modulename\Resources\")){mkdir "$modules\$modulename\Resources\"}

$MD = @"
Introduction
============

The **$ModuleName** module is a part of the Windows PowerShell Desired State Configuration (DSC) Resource Kit, which is a collection of DSC Resources. $Description, with simple declarative language.

**All of the resources in the DSC Resource Kit are provided AS IS, and are not supported through any Microsoft standard support program or service. The "x" in $ModuleName stands for experimental**, which means that these resources will be **fix forward** and monitored by the module owner(s).

Please leave comments, feature requests, and bug reports in the Q & A tab for
this module.

If you would like to modify the **$ModuleName** module, feel free. When modifying, please update the module name, resource friendly name, and MOF class name (instructions below). As specified in the license, you may copy or modify this resource as long as they are used on the Windows Platform.

For more information about Windows PowerShell Desired State Configuration, check out the blog posts on the [PowerShell Blog](http://blogs.msdn.com/b/powershell/) ([this](http://blogs.msdn.com/b/powershell/archive/2013/11/01/configuration-in-a-devops-world-windows-powershell-desired-state-configuration.aspx) is a good starting point). There are also great community resources, such as [PowerShell.org](http://powershell.org/wp/tag/dsc/), or [PowerShell Magazine](http://www.powershellmagazine.com/tag/dsc/). For more information on the DSC Resource Kit, checkout [this blog post](http://go.microsoft.com/fwlink/?LinkID=389546).

Installation
------------

To install **$ModuleName** module

-   If you are using WMF4 / PowerShell Version 4: Unzip the content under the $env:ProgramFiles\WindowsPowerShell\Modules folder

-   If you are using WMF5 Preview: From an elevated PowerShell session run "Install-Module $ModuleName"

To confirm installation

-   Run Get-DSCResource to see that the resources listed above are among the DSC Resources displayed

Requirements
------------

This module requires the latest version of PowerShell (v4.0, which ships in
Windows 8.1 or Windows Server 2012R2). To easily use PowerShell 4.0 on older
operating systems, install WMF 4.0. Please read the installation instructions
that are present on both the download page and the release notes for WMF 4.0.

Details
-------
**$Resource1** resource has following properties

"@
foreach ($res in $P1) {$MD += @"
- **$($res.Name)**: $($res.Description)

"@
}
$MD += @"
Renaming Requirements
---------------------

When making changes to these resources, we suggest the following practice

1. Update the following names by replacing MSFT with your company/community name
and replacing the **"x" with **"c" (short for "Community") or another prefix of your
choice
 -    Module name (ex: xModule becomes cModule)
 -    Resource folder (ex: MSFT\_xResource becomes Contoso\_xResource)
 -    Resource Name (ex: MSFT\_xResource becomes Contoso\_cResource)
 -    Resource Friendly Name (ex: xResource becomes cResource)
 -    MOF class name (ex: MSFT\_xResource becomes Contoso\_cResource)
 -    Filename for the <resource\>.schema.mof (ex: MSFT\_xResource.schema.mof becomes Contoso\_cResource.schema.mof)

2. Update module and metadata information in the module manifest  
3. Update any configuration that use these resources

We reserve resource and module names without prefixes ("x" or "c") for future use (e.g. "MSFT_Resource"). If the next version of Windows Server ships with a "WindowsEventForwarding" resource, we don't want to break any configurations that use any community modifications. Please keep a prefix such as "c" on all community modifications.

Versions
--------

**0.1.0.0**

- Initial release with the following resources
"@
foreach ($res in $P1) {$MD += @"
    - $($res.Name)

"@
    }
$MD += @'

Examples
--------

**Example 1**:  Request and Accept a certificate from an Active Directory Root Certificate Authority.

    configuration SSL
    {
        param (
            [Parameter(Mandatory=$true)] 
            [ValidateNotNullorEmpty()] 
            [PsCredential] $Credential 
            )
        Import-DscResource -ModuleName xCertificate
        Node 'localhost'
        {
            xCertReq SSLCert
            {
                CARootName                = 'test-dc01-ca'
                CAServerFQDN              = 'dc01.test.pha'
                Subject                   = 'foodomain.test.net'
                AutoRenew                 = $true
                Credential                = $Credential
            }
        }
    }
    $configData = @{
        AllNodes = @(
            @{
                NodeName                    = 'localhost';
                PSDscAllowPlainTextPassword = $true
                }
            )
        }
    SSL -ConfigurationData $configData -Credential (get-credential) -OutputPath 'c:\SSLConfig'
    Start-DscConfiguration -Wait -Force -Verbose -Path 'c:\SSLConfig'

    # Validate results
    Get-ChildItem Cert:\LocalMachine\My
'@ 
$MD | Out-File "$modules\$modulename\Resources\ReadMe.md"