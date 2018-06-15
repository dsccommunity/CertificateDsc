# Versions

## Unreleased

- Added a CODE_OF_CONDUCT.md with the same content as in the README.md - fixes
  [Issue #139](https://github.com/PowerShell/CertificateDsc/issues/139).

## 4.1.0.0

- PfxImport:
  - Changed so that PFX will be reimported if private key is not
    installed - fixes [Issue #129](https://github.com/PowerShell/CertificateDsc/issues/129).
  - Corrected to meet style guidelines.
  - Corrected path parameter description - fixes [Issue #125](https://github.com/PowerShell/CertificateDsc/issues/125).
  - Refactored to remove code duplication by creating Get-CertificateStorePath.
  - Improved unit tests to meet standards and provide better coverage.
  - Improved integration tests to meet standards and provide better coverage.
  - Changed Path parameter to be optional to fix error when ensuring certificate
    is absent and certificate file does not exist on disk - fixes [Issue #136](https://github.com/PowerShell/CertificateDsc/issues/136).
  - Removed ShouldProcess because it is not required by DSC Resources.
  - Minor style corrections.
  - Changed unit tests to be non-destructive.
  - Improved naming and description of example files.
  - Added localization string ID suffix for all strings.
- CertificateDsc.Common:
  - Corrected to meet style guidelines.
  - Added function Get-CertificateStorePath for generating Certificate Store path.
  - Remove false verbose message from `Test-Thumbprint` - fixes [Issue #127](https://github.com/PowerShell/CertificateDsc/issues/127).
- CertReq:
  - Added detection for FIPS mode in Test-Thumbprint - fixes [Issue #107](https://github.com/PowerShell/CertificateDsc/issues/107).

## 4.0.0.0

- BREAKING CHANGE
  - Renamed xCertificate to CertificateDsc - fixes [Issue #114](https://github.com/PowerShell/xCertificate/issues/114).
  - Changed all MSFT_xResourceName to MSFT_ResourceName.
  - Updated DSCResources, Examples, Modules and Tests for new naming.
  - Updated Year to 2018 in License and Manifest.
  - Updated README.md from xCertificate to CertifcateDsc
  - Removed unnecessary code from:
    - CertificateDsc\Modules\CertificateDsc\DSCResources\MSFT_CertReq\MSFT_CertReq.psm1
      - Deleted $rspPath = [System.IO.Path]::ChangeExtension($workingPath, '.rsp')

## 3.2.0.0

- Get-CertificateTemplateName: Fix missing template name

## 3.1.0.0

- xCertReq:
  - Fixed behaviour to allow certificate templates with spaces in the name
- Added `Documentation and Examples` section to Readme.md file - see
  [issue #98](https://github.com/PowerShell/xCertificate/issues/98).
- Changed description in Credential parameter of xPfxImport resource
  to correctly generate parameter documentation in Wiki - see [Issue #103](https://github.com/PowerShell/xCertificate/issues/103).
- Changed description in Credential parameter of xCertReq resource
  to clarify that a PSCredential object should be used.
- Updated tests to meet Pester V4 guidelines - fixes [Issue #105](https://github.com/PowerShell/xCertificate/issues/105).
- Add support for Windows Server 2008 R2 which does not contain PKI
  module so is missing `Import-PfxCertificate` and `Import-Certificate`
  cmdlets - fixes [Issue #46](https://github.com/PowerShell/xCertificate/issues/46).

## 3.0.0.0

- Add CodeCov.io code coverage reporting.
- Opted into 'Common Tests - Validate Example Files'.
- Fixed bugs in examples.
- Updated License and Manifest Copyright info to be 2017 Microsoft Corporation.
- xCertReq:
  - BREAKING CHANGE: Changed default Keylength to 2048 bits to meet
    [Microsoft Security Advisory](https://support.microsoft.com/en-us/help/2661254/microsoft-security-advisory-update-for-minimum-certificate-key-length).
  - Fixed spelling mistakes in MOF files.
- Added .github support files:
  - CONTRIBUTING.md
  - ISSUE_TEMPLATE.md
  - PULL_REQUEST_TEMPLATE.md
- Opted into Common Tests 'Validate Module Files' and 'Validate Script Files'.
- Converted files with UTF8 with BOM over to UTF8 - fixes [Issue 87](https://github.com/PowerShell/xCertificate/issues/87).
- Converted to use auto-documentation/wiki format - fixes [Issue 84](https://github.com/PowerShell/xCertificate/issues/84).

## 2.8.0.0

- xCertReq:
  - Added FriendlyName parameter to xCertReq.
  - Changed exceptions to be raised using New-InvalidOperationException from PSDscResources.
  - Changed integration tests to use Config Data instead of value in config to support
    additional tests.
  - Converted unit tests to use Get-InvalidOperationRecord in CommonTestHelper.
  - Improved unit test style to match standard layout.
  - Minor corrections to style to be HQRM compliant.
  - Improved Verbose logging by writing all lines of CertReq.exe output.
  - Fixed CA auto-detection to work when CA name contains a space.
- Corrected all makrdown rule violations in README.MD.
- Added markdownlint.json file to enable line length rule checking in VSCode
  with [MarkdownLint extension](https://marketplace.visualstudio.com/items?itemName=DavidAnson.vscode-markdownlint)
  installed.
- Added the VS Code PowerShell extension formatting settings that cause PowerShell
  files to be formatted as per the DSC Resource kit style guidelines.
- Fixed verbose preference not being passed to CertificateDsc.Common functions -
  fixes [Issue 70](https://github.com/PowerShell/xCertificate/issues/70).
- Converted all calls to `New-InvalidArgumentError` function to `New-InvalidArgumentException`
  found in `CertificateDsc.ResourceHelper` - fixes [Issue 68](https://github.com/PowerShell/xCertificate/issues/68)
- Replaced all calls to `Write-Error` with calls to `New-InvalidArgumentException`
  and `New-InvalidOperationException`
- xWaitForCertificateServices:
  - Added new resource.
- Cleaned up example format to meet style guidelines and changed examples to
  issue 2048 bit certificates.
- Fixed spelling error in xCertificateExport Issuer parameter description.
- Prevent unit tests from DSCResource.Tests from running during test
  execution - fixes [Issue 100](https://github.com/PowerShell/xCertificate/issues/100).

## 2.7.0.0

- Added integration test to test for conflicts with other common resource kit modules.
- Prevented ResourceHelper and Common module cmdlets from being exported to resolve
  conflicts with other resource modules.

## 2.6.0.0

- Added mandatory properties for xPfxImport resource example.
- xCertReq:
  - Fixed issue where xCertReq does not identify when DNS Names in SANs are incorrect.
  - Added Certificate Authority auto-discovery to resource xCertReq.
  - Added SAN and certificate template name to xCertReq's Get-TargetResource
  - Added new parameter UseMachineContext to be able to use CA templates that try
    to fill the subject alternative name
- CertificateDSc.Common:
  - Added function Get-CertificateTemplateName to retrieve template name
  - Added function Get-CertificateSan to retrieve subject alternative name
  - Added function Find-CertificateAuthority to enable auto-discovery

## 2.5.0.0

- Fixed issue where xCertReq does not process requested certificate when credentials
  parameter set and PSDscRunAsCredential not passed. See [issue](https://github.com/PowerShell/xCertificate/issues/49)

## 2.4.0.0

- Converted AppVeyor build process to use AppVeyor.psm1.
- Correct Param block to meet guidelines.
- Moved shared modules into modules folder.
- xCertificateExport:
  - Added new resource.
- Cleanup xCertificate.psd1 to remove unnecessary properties.
- Converted AppVeyor.yml to use DSCResource.tests shared code.
- Opted-In to markdown rule validation.
- Examples modified to meet standards for auto documentation generation.

## 2.3.0.0

- xCertReq:
  - Added additional parameters KeyLength, Exportable, ProviderName, OID, KeyUsage,
    CertificateTemplate, SubjectAltName
- Fixed most markdown errors in Readme.md.
- Corrected Parameter decoration format to be consistent with guidelines.

## 2.2.0.0

- Converted appveyor.yml to install Pester from PSGallery instead of from
  Chocolatey.
- Moved unit tests to correct folder structure.
- Changed unit tests to use standard test templates.
- Updated all resources to meet HQRM standards and style guidelines.
- Added .gitignore file
- Added .gitattributes file to force line endings to CRLF to allow unit tests to
  work.
- xCertificateCommon:
  - Moved common code into new module CertificateCommon.psm1
  - Added standard exception code.
  - Renamed common functions Validate-* to use acceptable verb Test-*.
  - Added help to all functions.
- xCertificateImport:
  - Fixed bug with Test-TargetResource incorrectly detecting change required.
  - Reworked unit tests for improved code coverage to meet HQRM standards.
  - Created Integration tests for both importing and removing an imported certificate.
  - Added descriptions to MOF file.
  - Removed default parameter values for parameters that are required or keys.
  - Added verbose messages.
  - Split message and error strings into localization string files.
  - Added help to all functions.
- xPfxImport:
  - Fixed bug with Test-TargetResource incorrectly detecting change required.
  - Reworked unit tests for improved code coverage to meet HQRM standards.
  - Created Integration tests for both importing and removing an imported certificate.
  - Added descriptions to MOF file.
  - Removed default parameter values for parameters that are required or keys.
  - Added verbose messages.
  - Split message and error strings into localization string files.
  - Added help to all functions.
- xCertReq:
  - Cleaned up descriptions in MOF file.
  - Fixed bugs generating certificate when credentials are specified.
  - Allowed output of certificate request when credentials are specified.
  - Split message and error strings into localization string files.
  - Created unit tests and integration tests.
  - Improved logging output to enable easier debugging.
  - Added help to all functions.
- xPDT:
  - Renamed to match standard module name format (MSFT_x).
  - Modified to meet 100 characters or less line length where possible.
  - Split message and error strings into localization string files.
  - Removed unused functions.
  - Renamed functions to standard verb-noun form.
  - Added help to all functions.
  - Fixed bug in Wait-Win32ProcessEnd that prevented waiting for process to end.
  - Added Wait-Win32ProcessStop to wait for a process to stop.
  - Removed unused and broken scheduled task code.

## 2.1.0.0

- Fixed xCertReq to support CA Root Name with spaces

## 2.0.0.0

- Breaking Change - Updated xPfxImport Store parameter is now a key value making
  it mandatory
- Updated xPfxImport with new Ensure support
- Updated xPfxImport with support for the CurrentUser value
- Updated xPfxImport with validationset for the Store parameter
- Added new resource: xCertificateImport

## 1.1.0.0

- Added new resource: xPfxImport

## 1.0.1.0

- Minor documentation updates

## 1.0.0.0

- Initial public release of xCertificate module with following resources
  - xCertReq
