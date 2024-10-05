# Change log for CertificateDsc

The format is based on and uses the types of changes according to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [6.0.0] - 2024-10-05

### Changed

- CertReq:
  - BREAKING CHANGE: Made Certificate FriendlyName a mandatory parameter - Fixes [Issue #269](https://github.com/dsccommunity/CertificateDsc/issues/269).
  - Consider FriendlyName + Template when getting existing certs - Fixes [Issue #121](https://github.com/dsccommunity/CertificateDsc/issues/121).
- CI Pipeline
  - Updated pipeline files to match current DSC Community patterns - fixes [Issue #274](https://github.com/dsccommunity/CertificateDsc/issues/274).
  - Updated HQRM and build steps to use windows-latest image.

### Changed

- Pin Gitversion to v5.* to stop build failing
- Added support for publishing code coverage to `CodeCov.io` and
  Azure Pipelines - Fixes [Issue #255](https://github.com/dsccommunity/CertificateDsc/issues/255).
- Updated build to use `Sampler.GitHubTasks` - Fixes [Issue #254](https://github.com/dsccommunity/CertificateDsc/issues/254).
- Corrected changelog.
- Updated pipeline tasks to latest pattern.
- Build pipeline: Removed unused `dscBuildVariable` tasks.
- Updated .github issue templates to standard - Fixes [Issue #263](https://github.com/dsccommunity/CertificateDsc/issues/263).
- Added Create_ChangeLog_GitHub_PR task to publish stage of build pipeline.
- Added SECURITY.md.
- Updated pipeline Deploy_Module anb Code_Coverage jobs to use ubuntu-latest
  images - Fixes [Issue #262](https://github.com/dsccommunity/CertificateDsc/issues/262).
- Updated pipeline unit tests and integration tests to use Windows Server 2019 and
  Windows Server 2022 images - Fixes [Issue #262](https://github.com/dsccommunity/CertificateDsc/issues/262).

### Fixed

- Fixed pipeline by replacing the GitVersion task in the `azure-pipelines.yml`
  with a script.
- Passed in an empty string to X509Certificate2.Import so that we do not get MethodCountCouldNotFindBest exception when using a null
  password for the PFX certificate. Fixes [Issue #258](https://github.com/dsccommunity/CertificateDsc/issues/258)

## [5.1.0] - 2021-02-26

### Added

- PfxImport:
  - Added Base64Content parameter to specify the content of a PFX file that can
    be included in the configuration MOF - Fixes [Issue #241](https://github.com/dsccommunity/CertificateDsc/issues/241).
- CertificateImport:
  - Added Base64Content parameter to specify the content of a certificate file
    that can be included in the configuration MOF - Fixes [Issue #241](https://github.com/dsccommunity/CertificateDsc/issues/241).

### Changed

- Fix bug where `Import-PfxCertificateEx` would not install private keys in the
  ALLUSERSPROFILE path when importing to LocalMachine store. [Issue #248](https://github.com/dsccommunity/CertificateDsc/issues/248).
- Renamed `master` branch to `main` - Fixes [Issue #237](https://github.com/dsccommunity/CertificateDsc/issues/237).
- Updated `GitVersion.yml` to latest pattern - Fixes [Issue #245](https://github.com/dsccommunity/CertificateDsc/issues/245).
- Changed `Test-Thumbprint` to cache supported hash algorithms to increase
  performance - Fixes [Issue #221](https://github.com/dsccommunity/CertificateDsc/issues/221).
- Added warning messages into empty catch blocks in `Certificate.PDT` module to
  assist with debugging.

### Fixed

- Removed requirement for tests to use `New-SelfSignedCertificateEx` from
  [TechNet Gallery due to retirement](https://docs.microsoft.com/teamblog/technet-gallery-retirement).
  This will prevent tests from running on Windows Server 2012 R2 - Fixes [Issue #250](https://github.com/dsccommunity/CertificateDsc/issues/250).
- Fixed FIPS support when used in versions of PowerShell Core 6 & PowerShell 7.
- Moved thumbprint generation for testing into helper function `New-CertificateThumbprint`
  and fixed tests for validating FIPS thumbprints in `Test-Thumbprint` so that it
  runs on PowerShell Core/7.x.

## [5.0.0] - 2020-10-16

### Changed

- Corrected incorrectly located entries in `CHANGELOG.MD`.
- Fix bug `Find-Certificate` when invalid certificate path is passed - fixes
  [Issue #208](https://github.com/dsccommunity/CertificateDsc/issues/208).
- CertReq:
  - Added `Get-CertificateCommonName` function as a fix for multiple
    certificates being issued when having a third party CA which doesn't
    format the Issuer CN in the same order as a MS CA - fixes [Issue #207](https://github.com/dsccommunity/CertificateDsc/issues/207).
  - Updated `Compare-CertificateIssuer` to use the new
    `Get-CertificateCommonName` function.
  - Added check for X500 subject name in Get-TargetResource, which already
    exists in Test- and Set-TargetResource - fixes [Issue #210](https://github.com/dsccommunity/CertificateDsc/issues/210).
  - Corrected name of working path to remove `x` - fixes [Issue #211](https://github.com/dsccommunity/CertificateDsc/issues/211).
- BREAKING CHANGE: Changed resource prefix from MSFT to DSC.
- Updated to use continuous delivery pattern using Azure DevOps - Fixes
  [Issue #215](https://github.com/dsccommunity/CertificateDsc/issues/215).
- Updated Examples and Module Manifest to be DSC Community from Microsoft.
- Fix style issues in `Certificate.PDT` and `Certificate.Common` modules.
- Update badges in README.MD to refer to correct pipeline.
- Correct version number in `GitVersion.yml` file.
- Change Azure DevOps Pipeline definition to include `source/*` - Fixes [Issue #226](https://github.com/dsccommunity/CertificateDsc/issues/226).
- Updated pipeline to use `latest` version of `ModuleBuilder` - Fixes [Issue #226](https://github.com/dsccommunity/CertificateDsc/issues/226).
- Merge `HISTORIC_CHANGELOG.md` into `CHANGELOG.md` - Fixes [Issue #227](https://github.com/dsccommunity/CertificateDsc/issues/227).
- Fixed build failures caused by changes in `ModuleBuilder` module v1.7.0
  by changing `CopyDirectories` to `CopyPaths` - Fixes [Issue #230](https://github.com/dsccommunity/CertificateDsc/issues/230).
- Updated to use the common module _DscResource.Common_ - Fixes [Issue #229](https://github.com/dsccommunity/CertificateDsc/issues/229).
- Pin `Pester` module to 4.10.1 because Pester 5.0 is missing code
  coverage - Fixes [Issue #233](https://github.com/dsccommunity/CertificateDsc/issues/233).
- Added a catch for certreq generic errors which fixes [Issue #224](https://github.com/dsccommunity/CertificateDsc/issues/224)
- CertificateDsc
  - Automatically publish documentation to GitHub Wiki - Fixes [Issue #235](https://github.com/dsccommunity/CertificateDsc/issues/235).

### Added

- PfxImport:
  - Added example showing importing private key using `PsDscRunAsCredential`
    to specify an administrator account - Fixes [Issue #213](https://github.com/dsccommunity/CertificateDsc/issues/213).

## [4.7.0.0] - 2019-06-26

### Changed

- Opted into Common Tests 'Common Tests - Validate Localization' -
  fixes [Issue #195](https://github.com/dsccommunity/CertificateDsc/issues/195).
- Combined all `CertificateDsc.ResourceHelper` module functions into
  `CertificateDsc.Common` module and renamed to `CertificateDsc.CommonHelper`
  module.
- CertReq:
  - Fix error when ProviderName parameter is not encapsulated in
    double quotes - fixes [Issue #185](https://github.com/dsccommunity/CertificateDsc/issues/185).
- Refactor integration tests to update to latest standards.
- Refactor unit tests to update to latest standards.
- CertificateImport:
  - Refactor to use common functions and share more code with `PfxImport`
    resource.
  - Resource will now only throw an exception if the PFX file does not exist
    and it needs to be imported.
  - Removed file existence check from `Path` parameter to enable the resource
    to remove a certificate from the store without the need to have the
    access to the certificate file.
  - Removed ShouldProcess because it is not required by DSC Resources.
- CertificatePfx:
  - Refactor to use common functions and share more code with
    `CertificateImport` resource.
  - Resource will now only throw an exception if the certificate file does
    not exist and it needs to be imported.
- CertificateImport:
  - Added `FriendlyName` parameter to allow setting the certificate friendly
    name of the imported certificate - fixes [Issue #194](https://github.com/dsccommunity/CertificateDsc/issues/194).
- CertificatePfx:
  - Added `FriendlyName` parameter to allow setting the certificate friendly
    name of the imported certificate - fixes [Issue #194](https://github.com/dsccommunity/CertificateDsc/issues/194).

## [4.6.0.0] - 2019-05-15

### Changed

- CertReq:
  - Added `Compare-CertificateIssuer` function to checks if the
    Certificate Issuer matches the CA Root Name.
  - Changed `Compare-CertificateSubject` function to return false
    if `ReferenceSubject` is null.
  - Fixed exception when Certificate with empty Subject exists in
    Certificate Store - fixes [Issue #190](https://github.com/dsccommunity/CertificateDsc/issues/190).
  - Fixed bug matching existing certificate when Subject Alternate
    Name is specified and machine language is not en-US - fixes
    [Issue #193](https://github.com/dsccommunity/CertificateDsc/issues/193).
  - Fixed bug matching existing certificate when Template Name
    is specified and machine language is not en-US - fixes
    [Issue #193](https://github.com/dsccommunity/CertificateDsc/issues/193).
  - Changed `Import-CertificateEx` function to use `X509Certificate2Collection`
    instead of `X509Certificate2` to support importing certificate chains

## [4.5.0.0] - 2019-04-03

### Changed

- Fix example publish to PowerShell Gallery by adding `gallery_api`
  environment variable to `AppVeyor.yml` - fixes [Issue #187](https://github.com/dsccommunity/CertificateDsc/issues/187).
- CertificateDsc.Common.psm1
  - Exclude assemblies that set DefinedTypes to null instead of an empty array
    to prevent failures on GetTypes(). This issue occurred with the
    Microsoft.WindowsAzure.Storage.dll assembly.

## [4.4.0.0] - 2019-02-20

### Changed

- Minor style corrections from PR for
  [Issue #161](https://github.com/dsccommunity/CertificateDsc/issues/161)
  that were missed.
- Opt-in to Example publishing to PowerShell Gallery - fixes
  [Issue #177](https://github.com/dsccommunity/CertificateDsc/issues/177).
- Changed Test-CertificateAuthority to return the template name if it finds the
  display name of the template in the certificate -fixes
  [Issue #147](https://github.com/dsccommunity/CertificateDsc/issues/147).

## [4.3.0.0] - 2019-01-10

### Changed

- CertificateImport:
  - Updated certificate import to only use Import-CertificateEx - fixes
    [Issue #161](https://github.com/dsccommunity/CertificateDsc/issues/161).
- Update LICENSE file to match the Microsoft Open Source Team standard - fixes
  [Issue 164](https://github.com/dsccommunity/CertificateDsc/issues/164).
- Opted into Common Tests - fixes
  [Issue 168](https://github.com/dsccommunity/CertificateDsc/issues/168):
  - Required Script Analyzer Rules
  - Flagged Script Analyzer Rules
  - New Error-Level Script Analyzer Rules
  - Custom Script Analyzer Rules
  - Validate Example Files To Be Published
  - Validate Markdown Links
  - Relative Path Length
- CertificateExport:
  - Fixed bug causing PFX export with matchsource enabled to fail - fixes
    [Issue 117](https://github.com/dsccommunity/CertificateDsc/issues/117)
- Added DSCResourcesToExport to the CertificateDSC.psd1
- CertReq:
  - Added key lengths for ECDH key type.
  - Added Key type to check for correct key lengths. - fixes
    [Issue 113](https://github.com/dsccommunity/CertificateDsc/issues/113)
  - Added request type parameter to support PKCS10.
  - Simplified unit test comparison certificate request strings to make
    tests easier to read.
  - Improved unit test layout and updated to meet standards.
  - Fixed bug in certificate renewal with `RenewalCert` attribute in the
    incorrect section - fixes
    [Issue 172](https://github.com/dsccommunity/CertificateDsc/issues/172)
  - Fixed bug in certificate renewal when subject contains X500 path that
    is in a different order - fixes
    [Issue 173](https://github.com/dsccommunity/CertificateDsc/issues/173)

## [4.2.0.0] - 2018-09-05

### Changed

- Added a CODE_OF_CONDUCT.md with the same content as in the README.md - fixes
  [Issue #139](https://github.com/dsccommunity/CertificateDsc/issues/139).
- Refactored module folder structure to move resource to root folder of
  repository and remove test harness - fixes
  [Issue #142](https://github.com/dsccommunity/CertificateDsc/issues/142).
- Updated Examples to support deployment to PowerShell Gallery scripts.
- Correct configuration names in Examples - fixes
  [Issue #150](https://github.com/dsccommunity/CertificateDsc/issues/150).
- Correct filename case of `CertificateDsc.Common.psm1` - fixes
  [Issue #149](https://github.com/dsccommunity/CertificateDsc/issues/149).
- Remove exclusion of all tags in appveyor.yml, so all common tests can be run
  if opt-in.
- PfxImport:
  - Added requirements to README.MD to specify cryptographic algorithm
    support - fixes
    [Issue #153](https://github.com/dsccommunity/CertificateDsc/issues/153).
  - Changed Path parameter to be optional to fix error when ensuring certificate
    is absent and certificate file does not exist on disk - fixes
    [Issue #136](https://github.com/dsccommunity/CertificateDsc/issues/136).
  - Removed ShouldProcess because it is not required by DSC Resources.
  - Minor style corrections.
  - Changed unit tests to be non-destructive.
  - Improved naming and description of example files.
  - Added localization string ID suffix for all strings.
- Added .VSCode settings for applying DSC PSSA rules - fixes
[Issue #157](https://github.com/dsccommunity/CertificateDsc/issues/157).

## [4.1.0.0] - 2018-06-13

### Changed

- PfxImport:
  - Changed so that PFX will be reimported if private key is not
    installed - fixes
    [Issue #129](https://github.com/dsccommunity/CertificateDsc/issues/129).
  - Corrected to meet style guidelines.
  - Corrected path parameter description - fixes
  [Issue #125](https://github.com/dsccommunity/CertificateDsc/issues/125).
  - Refactored to remove code duplication by creating Get-CertificateStorePath.
  - Improved unit tests to meet standards and provide better coverage.
  - Improved integration tests to meet standards and provide better coverage.
- CertificateDsc.Common:
  - Corrected to meet style guidelines.
  - Added function Get-CertificateStorePath for generating Certificate Store
    path.
  - Remove false verbose message from `Test-Thumbprint` - fixes
  [Issue #127](https://github.com/dsccommunity/CertificateDsc/issues/127).
- CertReq:
  - Added detection for FIPS mode in Test-Thumbprint - fixes
  [Issue #107](https://github.com/dsccommunity/CertificateDsc/issues/107).

## [4.0.0.0] - 2018-05-03

### Changed

- BREAKING CHANGE
  - Renamed xCertificate to CertificateDsc - fixes
  [Issue #114](https://github.com/dsccommunity/xCertificate/issues/114).
  - Changed all MSFT_xResourceName to MSFT_ResourceName.
  - Updated DSCResources, Examples, Modules and Tests for new naming.
  - Updated Year to 2018 in License and Manifest.
  - Updated README.md from xCertificate to CertifcateDsc
  - Removed unnecessary code from:
    - CertificateDsc\Modules\CertificateDsc\DSCResources\MSFT_CertReq\MSFT_CertReq.psm1
      - Deleted `$rspPath = [System.IO.Path]::ChangeExtension($workingPath, '.rsp')`

## [3.2.0.0] - 2018-02-08

### Changed

- Get-CertificateTemplateName: Fix missing template name

## [3.1.0.0] - 2017-12-20

### Changed

- xCertReq:
  - Fixed behaviour to allow certificate templates with spaces in the name
- Added `Documentation and Examples` section to Readme.md file - see
  [issue #98](https://github.com/dsccommunity/xCertificate/issues/98).
- Changed description in Credential parameter of xPfxImport resource
  to correctly generate parameter documentation in Wiki - see
  [Issue #103](https://github.com/dsccommunity/xCertificate/issues/103).
- Changed description in Credential parameter of xCertReq resource
  to clarify that a PSCredential object should be used.
- Updated tests to meet Pester V4 guidelines - fixes
  [Issue #105](https://github.com/dsccommunity/xCertificate/issues/105).
- Add support for Windows Server 2008 R2 which does not contain PKI
  module so is missing `Import-PfxCertificate` and `Import-Certificate`
  cmdlets - fixes
  [Issue #46](https://github.com/dsccommunity/xCertificate/issues/46).

## [3.0.0.0] - 2017-08-23

### Changed

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
- Converted files with UTF8 with BOM over to UTF8 - fixes
  [Issue 87](https://github.com/dsccommunity/xCertificate/issues/87).
- Converted to use auto-documentation/wiki format - fixes
  [Issue 84](https://github.com/dsccommunity/xCertificate/issues/84).

## [2.8.0.0] - 2017-07-12

### Changed

- xCertReq:
  - Added FriendlyName parameter to xCertReq.
  - Changed exceptions to be raised using New-InvalidOperationException from
  PSDscResources.
  - Changed integration tests to use Config Data instead of value in config to
  support additional tests.
  - Converted unit tests to use Get-InvalidOperationRecord in CommonTestHelper.
  - Improved unit test style to match standard layout.
  - Minor corrections to style to be HQRM compliant.
  - Improved Verbose logging by writing all lines of CertReq.exe output.
  - Fixed CA auto-detection to work when CA name contains a space.
- Corrected all makrdown rule violations in README.MD.
- Added markdownlint.json file to enable line length rule checking in VSCode
  with [MarkdownLint extension](https://marketplace.visualstudio.com/items?itemName=DavidAnson.vscode-markdownlint)
  installed.
- Added the VS Code PowerShell extension formatting settings that cause
  PowerShell files to be formatted as per the DSC Resource kit style guidelines.
- Fixed verbose preference not being passed to CertificateDsc.Common functions -
  fixes [Issue 70](https://github.com/dsccommunity/xCertificate/issues/70).
- Converted all calls to `New-InvalidArgumentError` function to
  `New-InvalidArgumentException` found in `CertificateDsc.ResourceHelper` - fixes
  [Issue 68](https://github.com/dsccommunity/xCertificate/issues/68)
- Replaced all calls to `Write-Error` with calls to
  `New-InvalidArgumentException` and `New-InvalidOperationException`
- xWaitForCertificateServices:
  - Added new resource.
- Cleaned up example format to meet style guidelines and changed examples to
  issue 2048 bit certificates.
- Fixed spelling error in xCertificateExport Issuer parameter description.
- Prevent unit tests from DSCResource.Tests from running during test
  execution - fixes
  [Issue 100](https://github.com/dsccommunity/xCertificate/issues/100).

## [2.7.0.0] - 2017-06-01

### Changed

- Added integration test to test for conflicts with other common resource kit
  modules.
- Prevented ResourceHelper and Common module cmdlets from being exported to
  resolve conflicts with other resource modules.

## [2.6.0.0] - 2017-05-31

### Changed

- Added mandatory properties for xPfxImport resource example.
- xCertReq:
  - Fixed issue where xCertReq does not identify when DNS Names in SANs are
    incorrect.
  - Added Certificate Authority auto-discovery to resource xCertReq.
  - Added SAN and certificate template name to xCertReq's Get-TargetResource
  - Added new parameter UseMachineContext to be able to use CA templates that
    try to fill the subject alternative name.
- CertificateDSc.Common:
  - Added function Get-CertificateTemplateName to retrieve template name
  - Added function Get-CertificateSan to retrieve subject alternative name
  - Added function Find-CertificateAuthority to enable auto-discovery

## [2.5.0.0] - 2017-04-19

### Changed

- Fixed issue where xCertReq does not process requested certificate when
  credentials parameter set and PSDscRunAsCredential not passed. See
  [issue](https://github.com/dsccommunity/xCertificate/issues/49)

## [2.4.0.0] - 2017-03-08

### Changed

- Converted AppVeyor build process to use AppVeyor.psm1.
- Correct Param block to meet guidelines.
- Moved shared modules into modules folder.
- xCertificateExport:
  - Added new resource.
- Cleanup xCertificate.psd1 to remove unnecessary properties.
- Converted AppVeyor.yml to use DSCResource.tests shared code.
- Opted-In to markdown rule validation.
- Examples modified to meet standards for auto documentation generation.

## [2.3.0.0] - 2016-12-14

### Changed

- xCertReq:
  - Added additional parameters KeyLength, Exportable, ProviderName, OID,
    KeyUsage, CertificateTemplate, SubjectAltName
- Fixed most markdown errors in Readme.md.
- Corrected Parameter decoration format to be consistent with guidelines.

## [2.2.0.0] - 2016-11-02

### Changed

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
  - Created Integration tests for both importing and removing an imported
    certificate.
  - Added descriptions to MOF file.
  - Removed default parameter values for parameters that are required or keys.
  - Added verbose messages.
  - Split message and error strings into localization string files.
  - Added help to all functions.
- xPfxImport:
  - Fixed bug with Test-TargetResource incorrectly detecting change required.
  - Reworked unit tests for improved code coverage to meet HQRM standards.
  - Created Integration tests for both importing and removing an imported
    certificate.
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

## [2.1.0.0] - 2016-06-29

### Changed

- Fixed xCertReq to support CA Root Name with spaces

## [2.0.0.0] - 2016-05-18

### Changed

- Breaking Change - Updated xPfxImport Store parameter is now a key value making
  it mandatory
- Updated xPfxImport with new Ensure support
- Updated xPfxImport with support for the CurrentUser value
- Updated xPfxImport with validationset for the Store parameter
- Added new resource: xCertificateImport

## [1.1.0.0] - 2015-12-03

### Changed

- Added new resource: xPfxImport

## [1.0.1.0] - 2015-07-24

### Changed

- Minor documentation updates

## [1.0.0.0] - 2015-06-17

### Changed

- Initial public release of xCertificate module with following resources
  - xCertReq
