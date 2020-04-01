# Change log for CertificateDsc

The format is based on and uses the types of changes according to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
