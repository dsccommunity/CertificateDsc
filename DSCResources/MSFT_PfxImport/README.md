# Description

The resource is used to import a PFX certificate into a Windows certificate
store.

## Requirements

- Target machine must be running Windows Server 2008 R2 or later.
- Target machine must be running Windows 10 1709 or later or
  Windows Server 2016 1709 or later to import a certificate exported
  using `AES256_SHA256` cryptographic algorithm.
  If importing a PFX certificate exported with `AES256_SHA256` cryptographic
  algorithm the following error will occur:

  `The PFX file you are trying to import requires either a different password
  or membership in an Active Directory principal to which it is protected.`
