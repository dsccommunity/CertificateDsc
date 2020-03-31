# Description

The resource is used to import a PFX certificate into a Windows certificate
store.

## Requirements

- Target machine must be running Windows Server 2008 R2 or later.
- To import a certificate exported using `AES256_SHA256` cryptographic
  algorithm, the target machine must be running build 1709 or later of
  Windows 10 or Windows Server 2016.

  If importing a PFX certificate exported with `AES256_SHA256` cryptographic
  algorithm on a target machine running a Windows 10 or Windows Server 2016
  build earlier than 1709, the following error will occur:

  `The PFX file you are trying to import requires either a different password
  or membership in an Active Directory principal to which it is protected.`
