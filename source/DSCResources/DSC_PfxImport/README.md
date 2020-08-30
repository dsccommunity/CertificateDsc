# Description

The resource is used to import a PFX certificate into a Windows certificate
store.

## Credentials for Importing a Private Key

Depending on your operating system and domain configuration, you may need to
use a local or domain administrator credential to import certificates with a
private key. To do this, set the `PsDscRunAsCredential` parameter with this
resource to the credential of a local or domain administrator for this machine.

If you still have problems importing the PFX into the Local Machine store
please check the account specified in `PsDscRunAsCredential` has permissions
to `$env:SystemDrive:\Documents and Settings\All Users\Application Data\Microsoft\Crypto\RSA\MachineKeys`.
See [this page](https://docs.microsoft.com/en-us/troubleshoot/iis/cannot-import-ssl-pfx-local-certificate)
for more information.

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
