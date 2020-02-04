# Pericia.OpenPgp

[![Build status](https://dev.azure.com/glacasa/GithubBuilds/_apis/build/status/Pericia.OpenPgp-CI)](https://dev.azure.com/glacasa/GithubBuilds/_build/latest?definitionId=79)

Library with helper methods for OpenPGP use in .NET apps. Heavily based on [BouncyCastle Portable](https://github.com/novotnyllc/bc-csharp)

Still in early development, expect lots of fixes and API changes for quite some time. 

## API

`IOpenPgpKeyManagement`  

- `SearchHttpKeyServer(address, keyServer)`  
Search the public key for the e-mail address on the specified key server

- `SearchHttpKeyServer(address)`  
Search the public key for the e-mail address on the default key server [keys.openpgp.org](https://keys.openpgp.org)

- `SearchWebKeyDirectory(address)`  
Use the [Web Key Directory (WKD)](https://wiki.gnupg.org/WKD) protocol to search the public key for the e-mail address

- `GetHashedUserId(userName)`  
Generate the hashed user-id (hu), used by WKD protocol.  
The hu is the user part of the e-mail address, SHA-1 hashed and z-base32 converted.

`IOpenPgpEncryption`

- `Encrypt(message, publicKey)`  
Encypt the message using the provided public key
