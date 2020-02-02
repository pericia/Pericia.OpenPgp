# Pericia.OpenPgp

[![Build status](https://dev.azure.com/glacasa/GithubBuilds/_apis/build/status/Pericia.OpenPgp-CI)](https://dev.azure.com/glacasa/GithubBuilds/_build/latest?definitionId=79)

Library with helper methods for OpenPGP use in .NET apps. Heavily based on [BouncyCastle Portable](https://github.com/novotnyllc/bc-csharp)

Still in early development, expect lots of fixes and API changes for quite some time. 

## API

`IOpenPgpKeyManagement`  

- `SearchWebKeyDirectory(address)`  
Use the [Web Key Directory (WKD)](https://wiki.gnupg.org/WKD) protocol to search an available public key for the e-mail address
  
`IOpenPgpEncryption`

- `Encrypt(message, publicKey)`  
Encypt the message using the provided public key
