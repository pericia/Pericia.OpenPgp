# Pericia.OpenPgp

[![Build status](https://dev.azure.com/glacasa/GithubBuilds/_apis/build/status/Pericia.OpenPgp-CI)](https://dev.azure.com/glacasa/GithubBuilds/_build/latest?definitionId=79)

Library with helper methods for OpenPGP use in .NET apps. Heavily based on [BouncyCastle](https://www.bouncycastle.org/csharp/)

Still in early development, expect lots of fixes and API changes for quite some time. 

## API

`IOpenPgpEncryption`

- `Encrypt(message, publicKey)`  
Encypt the message using the provided public key

- `Decrypt(message, secretKey, passPhrase)`
Decrypt the message using the provided private key and its pass phrase

`IOpenPgpKeyManagement`  

- `GenerateKeyPair(string identity, string passPhrase)`  
Generate a new pgp key pair

- `Export(key)`
Export a public key or secret key to armored string

- `LoadPublicKey(key)`
Load a public key from an armored string

- `LoadSecretKey(key)`
Load a secret key from an armored string

`IOpenPgpKeySearch`  

- `SearchHttpKeyServer(address, keyServer)`  
Search the public key for the e-mail address on the specified key server

- `SearchHttpKeyServer(address)`  
Search the public key for the e-mail address on the default key server [keys.openpgp.org](https://keys.openpgp.org)

- `SearchWebKeyDirectory(address)`  
Use the [Web Key Directory (WKD)](https://wiki.gnupg.org/WKD) protocol to search the public key for the e-mail address

- `GetHashedUserId(userName)`  
Generate the hashed user-id (hu), used by WKD protocol.  
The hu is the user part of the e-mail address, SHA-1 hashed and z-base32 converted.