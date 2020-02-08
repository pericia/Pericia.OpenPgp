﻿using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.Collections.Generic;
using System.Text;

namespace Pericia.OpenPgp
{
    public interface IOpenPgpEncryption
    {
        PgpKeyPair GenerateKeyPair(string identity, string passPhrase);

        string Encrypt(string message, PgpPublicKey publicKey);
        string Encrypt(byte[] message, PgpPublicKey publicKey);

        string Decrypt(string message, PgpPrivateKey privateKey, string passPhrase);
    }
}
