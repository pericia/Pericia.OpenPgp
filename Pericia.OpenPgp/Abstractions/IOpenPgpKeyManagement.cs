using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Pericia.OpenPgp
{
    public interface IOpenPgpKeyManagement
    {
        PgpSecretKey GenerateKeyPair(string identity, string passPhrase);

        string Export(PgpPublicKey publicKey);
        string Export(PgpSecretKey secretKey);

        PgpPublicKey LoadPublicKey(string key);
        PgpPublicKey LoadPublicKey(byte[] key);
        PgpPublicKey LoadPublicKey(Stream publicKey);
        PgpSecretKey LoadSecretKey(string key);
        PgpSecretKey LoadSecretKey(byte[] key);
        PgpSecretKey LoadSecretKey(Stream key);
    }
}
