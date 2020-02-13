using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.Collections.Generic;
using System.Text;

namespace Pericia.OpenPgp
{
    public interface IOpenPgpKeyManagement
    {
        PgpSecretKey GenerateKeyPair(string identity, string passPhrase);

        PgpPublicKey LoadPublicKey(string key);
        PgpPublicKey LoadPublicKey(byte[] key);
        PgpSecretKey LoadSecretKey(string key);
        PgpSecretKey LoadSecretKey(byte[] key);

        string Export(PgpPublicKey publicKey);
        string Export(PgpSecretKey secretKey);
    }
}
