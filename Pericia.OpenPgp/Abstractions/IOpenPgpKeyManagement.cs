using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.Collections.Generic;
using System.Text;

namespace Pericia.OpenPgp
{
    public interface IOpenPgpKeyManagement
    {
        PgpKeyPair GenerateKeyPair(string identity, string passPhrase);

        PgpPublicKey LoadPublicKey(string key);
        PgpPrivateKey LoadPrivateKey(string key, string passPhrase);

        string Export(PgpPublicKey publicKey);
        string Export(PgpSecretKey secretKey);
    }
}
