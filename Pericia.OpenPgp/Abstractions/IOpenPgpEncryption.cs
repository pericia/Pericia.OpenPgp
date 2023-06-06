using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Pericia.OpenPgp
{
    public interface IOpenPgpEncryption
    {
        string EncryptText(string message, PgpPublicKey publicKey);
        string EncryptText(byte[] message, PgpPublicKey publicKey);

        string DecryptText(string message, PgpSecretKey secretKey, string passPhrase);
        string DecryptText(byte[] message, PgpSecretKey secretKey, string passPhrase);

        //Stream EncryptFile(Stream file, PgpPublicKey publicKey);
    }
}
