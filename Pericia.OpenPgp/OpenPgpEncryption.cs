using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Pericia.OpenPgp
{
    public class OpenPgpEncryption : IOpenPgpEncryption
    {

        public PgpKeyPair GenerateKeyPair(string identity, string passPhrase)
        {
            if (string.IsNullOrEmpty(identity)) throw new ArgumentException("Identity must be supplied", nameof(identity));
            if (string.IsNullOrEmpty(passPhrase)) throw new ArgumentException("Pass phrase must be supplied", nameof(passPhrase));

            IAsymmetricCipherKeyPairGenerator kpg = GeneratorUtilities.GetKeyPairGenerator("RSA");

            kpg.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), new SecureRandom(), 1024, 25));

            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();

            PgpSecretKey secretKey = new PgpSecretKey(
                PgpSignature.DefaultCertification,
                PublicKeyAlgorithmTag.RsaGeneral,
                kp.Public,
                kp.Private,
                DateTime.UtcNow,
                identity,
                SymmetricKeyAlgorithmTag.Cast5,
                passPhrase.ToCharArray(),
                null,
                null,
                new SecureRandom()
                );

            return new PgpKeyPair(secretKey.PublicKey, secretKey.ExtractPrivateKey(passPhrase.ToCharArray()));
        }

        public string Encrypt(string message, PgpPublicKey publicKey)
        {
            if (string.IsNullOrEmpty(message)) throw new ArgumentException("Message must be supplied", nameof(message));

            var messageData = Encoding.UTF8.GetBytes(message);
            return Encrypt(messageData, publicKey);
        }


        public string Encrypt(byte[] message, PgpPublicKey publicKey)
        {
            if (message == null || message.Length == 0) throw new ArgumentException("Message must be supplied", nameof(message));
            if (publicKey == null) throw new ArgumentException("Public key must be supplied", nameof(publicKey));

            byte[] processedData = Compress(message, PgpLiteralData.Console, CompressionAlgorithmTag.Zip);

            MemoryStream bOut = new MemoryStream();
            Stream output = new ArmoredOutputStream(bOut);


            PgpEncryptedDataGenerator encGen = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, true, new SecureRandom());
            encGen.AddMethod(publicKey);

            Stream encOut = encGen.Open(output, processedData.Length);

            encOut.Write(processedData, 0, processedData.Length);
            encOut.Close();

            output.Close();

            return Encoding.UTF8.GetString(bOut.ToArray());
        }

        private static byte[] Compress(byte[] clearData, string fileName, CompressionAlgorithmTag algorithm)
        {
            MemoryStream bOut = new MemoryStream();

            PgpCompressedDataGenerator comData = new PgpCompressedDataGenerator(algorithm);
            Stream cos = comData.Open(bOut); // open it with the final destination
            PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();

            // we want to Generate compressed data. This might be a user option later,
            // in which case we would pass in bOut.
            Stream pOut = lData.Open(
            cos,                    // the compressed output stream
            PgpLiteralData.Binary,
            fileName,               // "filename" to store
            clearData.Length,       // length of clear data
            DateTime.UtcNow         // current time
            );

            pOut.Write(clearData, 0, clearData.Length);
            pOut.Close();

            comData.Close();

            return bOut.ToArray();
        }

        public string Decrypt(string message, PgpPrivateKey privateKey, string passPhrase)
        {
            throw new NotImplementedException();
        }
    }
}
