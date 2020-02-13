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
    public class OpenPgpKeyManagement : IOpenPgpKeyManagement
    {

        public PgpSecretKey GenerateKeyPair(string identity, string passPhrase)
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

            return secretKey;
            //return new PgpKeyPair(secretKey.PublicKey, secretKey.ExtractPrivateKey(passPhrase.ToCharArray()));
        }

        public PgpPublicKey LoadPublicKey(string publicKey)
        {
            byte[] byteArray = Encoding.ASCII.GetBytes(publicKey);
            return LoadPublicKey(byteArray);
        }

        public PgpPublicKey LoadPublicKey(byte[] publicKey)
        {
            Stream inputStream = new MemoryStream(publicKey);
            return LoadPublicKey(inputStream);
        }

        private PgpPublicKey LoadPublicKey(Stream inputStream)
        {
            var armoredStream = PgpUtilities.GetDecoderStream(inputStream);
            var pgpPub = new PgpPublicKeyRingBundle(armoredStream);

            foreach (PgpPublicKeyRing keyRing in pgpPub.GetKeyRings())
            {
                foreach (PgpPublicKey key in keyRing.GetPublicKeys())
                {
                    if (key.IsEncryptionKey)
                    {
                        return key;
                    }
                }
            }

            throw new ArgumentException("Can't find encryption key in key ring.");
        }

        public PgpSecretKey LoadSecretKey(string key)
        {
            byte[] byteArray = Encoding.ASCII.GetBytes(key);
            return LoadSecretKey(byteArray);
        }

        public PgpSecretKey LoadSecretKey(byte[] key)
        {
            Stream inputStream = new MemoryStream(key);
            return LoadSecretKey(inputStream);
        }

        private PgpSecretKey LoadSecretKey(Stream inputStream)
        {
            var armoredStream = PgpUtilities.GetDecoderStream(inputStream);
            var pgpSecretKeyBundle = new PgpSecretKeyRingBundle(armoredStream);

            foreach (PgpSecretKeyRing keyRing in pgpSecretKeyBundle.GetKeyRings())
            {
                return keyRing.GetSecretKey();
            }

            throw new ArgumentException("Can't find secret key in key ring.");
        }

        public string Export(PgpPublicKey publicKey)
        {
            return Export(publicKey.GetEncoded());
        }

        public string Export(PgpSecretKey secretKey)
        {
            return Export(secretKey.GetEncoded());
        }

        private string Export(byte[] key)
        {
            MemoryStream bOut = new MemoryStream();
            using (ArmoredOutputStream armorOut = new ArmoredOutputStream(bOut))
            {
                armorOut.Write(key);
                armorOut.Flush();
            }
            bOut.Position = 0;
            var reader = new StreamReader(bOut);
            return reader.ReadToEnd();
        }


    }
}
