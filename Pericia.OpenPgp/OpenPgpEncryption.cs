﻿using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Linq;
using System.Text;

namespace Pericia.OpenPgp
{
    public class OpenPgpEncryption : IOpenPgpEncryption
    {

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


        private string Decrypt(Stream input, PgpSecretKey secretKey, string passPhrase)
        {
            input = PgpUtilities.GetDecoderStream(input);

            PgpObjectFactory pgpObjF = new PgpObjectFactory(input);
            PgpEncryptedDataList enc;
            PgpObject obj = pgpObjF.NextPgpObject();
            if (obj is PgpEncryptedDataList)
            {
                enc = (PgpEncryptedDataList)obj;
            }
            else
            {
                enc = (PgpEncryptedDataList)pgpObjF.NextPgpObject();
            }

            PgpPublicKeyEncryptedData pbe = enc.GetEncryptedDataObjects().Cast<PgpPublicKeyEncryptedData>().First();
            Stream clear;
            PgpPrivateKey privateKey = secretKey.ExtractPrivateKey(passPhrase.ToCharArray());
            clear = pbe.GetDataStream(privateKey);
            PgpObjectFactory plainFact = new PgpObjectFactory(clear);
            PgpObject message = plainFact.NextPgpObject();
            if (message is PgpCompressedData)
            {
                PgpCompressedData cData = (PgpCompressedData)message;
                Stream compDataIn = cData.GetDataStream();
                PgpObjectFactory o = new PgpObjectFactory(compDataIn);
                message = o.NextPgpObject();
                if (message is PgpOnePassSignatureList)
                {
                    message = o.NextPgpObject();
                }

                var ld = (PgpLiteralData)message;
                var unc = ld.GetInputStream();
                var reader = new StreamReader(unc);
                return reader.ReadToEnd();
            }

            throw new NotImplementedException();
        }

        public string Decrypt(string message, PgpSecretKey secretKey, string passPhrase)
        {
            var messageData = Encoding.UTF8.GetBytes(message);
            return Decrypt(messageData, secretKey, passPhrase);
        }

        public string Decrypt(byte[] message, PgpSecretKey secretKey, string passPhrase)
        {
            var stream = new MemoryStream();
            stream.Write(message, 0, message.Length);
            stream.Position = 0;

            return Decrypt(stream, secretKey, passPhrase);
        }
    }
}
