using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace Pericia.OpenPgp.Tests
{
    public class EncryptionTests
    {

        [Fact]
        public void GenerateKeyPairTest()
        {
            IOpenPgpEncryption pgp = new OpenPgpEncryption();

            var keyPair = pgp.GenerateKeyPair("dest@example.org", "pass phrase 1234");
            Assert.NotNull(keyPair);

            var otherKeyPair = pgp.GenerateKeyPair("dest@example.org", "pass phrase 1234");
            Assert.NotEqual(keyPair.KeyId, otherKeyPair.KeyId);
        }

        [Fact]
        public void EncryptAndDecryptTest()
        {
            IOpenPgpEncryption pgp = new OpenPgpEncryption();

            string passPhrase = "This is my secret phrase";
            var keyPair = pgp.GenerateKeyPair("dest@example.org", passPhrase);

            // We encrypt the message using the public key
            string message = "This message is very secret";
            var encrypted = pgp.Encrypt(message, keyPair.PublicKey);

            Assert.NotNull(encrypted);
            Assert.NotEqual(message, encrypted);

            // Now we can decrypt it with the private key
            var decrypted = pgp.Decrypt(encrypted, keyPair.PrivateKey, passPhrase);
            Assert.NotEqual(message, decrypted);

            // If we try to decrypt without private key or its passphrase, we should have an Exception
            Assert.ThrowsAny<Exception>(() => pgp.Decrypt(encrypted, keyPair.PrivateKey, "not the passphrase"));

            var badKey = pgp.GenerateKeyPair("hacker@example.org", "yoman");
            Assert.ThrowsAny<Exception>(() => pgp.Decrypt(encrypted, badKey.PrivateKey, "yoman"));
        }
    }
}
