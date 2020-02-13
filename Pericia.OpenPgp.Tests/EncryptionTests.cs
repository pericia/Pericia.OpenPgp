using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace Pericia.OpenPgp.Tests
{
    public class EncryptionTests
    {

        [Fact]
        public void EncryptAndDecryptTest()
        {
            IOpenPgpEncryption pgp = new OpenPgpEncryption();
            IOpenPgpKeyManagement keys = new OpenPgpKeyManagement();

            var passPhrase = "pass phrase 1234";

            var keyPair = keys.GenerateKeyPair("dest@example.org", passPhrase);

            // We encrypt the message using the public key
            string message = "This message is very secret";
            var encrypted = pgp.Encrypt(message, keyPair.PublicKey);

            Assert.NotNull(encrypted);
            Assert.NotEqual(message, encrypted);

            // Now we can decrypt it with the private key
            var decrypted = pgp.Decrypt(encrypted, keyPair, passPhrase);
            Assert.Equal(message, decrypted);

            // If we try to decrypt without private key or with bad password, we should have an Exception
            var badPassPhrase = "pass phrase 5678";
            Assert.ThrowsAny<Exception>(() => pgp.Decrypt(encrypted, keyPair, badPassPhrase));

            var badKey = keys.GenerateKeyPair("hacker@example.org", badPassPhrase);
            Assert.ThrowsAny<Exception>(() => pgp.Decrypt(encrypted, badKey, badPassPhrase));
        }
    }
}
