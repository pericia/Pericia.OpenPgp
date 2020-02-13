﻿using System;
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

            var keyPair = pgp.GenerateKeyPair("dest@example.org", "pass phrase 1234");

            // We encrypt the message using the public key
            string message = "This message is very secret";
            var encrypted = pgp.Encrypt(message, keyPair.PublicKey);

            Assert.NotNull(encrypted);
            Assert.NotEqual(message, encrypted);

            // Now we can decrypt it with the private key
            var decrypted = pgp.Decrypt(encrypted, keyPair.PrivateKey);
            Assert.Equal(message, decrypted);

            // If we try to decrypt without private key, we should have an Exception
            var badKey = pgp.GenerateKeyPair("hacker@example.org", "pass phrase 5678");
            Assert.ThrowsAny<Exception>(() => pgp.Decrypt(encrypted, badKey.PrivateKey));
        }
    }
}
