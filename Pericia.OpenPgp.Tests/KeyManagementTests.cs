using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace Pericia.OpenPgp.Tests
{
    public class KeyManagementTests
    {

        [Fact]
        public void GenerateKeyPairTest()
        {
            IOpenPgpKeyManagement keys = new OpenPgpKeyManagement();

            var keyPair = keys.GenerateKeyPair("dest@example.org", "pass phrase 1234");
            Assert.NotNull(keyPair);

            var otherKeyPair = keys.GenerateKeyPair("dest@example.org", "pass phrase 1234");
            Assert.NotEqual(keyPair.KeyId, otherKeyPair.KeyId);
        }

        [Fact]
        public void ImportTest()
        {
            IOpenPgpKeyManagement keys = new OpenPgpKeyManagement();

            var publicKeyBlock = @"-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: ProtonMail

xsBNBFYE8tYBCACnH05FAKnejlh2Pvpk7KRXT8SchyNNpfw8dcduVCJNOE+D
YvJF/3tPKujvODES6WDy2qrWU7ypC49ZS7wxpoEgIP4zfo/EqMNjJRvq2T7I
dIoj3eP8T0bQLbIkF5YexUqDXkD+ogEFXRcuFIq0dWAgAqeHtgQKKPlM18Qt
ilstfYJYQwAaSdz3N/KWAn3AbwubmfcJwBccdRHIrpD7Pv35pL88GZQ94EBq
jBZZMSHuZJtzu0NmKTPIuy6kBQxtg1+lc+a+WWGP88LwMia7puIKEOP3/789
Kq5YlS4MLemoHw3V/HDl3huz9Bc3ZTz6jf+XH8iXsIAR24veGNhfKv2PABEB
AAHNL2dsYWNhc2FAcHJvdG9ubWFpbC5jb20gPGdsYWNhc2FAcHJvdG9ubWFp
bC5jb20+wsB/BBABCAApBQJY5jnMBgsJBwgDAgkQi/xIGeYvSXcEFQgKAgMW
AgECGQECGwMCHgEACgkQi/xIGeYvSXf9vggAlvkRayvy2BeKH+r9wmGXaZOM
NSMUq5mjSce8g/EX0WS1cShwOkWQdoiDEUxE6OV2CsIo+wRdkLLdwTUHK8RM
T4GoDxn3sHYr4dXWGwUpQLhAB8KByhNRy7fm8jP2blS9Bohe4kB5vDITbL8x
KseajWK9v+3rQcON5cUoOwTmRqL97zAjL+t5iFI+raUD6jNVbN6rQw0c+IXZ
+VLfN465C6pcYIVMKgeu00LPlsUf9tzQ769hYNZsuadqZ0B4azBP6W8wSOuF
fV9YGvwGroZeqlH9WNvHaM7sUKrJTV7QsX2gXfhykzPrwTXf8zD8/2ud7vJq
rwMpt2gJZjlSsfB6Zc7ATQRWBPLWAQgArpqHuOWex4LkL9CihG6pvgn6WBib
jwIMYnYF/rvfos/5KywJrpApCITEiKpBNADjUyijSigtX4DXm6SZWFwWD96a
+Uz92jQRtf4Y6agun/EQaYBk4YbflGXnO1kHeCCRcEYINH7rbFykqtifXUT1
H9PVghwaOLu6csNof+U1pc3ROg01YnlnvJHUdZQEbIiBGe1Yofhd6zV9zEnx
Us5lHXYxz5CrbuzZc1uaEbBO6bSlSJ5KP7kxjgdQWH4mdhT+TA77SYPSBG7z
FOIse0r9HIecvGASmZsubNUU1o1pHgoqHXYPwelUX1F9zIYrQQbite9RMzkP
MPw+dCVGH5EsnQARAQABwsBpBBgBCAATBQJY5jnMCRCL/EgZ5i9JdwIbDAAK
CRCL/EgZ5i9Jd+5BCACGWfkdvtkR+gktydg6vF+H/d8ubGu4D9w+fHQDdgCA
o3JFyW/72iGCrYbJ4ubVvY74R7dyViCSRlY90yfDA32ltNK66mK+ndhsrW3o
kC9YXR5KFyBLo7zDegUxNC82bISDl+H/+6UU7jNJeKh1fkx6isSBvTcZK3Dz
wp3ro0WRnlN9FWank5Mtge7kOwfCz8E9YLm8aadzNpflj0aXcbpffk5q7vp7
VDqPPxFbAf1kpFDu3dGslDMklzbHyDgv5IfezYpr40m2jVI9hawn2hY60JNl
l7kkkgh8anR4kuki/pMoweSNxnOIORdQwMqqhe4GFmMfv8HC9wO1zGD8W2G9
=Ycp8
-----END PGP PUBLIC KEY BLOCK-----";

            var publicKey = keys.LoadPublicKey(publicKeyBlock);

            Utils.CheckFingerprint(publicKey, "4805b5106ca0eab809e16b798bfc4819e62f4977");
        }

        [Fact]
        public void ExportTest()
        {
            IOpenPgpKeyManagement keys = new OpenPgpKeyManagement();
            var passPhrase = "pass phrase 1234";
            var key = keys.GenerateKeyPair("Mail@example.org", passPhrase);

            // Public key
            var originalFingerPrint = key.PublicKey.GetFingerprint();

            var exportedPublicKey = keys.Export(key.PublicKey);

            var reimportedKey = keys.LoadPublicKey(exportedPublicKey);
            var reimportedFingerprint = reimportedKey.GetFingerprint();

            Assert.Equal(originalFingerPrint.Length, reimportedFingerprint.Length);
            for (int i = 0; i < originalFingerPrint.Length; i++)
            {
                Assert.Equal(originalFingerPrint[i], reimportedFingerprint[i]);
            }


            // Private key
            var exportedSecretKey = keys.Export(key);
            var reimportedSecretKey = keys.LoadSecretKey(exportedSecretKey);

            // Imported key should allow to decrypt message
            IOpenPgpEncryption pgp = new OpenPgpEncryption();

            var encrypted = pgp.Encrypt("Hello", key.PublicKey);
            var decrypted = pgp.Decrypt(encrypted, reimportedSecretKey, passPhrase);
            Assert.Equal("Hello", decrypted);
        }
    }
}
