using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace Pericia.OpenPgp.Tests
{
    public class KeyTests
    {

        [Fact]
        public async Task SearchErrorTest()
        {
            IOpenPgpKeyManagement pgpKeys = new OpenPgpKeyManagement();

            await Assert.ThrowsAsync<FormatException>(() => pgpKeys.SearchWebKeyDirectory("notanaddress"));

            var inexistantEmail = "doesntexist@example.org";
            var inexistantKey = await pgpKeys.SearchWebKeyDirectory(inexistantEmail);
            Assert.Null(inexistantKey);
        }

        [Fact]
        public async Task SearchKeyTest()
        {
            IOpenPgpKeyManagement pgpKeys = new OpenPgpKeyManagement();

            var email = "glacasa@protonmail.com";
            var key = await pgpKeys.SearchWebKeyDirectory(email);
            Assert.NotNull(key);

            var fingerprint = key.GetFingerprint();
            var expectedFingerprint = "4805b5106ca0eab809e16b798bfc4819e62f4977";
            for (int i = 0; i < fingerprint.Length; i++)
            {
                var expectedByteValue = int.Parse(expectedFingerprint.Substring(i * 2, 2), NumberStyles.HexNumber);
                Assert.Equal(expectedByteValue, fingerprint[i]);
            }
        }

        [Fact]
        public void HashedUserTest()
        {
            IOpenPgpKeyManagement pgpKeys = new OpenPgpKeyManagement();

            var hu = pgpKeys.GetHashedUser("me");
            Assert.Equal("s8y7oh5xrdpu9psba3i5ntk64ohouhga", hu);
        }
    }
}
