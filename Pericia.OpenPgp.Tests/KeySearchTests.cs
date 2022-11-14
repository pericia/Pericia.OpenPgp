using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace Pericia.OpenPgp.Tests
{
    public class KeySearchTests
    {

        [Fact]
        public async Task SearchErrorTest()
        {
            IOpenPgpKeySearch pgpKeys = new OpenPgpKeySearch(new TestHttpClientFactory(), new NullLogger<OpenPgpKeySearch>());

            await Assert.ThrowsAsync<FormatException>(() => pgpKeys.SearchWebKeyDirectory("notanaddress"));

            var inexistantEmail = "doesntexist@example.org";
            var inexistantKey = await pgpKeys.SearchWebKeyDirectory(inexistantEmail);
            Assert.Null(inexistantKey);

            inexistantKey = await pgpKeys.SearchHttpKeyServer(inexistantEmail);
            Assert.Null(inexistantKey);
        }

        [Fact]
        public async Task SearchWebKeyDirectoryDirectTest()
        {

            IOpenPgpKeySearch pgpKeys = new OpenPgpKeySearch(new TestHttpClientFactory(), new NullLogger<OpenPgpKeySearch>());

            var email = "blog@lacasa.fr";
            var key = await pgpKeys.SearchWebKeyDirectory(email);

            Assert.NotNull(key);

            Utils.CheckFingerprint(key, "4805b5106ca0eab809e16b798bfc4819e62f4977");
        }

        [Fact]
        public async Task SearchWebKeyDirectoryAdvancedTest()
        {
            IOpenPgpKeySearch pgpKeys = new OpenPgpKeySearch(new TestHttpClientFactory(), new NullLogger<OpenPgpKeySearch>());

            var email = "glacasa@protonmail.com";
            var key = await pgpKeys.SearchWebKeyDirectory(email);

            Assert.NotNull(key);

            Utils.CheckFingerprint(key, "4805b5106ca0eab809e16b798bfc4819e62f4977");
        }

        [Fact]
        public async Task SearchHttpKeyserverProtocol()
        {
            IOpenPgpKeySearch pgpKeys = new OpenPgpKeySearch(new TestHttpClientFactory(), new NullLogger<OpenPgpKeySearch>());

            var email = "blog@lacasa.fr";
            var key = await pgpKeys.SearchHttpKeyServer(email);

            Assert.NotNull(key);

            Utils.CheckFingerprint(key, "4805b5106ca0eab809e16b798bfc4819e62f4977");
        }

        [Fact]
        public void HashedUserTest()
        {
            IOpenPgpKeySearch pgpKeys = new OpenPgpKeySearch(new TestHttpClientFactory(), new NullLogger<OpenPgpKeySearch>());

            var hu = pgpKeys.GetHashedUserId("me");
            Assert.Equal("s8y7oh5xrdpu9psba3i5ntk64ohouhga", hu);
        }
    }
}
