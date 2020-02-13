using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using Xunit;

namespace Pericia.OpenPgp.Tests
{
    public static class Utils
    {

        public static void CheckFingerprint(PgpPublicKey key, string expectedFingerprint)
        {
            var fingerprint = key.GetFingerprint();
            for (int i = 0; i < fingerprint.Length; i++)
            {
                var expectedByteValue = int.Parse(expectedFingerprint.Substring(i * 2, 2), NumberStyles.HexNumber);
                Assert.Equal(expectedByteValue, fingerprint[i]);
            }
        }
    }
}
