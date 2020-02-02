using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace Pericia.OpenPgp.Tests
{
    public class EncryptionTests
    {

        [Fact]
        public void EncryptMessageTest()
        {
            IOpenPgpEncryption pgp = new OpenPgpEncryption();

            //TODO test encryption and decryption with test public and private keys        

        }
    }
}
