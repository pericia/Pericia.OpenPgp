﻿using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.Collections.Generic;
using System.Text;

namespace Pericia.OpenPgp
{
    public interface IOpenPgp
    {
        string Encrypt(string message, PgpPublicKey publicKey);
        string Encrypt(byte[] message, PgpPublicKey publicKey);
    }
}
