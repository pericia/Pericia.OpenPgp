﻿using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.Collections.Generic;
using System.Net.Mail;
using System.Text;
using System.Threading.Tasks;

namespace Pericia.OpenPgp
{
    public interface IOpenPgpKeySearch
    {
        Task<PgpPublicKey?> SearchHttpKeyServer(string address);
        Task<PgpPublicKey?> SearchHttpKeyServer(MailAddress address);
        Task<PgpPublicKey?> SearchHttpKeyServer(string address, string keyServer);
        Task<PgpPublicKey?> SearchHttpKeyServer(MailAddress address, string keyServer);

        Task<PgpPublicKey?> SearchWebKeyDirectory(string address);
        Task<PgpPublicKey?> SearchWebKeyDirectory(MailAddress address);

        string GetHashedUserId(string userName);
        string GetHashedUserId(MailAddress address);
    }
}
