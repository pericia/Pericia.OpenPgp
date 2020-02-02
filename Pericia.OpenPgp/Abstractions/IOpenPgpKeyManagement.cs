using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.Collections.Generic;
using System.Net.Mail;
using System.Text;
using System.Threading.Tasks;

namespace Pericia.OpenPgp
{
    public interface IOpenPgpKeyManagement
    {

        Task<PgpPublicKey?> SearchWebKeyDirectory(string address);

        Task<PgpPublicKey?> SearchWebKeyDirectory(MailAddress address);

        string GetHashedUser(string address);
        string GetHashedUser(MailAddress address);
    }
}
