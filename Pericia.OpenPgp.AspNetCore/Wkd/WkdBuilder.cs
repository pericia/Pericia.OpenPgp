using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Mail;
using System.Text;
using System.Threading.Tasks;

namespace Pericia.OpenPgp.AspNetCore.Wkd
{
    public class WkdBuilder
    {
        internal WkdSavedKeys WkdSavedKeys { get; } = new WkdSavedKeys();
        private OpenPgpKeyManagement keyManagement = new OpenPgpKeyManagement();

        public WkdBuilder AddPublicKeys(string publicKeysDirectory)
        {
            var publicKeys = Directory.GetFiles(publicKeysDirectory)
                                      .Select(file => keyManagement.LoadPublicKey(File.OpenRead(file)));
            return AddPublicKeys(publicKeys);
        }

        public WkdBuilder AddPublicKeys(IEnumerable<PgpPublicKey> publicKeys)
        {
            foreach (var key in publicKeys)
            {
                AddPublicKey(key);
            }

            return this;
        }

        public WkdBuilder AddPublicKey(PgpPublicKey key)
        {
            foreach (string userId in key.GetUserIds())
            {
                AddPublicKey(userId, key);
            }

            return this;
        }

        public WkdBuilder AddPublicKey(string email, PgpPublicKey key)
        {
            if (!MailAddress.TryCreate(email, out var mailAddress))
            {
                // UserId is not a mail adress, we don't save it
                return this;
            }

            var host = mailAddress.Host;
            Dictionary<string, string> hostDic;
            if (!WkdSavedKeys.PublicKeys.TryGetValue(host, out hostDic!))
            {
                hostDic = new Dictionary<string, string>();
                WkdSavedKeys.PublicKeys.Add(host, hostDic);
            }

            var user = OpenPgpKeySearch.GetHashedUserIdStatic(mailAddress.User);

            if (hostDic.ContainsKey(user))
            {
                // we already have a public key for this e-mail address
                return this;
            }
            var keyString = keyManagement.Export(key);
            hostDic.Add(user, keyString);

            return this;
        }
    }
}
