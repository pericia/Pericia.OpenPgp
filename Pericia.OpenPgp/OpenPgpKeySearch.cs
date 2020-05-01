using MhanoHarkness;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Mail;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Pericia.OpenPgp
{
    public class OpenPgpKeySearch : IOpenPgpKeySearch
    {
        // Key server

        private const string DEFAULT_KEY_SERVER = "https://keys.openpgp.org";

        public Task<PgpPublicKey?> SearchHttpKeyServer(string address) => SearchHttpKeyServer(new MailAddress(address), DEFAULT_KEY_SERVER);
        public Task<PgpPublicKey?> SearchHttpKeyServer(MailAddress address) => SearchHttpKeyServer(address, DEFAULT_KEY_SERVER);
        public Task<PgpPublicKey?> SearchHttpKeyServer(string address, string keyServer) => SearchHttpKeyServer(new MailAddress(address), keyServer);

        public async Task<PgpPublicKey?> SearchHttpKeyServer(MailAddress address, string keyServer)
        {
            string url = GetKeyServerSearchUrl(address, keyServer);

            var request = new HttpClient();
            var response = await request.GetAsync(url);

            if (response.StatusCode == HttpStatusCode.OK)
            {
                var key = ReadPublicKey(await response.Content.ReadAsStreamAsync());

                return key;
            }

            return null;
        }

        public string GetKeyServerSearchUrl(MailAddress address, string keyServer)
        {
            return $"{keyServer}/pks/lookup?op=get&options=mr&search={address.Address}";
        }

        // Web Key Directory

        public Task<PgpPublicKey?> SearchWebKeyDirectory(string address) => SearchWebKeyDirectory(new MailAddress(address));

        public async Task<PgpPublicKey?> SearchWebKeyDirectory(MailAddress address)
        {
            string url = GetWkdUrl(address);

            var request = new HttpClient();
            var response = await request.GetAsync(url);

            if (response.StatusCode == HttpStatusCode.OK)
            {
                var key = ReadPublicKey(await response.Content.ReadAsStreamAsync());

                return key;
            }

            return null;
        }

        private static PgpPublicKey ReadPublicKey(Stream inputStream)
        {
            var armoredStream = PgpUtilities.GetDecoderStream(inputStream);
            PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(armoredStream);

            foreach (PgpPublicKeyRing keyRing in pgpPub.GetKeyRings())
            {
                foreach (PgpPublicKey key in keyRing.GetPublicKeys())
                {
                    if (key.IsEncryptionKey)
                    {
                        return key;
                    }
                }
            }

            throw new ArgumentException("Can't find encryption key in key ring.");
        }

        public string GetWkdUrl(MailAddress address)
        {
            var host = address.Host;
            var hu = GetHashedUserId(address);

            return $"https://{host}/.well-known/openpgpkey/hu/{hu}";
        }

        public string GetHashedUserId(string userName)
        {
            if (string.IsNullOrEmpty(userName)) throw new ArgumentException("userName can't be empty", nameof(userName));

            //https://wiki.gnupg.org/EasyGpg2016/PubkeyDistributionConcept
            //32-char long string constructed of the mapped local part of the email, SHA-1 hashed and z-Base-32 encoded.

            var sha1 = SHA1.Create();
            var hashed = sha1.ComputeHash(Encoding.UTF8.GetBytes(userName));

            var base32Encoder = new Base32Url(Base32Url.ZBase32Alphabet);
            var hu = base32Encoder.Encode(hashed);
            return hu;
        }

        public string GetHashedUserId(MailAddress address) => GetHashedUserId(address.User);

    }
}
