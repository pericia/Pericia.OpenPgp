using Microsoft.Extensions.Logging;
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
using Wiry.Base32;

namespace Pericia.OpenPgp
{
    public class OpenPgpKeySearch : IOpenPgpKeySearch
    {
        private readonly IHttpClientFactory httpClientFactory;
        private readonly ILogger logger;


        public OpenPgpKeySearch(IHttpClientFactory httpClientFactory, ILogger<OpenPgpKeySearch> logger)
        {
            this.httpClientFactory = httpClientFactory;
            this.logger = logger;
        }

        // Key server

        private const string DEFAULT_KEY_SERVER = "https://keys.openpgp.org";

        public Task<PgpPublicKey?> SearchHttpKeyServer(string address) => SearchHttpKeyServer(new MailAddress(address), DEFAULT_KEY_SERVER);
        public Task<PgpPublicKey?> SearchHttpKeyServer(MailAddress address) => SearchHttpKeyServer(address, DEFAULT_KEY_SERVER);
        public Task<PgpPublicKey?> SearchHttpKeyServer(string address, string keyServer) => SearchHttpKeyServer(new MailAddress(address), keyServer);

        public Task<PgpPublicKey?> SearchHttpKeyServer(MailAddress address, string keyServer)
        {
            string url = GetKeyServerSearchUrl(address, keyServer);
            return LoadFromUrl(url);
        }

        public string GetKeyServerSearchUrl(MailAddress address, string keyServer)
        {
            return $"{keyServer}/pks/lookup?op=get&options=mr&search={address.Address}";
        }

        // Web Key Directory

        public Task<PgpPublicKey?> SearchWebKeyDirectory(string address) => SearchWebKeyDirectory(new MailAddress(address));

        public async Task<PgpPublicKey?> SearchWebKeyDirectory(MailAddress address)
        {
            // Load keys from WDK url
            // https://www.uriports.com/blog/setting-up-openpgp-web-key-directory/
            // https://metacode.biz/openpgp/web-key-directory

            return await SearchAdvancedWkd(address)
                ?? await SearchDirectWkd(address);
        }

        public Task<PgpPublicKey?> SearchAdvancedWkd(MailAddress address) => LoadFromUrl(GetAdvancedWkdUrl(address));
        public Task<PgpPublicKey?> SearchDirectWkd(MailAddress address) => LoadFromUrl(GetDirectWkdUrl(address));

        private async Task<PgpPublicKey?> LoadFromUrl(string url)
        {
            var client = httpClientFactory.CreateClient();
            try
            {
                var response = await client.GetAsync(url);

                if (response.StatusCode == HttpStatusCode.OK)
                {
                    var key = ReadPublicKey(await response.Content.ReadAsStreamAsync());

                    return key;
                }
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Error while loading key");
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

        public string GetDirectWkdUrl(MailAddress address)
        {
            var hu = GetHashedUserId(address);
            return $"https://{address.Host}/.well-known/openpgpkey/hu/{hu}?l={address.User}";
        }

        public string GetAdvancedWkdUrl(MailAddress address)
        {
            var hu = GetHashedUserId(address);
            return $"https://openpgpkey.{address.Host}/.well-known/openpgpkey/{address.Host}/hu/{hu}?l={address.User}";
        }

        public string GetHashedUserId(MailAddress address) => GetHashedUserIdStatic(address.User);

        public string GetHashedUserId(string userName) => GetHashedUserIdStatic(userName);

        internal static string GetHashedUserIdStatic(string userName)
        {
            if (string.IsNullOrEmpty(userName)) throw new ArgumentException("userName can't be empty", nameof(userName));

            //https://wiki.gnupg.org/EasyGpg2016/PubkeyDistributionConcept
            //32-char long string constructed of the mapped local part of the email, SHA-1 hashed and z-Base-32 encoded.

            var sha1 = SHA1.Create();
            var hashed = sha1.ComputeHash(Encoding.UTF8.GetBytes(userName));
            
            var hu = Base32Encoding.ZBase32.GetString(hashed);
            return hu;
        }

    }
}
