using Microsoft.Extensions.FileProviders;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Pericia.OpenPgp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Mail;
using System.Text;
using Pericia.OpenPgp.AspNetCore.Wkd;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class WkdServiceCollectionExtensions
    {
        public static IServiceCollection AddWebKeyDirectory(this IServiceCollection services, params PgpPublicKey[] publicKeys)
        {
            services.AddSingleton(LoadPublicKeys(publicKeys));
            return services;
        }

        public static IServiceCollection AddWebKeyDirectory(this IServiceCollection services, IEnumerable<PgpPublicKey> publicKeys)
        {
            services.AddSingleton(LoadPublicKeys(publicKeys));
            return services;
        }

        public static IServiceCollection AddWebKeyDirectory(this IServiceCollection services, IDirectoryContents directory)
        {
            var keyManagement = new OpenPgpKeyManagement();
            var publicKeys = directory.Select(file => keyManagement.LoadPublicKey(file.CreateReadStream()));
            services.AddSingleton(LoadPublicKeys(publicKeys));

            return services;
        }

        public static IServiceCollection AddWebKeyDirectory(this IServiceCollection services, string path)
        {
            var keyManagement = new OpenPgpKeyManagement();
            var publicKeys = Directory.GetFiles(path).Select(file => keyManagement.LoadPublicKey(File.OpenRead(file)));
            services.AddSingleton(LoadPublicKeys(publicKeys));

            return services;
        }

        private static WkdSavedKeys LoadPublicKeys(IEnumerable<PgpPublicKey> publicKeys, OpenPgpKeyManagement? keyManagement = null)
        {
            var context = new WkdSavedKeys();
            if (keyManagement == null)
            {
                keyManagement = new OpenPgpKeyManagement();
            }

            foreach (var key in publicKeys)
            {
                foreach (string userId in key.GetUserIds())
                {
                    MailAddress mailAddress;
                    try
                    {
                        mailAddress = new MailAddress(userId);
                    }
                    catch (FormatException)
                    {
                        // UserId is not a mail adress, we don't save it
                        continue;
                    }

                    var host = mailAddress.Host;
                    Dictionary<string, string> hostDic;
                    if (!context.PublicKeys.TryGetValue(host, out hostDic!))
                    {
                        hostDic = new Dictionary<string, string>();
                        context.PublicKeys.Add(host, hostDic);
                    }

                    var user = OpenPgpKeySearch.GetHashedUserIdStatic(mailAddress.User);

                    if (hostDic.ContainsKey(user))
                    {
                        // we already have a public key for this e-mail address
                        continue;
                    }
                    var keyString = keyManagement.Export(key);
                    hostDic.Add(user, keyString);
                }
            }

            return context;
        }
    }
}
