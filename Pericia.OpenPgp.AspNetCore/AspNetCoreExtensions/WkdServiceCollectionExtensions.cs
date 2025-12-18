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
        public static WkdBuilder AddWebKeyDirectory(this IServiceCollection services)
        {
            var builder = new WkdBuilder();
            services.AddSingleton(builder.WkdSavedKeys);
            return builder;
        }

    }
}
