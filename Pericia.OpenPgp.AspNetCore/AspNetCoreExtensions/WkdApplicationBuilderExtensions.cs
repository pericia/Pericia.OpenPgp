using Pericia.OpenPgp.AspNetCore.Wkd;
using System;
using System.Collections.Generic;
using System.Text;

namespace Microsoft.AspNetCore.Builder
{
    public static class WkdApplicationBuilderExtensions
    {
        public static IApplicationBuilder UseWebKeyDirectory(this IApplicationBuilder app)
        {
            app.UseMiddleware<WkdMiddleware>();
            return app;
        }
    }
}
