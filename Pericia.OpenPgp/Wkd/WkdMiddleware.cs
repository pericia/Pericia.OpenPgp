using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Pericia.OpenPgp
{
    internal class WkdMiddleware
    {
        private readonly RequestDelegate next;

        public WkdMiddleware(RequestDelegate next)
        {
            this.next = next;
        }

        private const string WKD_PREFIX = "/.well-known/openpgpkey/";
        private const string ADVANCED_WKD_HOST_PREFIX = "openpgpkey.";

        public Task InvokeAsync(HttpContext context, WkdSavedKeys savedKeys)
        {
            if (context.Request.Path.HasValue &&
                context.Request.Path.Value.StartsWith(WKD_PREFIX))
            {
                var host = context.Request.Host.Host;
                bool isAdvanced = host.StartsWith(ADVANCED_WKD_HOST_PREFIX);
                string suffix;

                if (isAdvanced)
                {
                    host = host.Substring(ADVANCED_WKD_HOST_PREFIX.Length);
                    var fullPrefix = WKD_PREFIX + host + "/";
                    suffix = context.Request.Path.Value.Substring((WKD_PREFIX + fullPrefix).Length);
                }
                else
                {
                    suffix = context.Request.Path.Value.Substring(WKD_PREFIX.Length);
                }

                if (suffix == "policy")
                {
                    context.Response.StatusCode = 200;
                    return Task.CompletedTask;
                }

                if (suffix.StartsWith("hu/"))
                {
                    var hu = suffix.Substring(3);
                    try
                    {
                        var key = savedKeys.PublicKeys[host][hu];

                        context.Response.StatusCode = 200;
                        context.Response.Headers.Add("content-disposition", "attachment; filename=\"publickey.asc\"");
                        context.Response.ContentType = "application/octet-stream";
                        return context.Response.WriteAsync(key);
                    }
                    catch (KeyNotFoundException)
                    {
                        context.Response.StatusCode = 404;
                        return Task.CompletedTask;
                    }
                }


                context.Response.StatusCode = 404;
                return Task.CompletedTask;
            }
            else
            {
                return next(context);
            }
        }
    }
}
