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

        private const string WKD_PREFIX = "/.well-known/openpgpkey/hu/";
        public Task InvokeAsync(HttpContext context, WkdSavedKeys savedKeys)
        {
            if (context.Request.Scheme == "https" && 
                context.Request.Path.HasValue &&
                context.Request.Path.Value.StartsWith(WKD_PREFIX))
            {
                var host = context.Request.Host.Host;
                var hu = context.Request.Path.Value.Substring(WKD_PREFIX.Length);

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
            else
            {
                return next(context);
            }
        }
    }
}
