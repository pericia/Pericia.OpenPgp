using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace Pericia.OpenPgp.Tests
{
    internal class TestHttpClientFactory : IHttpClientFactory
    {
        private static Lazy<HttpClient> httpClient = new Lazy<HttpClient>(() => new HttpClient());

        public HttpClient CreateClient(string name)
        {
            return httpClient.Value;
        }
    }
}
