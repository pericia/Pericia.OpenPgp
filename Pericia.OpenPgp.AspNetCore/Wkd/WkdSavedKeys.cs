using System;
using System.Collections.Generic;
using System.Text;

namespace Pericia.OpenPgp.AspNetCore.Wkd
{
    internal class WkdSavedKeys
    {
        public Dictionary<string, Dictionary<string, string>> PublicKeys { get; } = new Dictionary<string, Dictionary<string, string>>();
    }
}
