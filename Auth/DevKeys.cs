using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace Auth
{
    public class DevKeys
    {
        public DevKeys(IWebHostEnvironment env)
        {
            RsaKey = RSA.Create();

            var path = Path.Combine(env.ContentRootPath, "crypto_key");

            if (!File.Exists(path))
            {
                var privateKey = RsaKey.ExportRSAPrivateKey();
                File.WriteAllBytes(path, privateKey);
            }
            else
            {
                var rsaKey = RSA.Create();
                rsaKey.ImportRSAPrivateKey(File.ReadAllBytes(path), out _);
            }
        }

        public RSA RsaKey { get; }
        public RsaSecurityKey RsaSecurityKey => new RsaSecurityKey(RsaKey);
    }
}
