using System;
using System.Text;
using System.Threading.Tasks;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System.IO;


namespace EncrytionKeyVault
{
    class Program
    {
        static string  keyencrytion = "goNLTm4LJONI6b/Y25raZ25b+eLSxWlGqigrq4mHDRM=";
        static string ClientID, ClientSecret; ///needs to secure this info

        static string keyVaultName = "encrytiontest";
        static string keyVaultUri = "https://" + keyVaultName + ".vault.azure.net";
        static string keyVaultKeyName = "myfavouritekey";

        static WrapResult wrapResult; 
        static string authority ="https://login.microsoftonline.com/common";




         static async Task Main(string[] args)
        {
          await EncrytFile();
          await  DeencrytFile(keyencrytion);
         
        }

        static async Task<bool> EncrytFile()
        {
            using (var sourceStream = File.OpenRead("obj/files/test.txt"))
            using (var destinationStream = File.Create("obj/files/encrytion"))
            using (var provider = new AesCryptoServiceProvider())
            using (var cryptoTransform = provider.CreateEncryptor())
            using (var cryptoStream = new CryptoStream(destinationStream, cryptoTransform, CryptoStreamMode.Write))
            {
                 destinationStream.Write(provider.IV, 0, provider.IV.Length);
                 sourceStream.CopyTo(cryptoStream);
                 keyencrytion = System.Convert.ToBase64String(provider.Key);      
                 //encryt the key with a public key 
                 await WrappingKey(keyencrytion);             
            }

            return true;
        }
        static async Task<bool> DeencrytFile(string wrapKey)
        {
           var secret = await UnWrappingKey(wrapKey);
            //un
           byte[] key = null;
            if (secret.Length > 0)
            {
                key = System.Convert.FromBase64String(secret);
            }

            using (var sourceStream = File.OpenRead("obj/files/encrytion"))
            using (var destinationStream = File.Create("obj/files/testUnencyted.txt"))
            using (var provider = new AesCryptoServiceProvider())
            {
                var IV = new byte[provider.IV.Length];
                sourceStream.Read(IV, 0, IV.Length);
                using (var cryptoTransform = provider.CreateDecryptor(key, IV))
                using (var cryptoStream = new CryptoStream(sourceStream, cryptoTransform, CryptoStreamMode.Read))
                {
                    cryptoStream.CopyTo(destinationStream);
                }
            }

            return true;
        }

        static async Task<string> WrappingKey(string key)
        {
            var authentication =  new InteractiveBrowserCredential();

            var client = new KeyClient(new Uri(keyVaultUri), authentication);
            //with SPN  var client = new KeyClient(new Uri(keyVaultUri),GetToken(authority,keyVaultUri));
        
            //get public key 
            KeyVaultKey publicKey = await client.GetKeyAsync(keyVaultKeyName).ConfigureAwait(false);

            //new Cyto client 
            var cryptoClient = new CryptographyClient(publicKey.Id, authentication);

            //convert the key to the right format
            byte[] inputAsByteArray = Convert.FromBase64String(key);

            //wrap the key with the public key
            wrapResult = await cryptoClient.WrapKeyAsync(KeyWrapAlgorithm.RsaOaep, inputAsByteArray);
            
            var newWrappedKey = Convert.ToBase64String(wrapResult.EncryptedKey);
            Console.WriteLine($"Wrap key: {newWrappedKey}");
            ///to do: save the key into a secure are 
            return newWrappedKey;
        }

        static async Task<string> UnWrappingKey(string key)
        {
            var authentication =  new InteractiveBrowserCredential();

            var client = new KeyClient(new Uri(keyVaultUri), authentication);
            //with SPN  var client = new KeyClient(new Uri(keyVaultUri),GetToken(authority,keyVaultUri));
        
            //get public key 
            KeyVaultKey publicKey = await client.GetKeyAsync(keyVaultKeyName).ConfigureAwait(false);

            //new Cyto client 
            var cryptoClient = new CryptographyClient(publicKey.Id, authentication);

            UnwrapResult unwrapResult = cryptoClient.UnwrapKey(KeyWrapAlgorithm.RsaOaep, wrapResult.EncryptedKey);

            var unWrappedKey = Convert.ToBase64String(unwrapResult.Key);
            Console.WriteLine($"Wrap key: {unwrapResult}");

            return unWrappedKey;
        }


        //get AAD token for authentication using SPNs 

        /*
         static async Task<Azure.Core.TokenCredential> GetToken(string authority, string resource)
        {
            var authContext = new AuthenticationContext(authority);
            ClientCredential clientCred = new ClientCredential(ClientID, ClientSecret);
            
            AuthenticationResult result = await authContext.AcquireTokenAsync(resource, clientCred);

            if (result == null)
                throw new InvalidOperationException("Failed to obtain the JWT token");

            return result.AccessToken;
        }
         static async Task<string> EncryptStringAsync(CryptographyClient cryptoClient, string input)
        {
            byte[] inputAsByteArray = Encoding.UTF8.GetBytes(input);

            EncryptResult encryptResult =  await cryptoClient.EncryptAsync(EncryptionAlgorithm.RsaOaep, inputAsByteArray).ConfigureAwait(false);

            return Convert.ToBase64String(encryptResult.Ciphertext);
        }

        static async Task<string> DecryptStringAsync(CryptographyClient cryptoClient, string input)
        {
            byte[] inputAsByteArray = Convert.FromBase64String(input);

            DecryptResult decryptResult = await cryptoClient.DecryptAsync(EncryptionAlgorithm.RsaOaep, inputAsByteArray).ConfigureAwait(false);

            return Encoding.Default.GetString(decryptResult.Plaintext);
        }

        static async Task<string> KeyVaultDemo()
        {
            string keyVaultName = "encrytiontest";
            string keyVaultUri = "https://" + keyVaultName + ".vault.azure.net";
            string keyVaultKeyName = "myfavouritekey";
            

            //1.- generate a randon key and SQK 
            // 2.- using randon key encryt file/s
            //3.- 
            string textToEncrypt = "StuffIDoNotWantYouToKnow";

            var client = new KeyClient(new Uri(keyVaultUri), new InteractiveBrowserCredential());

            await client.CreateRsaKeyAsync(new CreateRsaKeyOptions(keyVaultKeyName)).ConfigureAwait(false);

            KeyVaultKey key = await client.GetKeyAsync(keyVaultKeyName).ConfigureAwait(false);

            var cryptoClient = new CryptographyClient(key.Id, new InteractiveBrowserCredential());

            string encryptedString = await EncryptStringAsync(cryptoClient, textToEncrypt).ConfigureAwait(false);

            Console.WriteLine($"Encrypted string: {encryptedString}");
//4.- upload encryted key to blob storage

///  BATCH SERVERS


            
            string decryptedString = await DecryptStringAsync(cryptoClient, encryptedString).ConfigureAwait(false);

            Console.WriteLine($"Decrypted string: {decryptedString}");

            return "completed";
        }
        */
    }
}
