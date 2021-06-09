using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using DataObjects;
using Konscious.Security.Cryptography;

namespace Services
{
    public class Cryptography : ICryptography, IDisposable
    {
        private bool _disposed = false;

        public bool CalculationRunning { get; set; } = false;
        public event EventHandler<HashEventArgs> HashCalcualtionComplete;
        public event EventHandler<HashVerificationEventArgs> HashVerificationComplete;
        private Argon2 Argon { get; set; }

        protected virtual void AlertCalculationComplete(UserHash user)
        {
            CalculationRunning = false;
            HashCalcualtionComplete?.Invoke(this, new HashEventArgs(user));
        }

        protected virtual void AlertHashVerificationComplete(bool result)
        {
            CalculationRunning = false;
            HashVerificationComplete?.Invoke(this, new HashVerificationEventArgs(result));
        }

        /// <summary>
        /// Generates cryptographic salt as byte array
        /// </summary>
        /// <returns></returns>
        public byte[] CreateSalt()
        {
            var buffer = new byte[16];
            var rng = new RNGCryptoServiceProvider();
            rng.GetBytes(buffer);
            return buffer;
        }

        /// <summary>
        /// Calculates Argon_2 hash for user input and salt
        /// </summary>
        /// <param name="inputString"></param>
        /// <param name="salt"></param>
        /// <returns></returns>
        public async Task<byte[]> HashInput(string inputString, byte[] salt)
        {
            CalculationRunning = true;
            byte[] hashedBytes;
            hashedBytes = await CalculateHashAsync(inputString, salt);
            return hashedBytes;

        }

        private async Task<byte[]> CalculateHashAsync(string inputString, byte[] salt)
        {
            byte[] hashedBytes;
            Argon = new(inputString, salt);
            hashedBytes = await Argon.CalculateHashAsync();
            
            return hashedBytes;
        }

        ~Cryptography() => Dispose(false);

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }


        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
            {
                return;
            }

            if (disposing)
            {
                
                Argon?.Dispose();
            }

            _disposed = true;
        }

        private static async Task<byte[]> StaticCalculateHashAsync(string inputString, byte[] salt)
        {
            byte[] hashedBytes;
            Argon2 Argon = new(inputString, salt);
            hashedBytes = await Argon.CalculateHashAsync();
            Argon?.Dispose();
            //Argon = null; // overkill
            return hashedBytes;
        }


        /// <summary>
        /// Verifyes the given password vs stored hash and salt.
        /// </summary>
        /// <param name="inputString"></param>
        /// <param name="salt"></param>
        /// <param name="hash"></param>
        /// <returns></returns>
        public async Task<bool> VerifyHash(string inputString, byte[] salt, byte[] hash)
        {
            var newHash = await HashInput(inputString, salt);
            var result = hash.SequenceEqual(newHash);
            Argon?.Dispose();
            return result; // Can also be set as async Task or void.
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="inputString"></param>
        /// <param name="hashedUser"></param>
        /// <returns></returns>
        public async Task<bool> VerifyHash(string inputString, UserHash hashedUser)
        {
            var newHash = await HashInput(inputString, hashedUser.Salt);
            var result = hashedUser.Hash.SequenceEqual(newHash);
            Argon?.Dispose();
            return result; // Can also be set as async Task or void.
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="inputString"></param>
        /// <param name="salt"></param>
        /// <param name="hash"></param>
        public async Task VerifyHashEvent(string inputString, byte[] salt, byte[] hash)
        {
            var newHash = await HashInput(inputString, salt);
            var result = hash.SequenceEqual(newHash);
            Argon?.Dispose();
            AlertHashVerificationComplete(result);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="inputString"></param>
        /// <param name="hashedUser"></param>
        public async Task VerifyHashEvent(string inputString, UserHash hashedUser)
        {
            var newHash = await HashInput(inputString, hashedUser.Salt);
            var result = hashedUser.Hash.SequenceEqual(newHash);
            Argon?.Dispose();
            AlertHashVerificationComplete(result);
        }


        /// <summary>
        /// Creates dataset to store userlogin
        /// 
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public async Task CreateHashAndSalt(string username, string password)
        {
            var salt = CreateSalt();
            var hash = await HashInput(password, salt);
            var user = new UserHash
            {
                Salt = salt,
                Username = username,
                Hash = hash
            };
            Argon?.Dispose();
            AlertCalculationComplete(user);
        }

        public byte[] Encrypt(string inputString)
        {
            throw new NotImplementedException();
        }

        public byte[] Decrypt(string inputString, byte[] key)
        {
            throw new NotImplementedException();
        }
    }
}
