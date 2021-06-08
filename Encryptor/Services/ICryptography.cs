using DataObjects;
using System;
using System.Threading.Tasks;

namespace Services
{
    public interface ICryptography
    {
        bool CalculationRunning { get; set; }

        event EventHandler<HashEventArgs> HashCalcualtionComplete;
        event EventHandler<HashVerificationEventArgs> HashVerificationComplete;

        Task CreateHashAndSalt(string username, string password);
        byte[] CreateSalt();
        byte[] Decrypt(string inputString, byte[] key);
        byte[] Encrypt(string inputString);
        Task<byte[]> HashInput(string inputString, byte[] salt);
        Task<bool> VerifyHash(string inputString, byte[] salt, byte[] hash);
        Task<bool> VerifyHash(string inputString, UserHash hashedUser);
        Task VerifyHashEvent(string inputString, byte[] salt, byte[] hash);
        Task VerifyHashEvent(string inputString, UserHash hashedUser);
    }
}