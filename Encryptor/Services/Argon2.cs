using Konscious.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Services
{
    public class Argon2 : IDisposable
    {

        private bool _disposed = false;

        //private SafeHandle _safeHandle = new SafeFileHandle(IntPtr.Zero, true);

        ~Argon2() => Dispose(false);

        private Argon2id ArgonHasher;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="inputString"></param>
        /// <param name="salt">byte coded cryptographic salt</param>
        /// <param name="parallelism">Number of threads to utilize</param>
        /// <param name="iterations"></param>
        /// <param name="memoryDim">Memory pre-allocation</param>
        public Argon2(string inputString, byte[] salt, int parallelism = 4, int iterations = 4, int memoryDim = 256)
        {
            ArgonHasher = new Argon2id(Encoding.UTF8.GetBytes(inputString))
            {
                Salt = salt,
                DegreeOfParallelism = parallelism, // Number of threads to utilize
                Iterations = iterations,
                MemorySize = memoryDim * memoryDim // Set to a defualt of 1024^2 memory size... 
            };
        }

        public async Task<byte[]> CalculateHashAsync()
        {
            byte[] hashedBytes;
            
            hashedBytes = await ArgonHasher.GetBytesAsync(16);
            return hashedBytes;
        }

        public void Dispose() {
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
                // Dispose managed state (managed objects).
                ArgonHasher?.Dispose();
                //_safeHandle?.Dispose();
            }

            _disposed = true;
        }

    }
}
