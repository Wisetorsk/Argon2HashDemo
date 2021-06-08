using System;
using System.Collections.Generic;
using System.Text;

namespace DataObjects
{
    public class HashEventArgs : EventArgs
    {
        public UserHash User { get; set; }
        public HashEventArgs(byte[] hash, byte[] salt, string username)
        {
            User = new UserHash {
                Hash = hash, Salt = salt, Username = username
            };
        }

        public HashEventArgs(UserHash user)
        {
            User = user;
        }
    }
}
