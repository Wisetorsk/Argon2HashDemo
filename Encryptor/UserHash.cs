using System;
using System.Collections.Generic;
using System.Text;

namespace KOMTEK.KundeInnsyn.Common.DataObjects
{
    public class UserHash
    {
        public Guid CustomerID { get; set; }
        public string Username { get; set; }
        public byte[] Salt { get; set; }
        public byte[] Hash { get; set; }

        public string HashString => BitConverter.ToString(Hash).Replace("-", "");
        public string SaltString => BitConverter.ToString(Salt).Replace("-", "");
    }
}
