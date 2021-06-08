using System;
using System.Collections.Generic;
using System.Text;

namespace KOMTEK.KundeInnsyn.Common.DataObjects
{
    public class HashVerificationEventArgs : EventArgs
    {
        public bool Outcome { get; set; }

        public HashVerificationEventArgs(bool outcome)
        {
            Outcome = outcome;
        }
    }
}
