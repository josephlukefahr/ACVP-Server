﻿using System;
using System.Collections.Generic;
using System.Text;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.KDF.Components.TPM;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.MAC.HMAC;
using NIST.CVP.ACVTS.Libraries.Math;

namespace NIST.CVP.ACVTS.Libraries.Crypto.TPM
{
    public class Tpm : ITpm
    {
        private readonly IHmac _hmac;

        public Tpm(IHmac hmac)
        {
            _hmac = hmac;
        }

        public KdfResult DeriveKey(BitString auth, BitString nonceEven, BitString nonceOdd)
        {
            var value = nonceEven.ConcatenateBits(nonceOdd);
            var result = _hmac.Generate(auth, value);

            if (result.Success)
            {
                return new KdfResult(result.Mac);
            }
            else
            {
                return new KdfResult(result.ErrorMessage);
            }
        }
    }
}
