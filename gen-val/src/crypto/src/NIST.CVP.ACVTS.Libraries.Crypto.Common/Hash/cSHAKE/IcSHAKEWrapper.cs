﻿using NIST.CVP.ACVTS.Libraries.Math;

namespace NIST.CVP.ACVTS.Libraries.Crypto.Common.Hash.cSHAKE
{
    public interface IcSHAKEWrapper
    {
        BitString HashMessage(BitString message, int digestLength, int capacity, string customization, string functionName);
        BitString HashMessage(BitString message, int digestLength, int capacity);
        BitString HashMessage(BitString message, int digestLength, int capacity, BitString customization, string functionName);
    }
}