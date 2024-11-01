﻿using System;
using NIST.CVP.ACVTS.Libraries.Crypto.AES;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.MAC.CMAC;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.MAC.CMAC.Enums;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.Symmetric.BlockModes;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.Symmetric.Engines;

namespace NIST.CVP.ACVTS.Libraries.Crypto.CMAC
{
    public class CmacFactory : ICmacFactory
    {
        private readonly IBlockCipherEngineFactory _engineFactory;
        private readonly IModeBlockCipherFactory _modeFactory;

        public CmacFactory(IBlockCipherEngineFactory engineFactory, IModeBlockCipherFactory modeFactory)
        {
            _engineFactory = engineFactory;
            _modeFactory = modeFactory;
        }

        public ICmac GetCmacInstance(CmacTypes cmacType)
        {
            switch (cmacType)
            {
                case CmacTypes.AES128:
                case CmacTypes.AES192:
                case CmacTypes.AES256:
                    return new CmacAes(_engineFactory, _modeFactory);

                case CmacTypes.TDES:
                    return new CmacTdes(_engineFactory, _modeFactory);
            }

            throw new ArgumentException($"Invalid {cmacType}");
        }
    }
}
