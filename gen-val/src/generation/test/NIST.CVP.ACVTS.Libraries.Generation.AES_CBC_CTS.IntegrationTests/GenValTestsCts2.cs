﻿using NIST.CVP.ACVTS.Libraries.Common;

namespace NIST.CVP.ACVTS.Libraries.Generation.AES_CBC_CTS.IntegrationTests
{
    public class GenValTestsCts2 : GenValTestsCtsBase
    {
        public override string Algorithm { get; } = "ACVP-AES-CBC-CS2";
        public override AlgoMode AlgoMode => AlgoMode.AES_CBC_CS2_v1_0;
    }
}
