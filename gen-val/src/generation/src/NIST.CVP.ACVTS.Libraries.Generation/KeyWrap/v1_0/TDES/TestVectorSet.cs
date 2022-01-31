﻿namespace NIST.CVP.ACVTS.Libraries.Generation.KeyWrap.v1_0.TDES
{
    public class TestVectorSet : TestVectorSetBase<TestGroup, TestCase>
    {
        public override string Algorithm { get; set; } = "KeyWrap";
        public override string Mode { get; set; } = "TDES";
    }
}