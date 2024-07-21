using NIST.CVP.ACVTS.Libraries.Common;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.PQC.SLHDSA.Enums;
using NIST.CVP.ACVTS.Libraries.Generation.SLH_DSA.FIPS205.SigGen;
using NIST.CVP.ACVTS.Libraries.Generation.Tests;
using NIST.CVP.ACVTS.Libraries.Math;
using NIST.CVP.ACVTS.Libraries.Math.Domain;
using NIST.CVP.ACVTS.Tests.Core.TestCategoryAttributes;
using NUnit.Framework;

namespace NIST.CVP.ACVTS.Libraries.Generation.SLH_DSA.SigGen.IntegrationTests;

[TestFixture, FastIntegrationTest]
public class GenValTests : GenValTestsSingleRunnerBase
{
    public override string Algorithm { get; } = "SLH-DSA";
    public override string Mode { get; } = "sigGen";
    public override string Revision { get; set; } = "FIPS205";

    public override AlgoMode AlgoMode => AlgoMode.SLH_DSA_SigGen_FIPS205;

    public override IRegisterInjections RegistrationsGenVal => new RegisterInjections();

    protected override void ModifyTestCaseToFail(dynamic testCase)
    {
        var rand = new Random800_90();

        var oldValue = new BitString(testCase.signature.ToString());
        var newValue = rand.GetDifferentBitStringOfSameSize(oldValue);
        testCase.signature = newValue.ToHex();
    }
    
    protected override string GetTestFileFewTestCases(string targetFolder)
    {
        var p = new Parameters
        {
            VectorSetId = 53,
            Algorithm = Algorithm,
            Mode = Mode,
            Revision = Revision,
            Deterministic = new []{ false },
            Capabilities = new []
            {
                new Capability()
                {
                    ParameterSets = new[] { SlhdsaParameterSet.SLH_DSA_SHAKE_128s, SlhdsaParameterSet.SLH_DSA_SHA2_128f },
                    MessageLength = new MathDomain().AddSegment(new RangeDomainSegment(new Random800_90(), 8, 65536, 8))
                }
            },
            IsSample = true
        };

        return CreateRegistration(targetFolder, p);
    }
    
    protected override string GetTestFileLotsOfTestCases(string targetFolder)
    {
        var p = new Parameters
        {
            VectorSetId = 53,
            Algorithm = Algorithm,
            Mode = Mode,
            Revision = Revision,
            Deterministic = new []{ true, false },
            Capabilities = new []
            {
                new Capability()
                {
                    ParameterSets = new[] { SlhdsaParameterSet.SLH_DSA_SHA2_192s, SlhdsaParameterSet.SLH_DSA_SHA2_256f, SlhdsaParameterSet.SLH_DSA_SHAKE_192s, SlhdsaParameterSet.SLH_DSA_SHAKE_256f },
                    MessageLength = new MathDomain().AddSegment(new RangeDomainSegment(new Random800_90(), 8, 65536, 8))
                },
                new Capability()
                {
                    ParameterSets = new[] { SlhdsaParameterSet.SLH_DSA_SHAKE_128f },
                    MessageLength = new MathDomain().AddSegment(new RangeDomainSegment(new Random800_90(), 1024, 4096, 8))
                }
            },
            IsSample = true
        };

        return CreateRegistration(targetFolder, p);
    }
}