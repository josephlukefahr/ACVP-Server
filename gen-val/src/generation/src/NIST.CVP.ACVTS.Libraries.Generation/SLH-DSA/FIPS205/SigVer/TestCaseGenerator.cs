using System;
using System.Linq;
using System.Threading.Tasks;
using NIST.CVP.ACVTS.Libraries.Generation.Core;
using NIST.CVP.ACVTS.Libraries.Generation.Core.Async;
using NIST.CVP.ACVTS.Libraries.Math;
using NIST.CVP.ACVTS.Libraries.Oracle.Abstractions;
using NIST.CVP.ACVTS.Libraries.Oracle.Abstractions.ParameterTypes.SLH_DSA;
using NLog;

namespace NIST.CVP.ACVTS.Libraries.Generation.SLH_DSA.FIPS205.SigVer;

public class TestCaseGenerator : ITestCaseGeneratorWithPrep<TestGroup, TestCase>
{
    private readonly IOracle _oracle;
    private ShuffleQueue<int> _messageLengths;
    
    // Set up to use one of the possible dispositions 3X, and the other 6 possible dispositions 1X. NOTE: 9 is a placeholder.
    public int NumberOfTestCasesToGenerate { get; private set; } = 9;
    
    public TestCaseGenerator(IOracle oracle)
    {
        _oracle = oracle;
    }

    public GenerateResponse PrepareGenerator(TestGroup group, bool isSample)
    {
        NumberOfTestCasesToGenerate = group.TestCaseExpectationProvider.ExpectationCount;
        
        var messageLengthDomain = group.MessageLengths.GetDeepCopy();

        // test the smallest and largest supported message lengths (adds 2 message lengths)
        var messageLengthValues = messageLengthDomain.GetDomainMinMaxAsEnumerable().Distinct().ToList();
        
        // If count is 1, min == max and the IUT only supports one message length. If count > 1, min != max and the IUT
        // supports a number of message lengths; so grab a few message lengths between min and max for testing
        if (messageLengthValues.Count > 1)
        {
            var messageLengthMin = messageLengthValues[0];
            var messageLengthMax = messageLengthValues[1];
            
            // the next smallest supported message length "feels" special. For example, if an IUT supports message lengths
            // between 0 and 1024 bytes, the next smallest supported message length would be 1 byte long. (adds an additional message length)
            messageLengthValues.AddRange(messageLengthDomain.GetSequentialValues(x => x > messageLengthMin, 1));
            // grab more message lengths to test (should bring our total to NumberOfTestCasesToGenerate)
            messageLengthValues.AddRange(messageLengthDomain.GetRandomValues(x => x > messageLengthMin && x < messageLengthMax, NumberOfTestCasesToGenerate - 3));                
        }

        _messageLengths = new ShuffleQueue<int>(messageLengthValues);

        return new GenerateResponse();
    }

    public async Task<TestCaseGenerateResponse<TestGroup, TestCase>> GenerateAsync(TestGroup group, bool isSample,
        int caseNo = -1)
    {
        var messageLength = _messageLengths.Pop();
        
        var param = new SLHDSASignatureParameters
        {
            SlhdsaParameterSet = group.ParameterSet,
            Deterministic = false,
            MessageLength = messageLength,
            Disposition = group.TestCaseExpectationProvider.GetRandomReason().GetReason()
        };
        
        try
        {
            var result = await _oracle.GetSLHDSASigVerCaseAsync(param);

            return new TestCaseGenerateResponse<TestGroup, TestCase>(new TestCase
            {
                PrivateKey = result.VerifiedValue.PrivateKey,
                PublicKey = result.VerifiedValue.PublicKey,
                AdditionalRandomness = result.VerifiedValue.AdditionalRandomness,
                MessageLength = result.VerifiedValue.MessageLength,
                Message = result.VerifiedValue.Message,
                Signature = result.VerifiedValue.Signature,
                Reason = param.Disposition,
                TestPassed = result.Result
            });
        }
        catch (Exception ex)
        {
            ThisLogger.Error(ex);
            return new TestCaseGenerateResponse<TestGroup, TestCase>($"Error generating SLH-DSA FIPS205 SigVer test case: {ex.Message}");
        }
    }

    private static ILogger ThisLogger => LogManager.GetCurrentClassLogger();
}