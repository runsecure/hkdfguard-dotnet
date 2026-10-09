using System.Security.Cryptography;

namespace HkdfGuard.CryptoProvider.AesGcm256.Test;

public class EncryptionBudgetTests
{
    [Fact]
    public void Defaults_AreHalfAndOneEighthOfTheNistLimit()
    {
        var budget = new EncryptionBudget();

        Assert.Equal(1L << 31, budget.Limit);
        Assert.Equal(1L << 28, budget.WarningThreshold);
        Assert.Equal(0, budget.Count);
    }

    [Fact]
    public void Consume_ReturnsTrueExactlyOnce_WhenTheWarningThresholdIsReached()
    {
        var budget = new EncryptionBudget(warningThreshold: 3, limit: 10);

        var warnings = Enumerable.Range(1, 6).Select(_ => budget.Consume()).ToArray();

        Assert.Equal([false, false, true, false, false, false], warnings);
        Assert.Equal(6, budget.Count);
    }

    [Fact]
    public void Consume_PastTheLimit_ThrowsAndLeavesTheCountAtTheLimit()
    {
        var budget = new EncryptionBudget(warningThreshold: 1, limit: 2);
        budget.Consume();
        budget.Consume();

        var exception = Assert.Throws<CryptographicException>(() => budget.Consume());

        Assert.Contains("limit of 2", exception.Message);
        Assert.Equal(2, budget.Count);
        Assert.Throws<CryptographicException>(() => budget.Consume());
    }

    [Fact]
    public async Task Consume_UnderConcurrency_NeverExceedsTheLimit()
    {
        var budget = new EncryptionBudget(warningThreshold: 1, limit: 1000);
        var successes = 0;

        await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(() =>
        {
            for (var i = 0; i < 500; i++)
            {
                try
                {
                    budget.Consume();
                    Interlocked.Increment(ref successes);
                }
                catch (CryptographicException)
                {
                }
            }
        })));

        Assert.Equal(1000, successes);
        Assert.Equal(1000, budget.Count);
    }

    [Theory]
    [InlineData(0, 10)]
    [InlineData(11, 10)]
    [InlineData(1, 0)]
    public void Constructor_WithAnInvalidThresholdOrLimit_Throws(long warningThreshold, long limit)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new EncryptionBudget(warningThreshold, limit));
    }
}
