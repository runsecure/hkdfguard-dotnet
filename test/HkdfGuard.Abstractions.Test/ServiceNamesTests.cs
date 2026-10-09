namespace HkdfGuard.Abstractions.Test;

public class ServiceNamesTests
{
    [Theory]
    [InlineData("a")]
    [InlineData("7")]
    [InlineData("my.service")]
    [InlineData("com.example.Orders2")]
    [InlineData("trailing.")]
    public void ValidNames_Pass(string name)
    {
        Assert.True(ServiceNames.IsValid(name));
        Assert.Null(ServiceNames.GetProblem(name));
        ServiceNames.ThrowIfInvalid(name, "name");
    }

    [Fact]
    public void ExactlyMaxLength_Passes_AndOneMoreFails()
    {
        Assert.Equal(128, ServiceNames.MaxLength);
        Assert.True(ServiceNames.IsValid(new string('a', ServiceNames.MaxLength)));

        var tooLong = new string('a', ServiceNames.MaxLength + 1);
        Assert.False(ServiceNames.IsValid(tooLong));
        Assert.Contains("at most 128 characters; this one is 129", ServiceNames.GetProblem(tooLong));
    }

    [Theory]
    [InlineData(null, "required")]
    [InlineData("", "required")]
    [InlineData(".service", "can't start with '.'")]
    [InlineData(".", "can't start with '.'")]
    [InlineData("my..service", "can't contain '..'")]
    [InlineData("my...service", "can't contain '..'")]
    [InlineData("service..", "can't contain '..'")]
    [InlineData("my-service", "U+002D at position 2")]
    [InlineData("my service", "U+0020 at position 2")]
    [InlineData("my_service", "U+005F at position 2")]
    [InlineData("café", "U+00E9 at position 3")]
    [InlineData("a/b", "U+002F at position 1")]
    [InlineData("a\0b", "U+0000 at position 1")]
    public void InvalidNames_FailWithTheReason(string? name, string reason)
    {
        Assert.False(ServiceNames.IsValid(name));
        Assert.Contains(reason, ServiceNames.GetProblem(name));
    }

    [Fact]
    public void ThrowIfInvalid_ReportsTheParameterAndReason()
    {
        Assert.Equal("serviceName", Assert.Throws<ArgumentNullException>(() => ServiceNames.ThrowIfInvalid(null, "serviceName")).ParamName);

        var ex = Assert.Throws<ArgumentException>(() => ServiceNames.ThrowIfInvalid("a..b", "serviceName"));
        Assert.Equal("serviceName", ex.ParamName);
        Assert.Contains("can't contain '..'", ex.Message);
    }
}
