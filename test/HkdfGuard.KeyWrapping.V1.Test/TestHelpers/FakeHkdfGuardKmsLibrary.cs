using HkdfGuard.KeyWrapping.V1.Interop;

namespace HkdfGuard.KeyWrapping.V1.Test.TestHelpers;

internal sealed class FakeHkdfGuardKmsLibrary : AbstractHkdfGuardKmsLibrary
{
    public int WrapDekStatus { get; set; } = Ok;
    public int UnwrapDekStatus { get; set; } = Ok;
    public int GenerateAndWrapDekStatus { get; set; } = Ok;

    public int? WrapDekBytesWrittenOverride { get; set; }
    public int? UnwrapDekBytesWrittenOverride { get; set; }
    public int? GenerateAndWrapDekBytesWrittenOverride { get; set; }

    public byte[]? WrapPayloadToEmit { get; set; }
    public byte[]? UnwrapPayloadToEmit { get; set; }
    public byte[]? GenerateAndWrapPayloadToEmit { get; set; }

    public string? LastService { get; private set; }
    public byte[]? LastWrapPlaintext { get; private set; }
    public byte[]? LastUnwrapWrapped { get; private set; }

    public int WrapCallCount { get; private set; }
    public int UnwrapCallCount { get; private set; }
    public int GenerateAndWrapCallCount { get; private set; }

    /// <summary>When set, answers DescribeStatus; otherwise the base class (no description).</summary>
    public Func<int, string?>? Describe { get; set; }

    public override string? DescribeStatus(int status) => Describe is null ? base.DescribeStatus(status) : Describe(status);

    /// <summary>When set, answers HardenProcess; otherwise the base class (not supported).</summary>
    public Func<int>? Harden { get; set; }

    public int HardenCallCount { get; private set; }

    public override int HardenProcess()
    {
        HardenCallCount++;
        return Harden is null ? base.HardenProcess() : Harden();
    }

    public override int WrapDek(string service, ReadOnlySpan<byte> dek, Span<byte> destination, out int bytesWritten)
    {
        WrapCallCount++;
        LastService = service;
        LastWrapPlaintext = dek.ToArray();

        if (WrapDekStatus != Ok)
        {
            bytesWritten = WrapDekBytesWrittenOverride ?? 0;
            return WrapDekStatus;
        }

        var payload = WrapPayloadToEmit ?? dek.ToArray();
        payload.CopyTo(destination);
        bytesWritten = WrapDekBytesWrittenOverride ?? payload.Length;
        return Ok;
    }

    public override int UnwrapDek(string service, ReadOnlySpan<byte> wrapped, Span<byte> destination, out int bytesWritten)
    {
        UnwrapCallCount++;
        LastService = service;
        LastUnwrapWrapped = wrapped.ToArray();

        if (UnwrapDekStatus != Ok)
        {
            bytesWritten = UnwrapDekBytesWrittenOverride ?? 0;
            return UnwrapDekStatus;
        }

        var payload = UnwrapPayloadToEmit ?? wrapped.ToArray();
        payload.CopyTo(destination);
        bytesWritten = UnwrapDekBytesWrittenOverride ?? payload.Length;
        return Ok;
    }

    public override int GenerateAndWrapDek(string service, Span<byte> destination, out int bytesWritten)
    {
        GenerateAndWrapCallCount++;
        LastService = service;

        if (GenerateAndWrapDekStatus != Ok)
        {
            bytesWritten = GenerateAndWrapDekBytesWrittenOverride ?? 0;
            return GenerateAndWrapDekStatus;
        }

        var payload = GenerateAndWrapPayloadToEmit ?? new byte[64];
        payload.CopyTo(destination);
        bytesWritten = GenerateAndWrapDekBytesWrittenOverride ?? payload.Length;
        return Ok;
    }
}
