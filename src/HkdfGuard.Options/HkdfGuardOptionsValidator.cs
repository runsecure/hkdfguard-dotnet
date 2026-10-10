using HkdfGuard.Abstractions;
using Microsoft.Extensions.Options;

namespace HkdfGuard.Options;

/// <summary>
/// Validates an HkdfGuardOptions instance against the same constraints KeyRingBuilder itself
/// enforces (CachedKeyExpiry 1-300, MaxRefreshFailures at least 1, EphemeralKeyRotationHours 1-1193,
/// EphemeralKeyRetentionHours at least 1, at least one key source), plus what
/// ApplyTo needs to hold before it ever touches a KeyRingBuilder - a valid ServiceName (see ServiceNames), every
/// KeyFile having a path, and version numbers that don't collide across KeyFiles/EphemeralKeys
/// (KeyRing.Add throws on a duplicate version at Build time; catching it here up front gives a
/// much clearer failure, at options-bind time, than deep inside Build).
/// </summary>
public sealed class HkdfGuardOptionsValidator : IValidateOptions<HkdfGuardOptions>
{
    public ValidateOptionsResult Validate(string? name, HkdfGuardOptions options)
    {
        var failures = new List<string>();

        if (ServiceNames.GetProblem(options.ServiceName) is { } serviceNameProblem)
            failures.Add($"ServiceName is invalid: {serviceNameProblem}");

        if (options.CachedKeyExpiry is < 1 or > 300)
            failures.Add("CachedKeyExpiry must be between 1 and 300 seconds.");

        if (options.MaxRefreshFailures is < 1)
            failures.Add("MaxRefreshFailures must be at least 1.");

        if (options.EphemeralKeyRotationHours is < 1 or > HkdfGuardOptions.MaxEphemeralKeyRotationHours)
            failures.Add($"EphemeralKeyRotationHours must be between 1 and {HkdfGuardOptions.MaxEphemeralKeyRotationHours}.");

        if (options.EphemeralKeyRetentionHours is < 1)
            failures.Add("EphemeralKeyRetentionHours must be at least 1.");

        if (options.DisableEphemeralKeyRotation && options.EphemeralKeyRotationHours is not null)
            failures.Add("DisableEphemeralKeyRotation and EphemeralKeyRotationHours can't both be set: one turns rotation off, the other schedules it.");

        if (options.FailOpenOnRefreshFailure && options.MaxRefreshFailures is not null)
            failures.Add("FailOpenOnRefreshFailure and MaxRefreshFailures can't both be set: one fails open, the other fails closed.");

        if (options.KeyFiles.Count == 0 && options.EphemeralKeys.Count == 0)
            failures.Add("At least one key file or ephemeral key is required.");

        // ReSharper disable once ForeachCanBeConvertedToQueryUsingAnotherGetEnumerator
        foreach (var keyFile in options.KeyFiles)
        {
            if (string.IsNullOrWhiteSpace(keyFile.Path))
                failures.Add($"KeyFiles version {keyFile.Version} is missing a path.");
        }

        var duplicateVersions = options.KeyFiles.Select(k => k.Version)
            .Concat(options.EphemeralKeys)
            .GroupBy(version => version)
            .Where(group => group.Count() > 1)
            .Select(group => group.Key);

        foreach (var version in duplicateVersions)
            failures.Add($"Version {version} is registered more than once across KeyFiles/EphemeralKeys.");

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }
}
