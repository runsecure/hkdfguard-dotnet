using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace HkdfGuard.Diagnostics;

/// <summary>
/// One component's telemetry surface: an ActivitySource and Meter sharing that component's scope
/// name, an EnableSensitiveLogging toggle, and the RecordException/LogSensitiveOperation helpers
/// every operation across the library calls through. A single implementation shared by every
/// component in <see cref="HkdfGuardTelemetry"/> - replacing what used to be six near-identical,
/// hand-duplicated Diagnostics classes.
/// </summary>
public sealed class ComponentTelemetry
{
    private readonly ComponentTelemetry? _sharedFlagOwner;

    /// <summary>
    /// This component's ActivitySource/Meter scope name - e.g. "HkdfGuard.Cache".
    /// </summary>
    public string SourceName { get; }

    public ActivitySource ActivitySource { get; }

    public Meter Meter { get; }

    /// <param name="sourceName">This component's ActivitySource/Meter scope name.</param>
    internal ComponentTelemetry(string sourceName)
    {
        SourceName = sourceName;
        ActivitySource = new ActivitySource(sourceName);
        Meter = new Meter(sourceName);
    }

    /// <param name="sourceName">This component's ActivitySource/Meter scope name.</param>
    /// <param name="sharedFlagOwner">EnableSensitiveLogging delegates to this component's own
    /// flag instead of keeping an independent one - e.g. Cache/DataProtection/EncryptedConfiguration
    /// all share Root's flag.</param>
    internal ComponentTelemetry(string sourceName, ComponentTelemetry sharedFlagOwner)
        : this(sourceName)
    {
        _sharedFlagOwner = sharedFlagOwner;
    }

    /// <summary>
    /// When enabled, sensitive operations emit additional debug telemetry (operation metadata such
    /// as buffer lengths and identifiers). Raw key, plaintext, and ciphertext bytes are never
    /// logged, regardless of this setting. Components constructed with a sharedFlagOwner read and
    /// write that owner's flag instead of keeping their own.
    /// </summary>
    public bool EnableSensitiveLogging
    {
        get => _sharedFlagOwner?.EnableSensitiveLogging ?? field;
        set
        {
            if (_sharedFlagOwner is not null)
                _sharedFlagOwner.EnableSensitiveLogging = value;
            else
                field = value;
        }
    }

    /// <summary>
    /// Records an exception on the current activity and marks it as errored.
    /// </summary>
    public static void RecordException(Activity? activity, Exception exception)
    {
        activity?.AddException(exception);
        activity?.SetStatus(ActivityStatusCode.Error, exception.Message);
    }

    /// <summary>
    /// Emits a fixed-name (<see cref="EventNames.SensitiveOperation"/>) debug event when
    /// <see cref="EnableSensitiveLogging"/> is set, carrying operationName and every detail as
    /// attributes. Only pass non-sensitive metadata (lengths, identifiers, timings) as details -
    /// never raw key, plaintext, or ciphertext bytes.
    /// </summary>
    public void LogSensitiveOperation(Activity? activity, string operationName, params (string Key, object? Value)[] details)
    {
        if (!EnableSensitiveLogging || activity is null)
            return;

        var tags = new ActivityTagsCollection { [AttributeNames.OperationName] = operationName };
        foreach (var (key, value) in details)
            tags[key] = value;

        activity.AddEvent(new ActivityEvent(EventNames.SensitiveOperation, tags: tags));
    }
}
