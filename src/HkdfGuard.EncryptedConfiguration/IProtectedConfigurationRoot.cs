using HkdfGuard.Abstractions;
using Microsoft.Extensions.Configuration;

namespace HkdfGuard.EncryptedConfiguration;

/// <summary>
/// An IConfigurationRoot whose values can also be read as protected secrets via
/// IProtectedReadOnlyCache. A configuration value formatted as a protected value (see
/// DefaultFormatProvider - "enc::v{version}::{base64}") is revealed by Decrypt/
/// TryGetMaxDecryptedLength using that same name as the configuration key; every other
/// IConfigurationRoot member behaves exactly as it does on the underlying root.
/// </summary>
public interface IProtectedConfigurationRoot : IConfigurationRoot, IProtectedReadOnlyCache;
