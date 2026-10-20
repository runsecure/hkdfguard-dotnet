using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Amazon.Runtime;

namespace HkdfGuard.KeyWrapping.AwsKms.Test.TestHelpers;

/// <summary>
/// An in-process stand-in for KMS, implementing only the three calls AwsKmsKeyWrapper makes (any
/// other member throws). By default it behaves like a symmetric KMS key: ciphertext is AES-GCM
/// under a local key, binding the key ID and encryption context, so Decrypt fails unless both match.
/// Each call can be replaced with a handler to return or throw what a test needs. Every request is
/// recorded; Encrypt's plaintext is copied when it arrives, since the wrapper zeroes it afterwards.
/// </summary>
public class FakeKms : DispatchProxy
{
    private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);

    public Func<EncryptRequest, EncryptResponse>? OnEncrypt { get; set; }
    public Func<DecryptRequest, DecryptResponse>? OnDecrypt { get; set; }
    public Func<GenerateDataKeyWithoutPlaintextRequest, GenerateDataKeyWithoutPlaintextResponse>? OnGenerate { get; set; }

    public List<EncryptRequest> EncryptRequests { get; } = [];
    public List<byte[]> EncryptPlaintexts { get; } = [];
    public List<DecryptRequest> DecryptRequests { get; } = [];
    public List<GenerateDataKeyWithoutPlaintextRequest> GenerateRequests { get; } = [];

    /// <summary>The plaintext stream of every Decrypt response returned, to check it was zeroed.</summary>
    public List<MemoryStream> DecryptPlaintextStreams { get; } = [];

    public IAmazonKeyManagementService Client => (IAmazonKeyManagementService)(object)this;

    public static FakeKms Create() => (FakeKms)(object)Create<IAmazonKeyManagementService, FakeKms>();

    protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
    {
        var cancellationToken = args?.OfType<CancellationToken>().FirstOrDefault() ?? default;
        if (cancellationToken.IsCancellationRequested)
            return FromCanceled(targetMethod!.ReturnType, cancellationToken);

        try
        {
            return targetMethod?.Name switch
            {
                nameof(IAmazonKeyManagementService.EncryptAsync) => Task.FromResult(Encrypt((EncryptRequest)args![0]!)),
                nameof(IAmazonKeyManagementService.DecryptAsync) => Task.FromResult(Decrypt((DecryptRequest)args![0]!)),
                nameof(IAmazonKeyManagementService.GenerateDataKeyWithoutPlaintextAsync) =>
                    Task.FromResult(Generate((GenerateDataKeyWithoutPlaintextRequest)args![0]!)),
                _ => throw new NotSupportedException($"FakeKms does not implement {targetMethod?.Name}."),
            };
        }
        catch (Exception e) when (targetMethod!.Name.EndsWith("Async", StringComparison.Ordinal))
        {
            return FromException(targetMethod.ReturnType, e);
        }
    }

    private EncryptResponse Encrypt(EncryptRequest request)
    {
        EncryptRequests.Add(request);
        EncryptPlaintexts.Add(request.Plaintext.ToArray());
        return OnEncrypt?.Invoke(request) ?? new EncryptResponse
        {
            KeyId = request.KeyId,
            CiphertextBlob = new MemoryStream(Seal(request.Plaintext.ToArray(), request.KeyId, request.EncryptionContext)),
        };
    }

    private DecryptResponse Decrypt(DecryptRequest request)
    {
        DecryptRequests.Add(request);
        var response = OnDecrypt?.Invoke(request) ?? new DecryptResponse
        {
            KeyId = request.KeyId,
            // Built the way the SDK builds it: over an array it does not expose.
            Plaintext = new MemoryStream(Open(request.CiphertextBlob.ToArray(), request.KeyId, request.EncryptionContext)),
        };
        if (response.Plaintext is not null)
            DecryptPlaintextStreams.Add(response.Plaintext);
        return response;
    }

    private GenerateDataKeyWithoutPlaintextResponse Generate(GenerateDataKeyWithoutPlaintextRequest request)
    {
        GenerateRequests.Add(request);
        return OnGenerate?.Invoke(request) ?? new GenerateDataKeyWithoutPlaintextResponse
        {
            KeyId = request.KeyId,
            CiphertextBlob = new MemoryStream(Seal(RandomNumberGenerator.GetBytes(32), request.KeyId, request.EncryptionContext)),
        };
    }

    private byte[] Seal(byte[] plaintext, string keyId, Dictionary<string, string>? context)
    {
        var sealedBlob = new byte[12 + 16 + plaintext.Length];
        RandomNumberGenerator.Fill(sealedBlob.AsSpan(0, 12));
        using var aes = new AesGcm(_key, 16);
        aes.Encrypt(sealedBlob.AsSpan(0, 12), plaintext, sealedBlob.AsSpan(28), sealedBlob.AsSpan(12, 16), Aad(keyId, context));
        return sealedBlob;
    }

    private byte[] Open(byte[] sealedBlob, string keyId, Dictionary<string, string>? context)
    {
        if (sealedBlob.Length < 28)
            throw InvalidCiphertext();

        var plaintext = new byte[sealedBlob.Length - 28];
        try
        {
            using var aes = new AesGcm(_key, 16);
            aes.Decrypt(sealedBlob.AsSpan(0, 12), sealedBlob.AsSpan(28), sealedBlob.AsSpan(12, 16), plaintext, Aad(keyId, context));
        }
        catch (AuthenticationTagMismatchException)
        {
            // Real KMS reports a key mismatch as IncorrectKeyException and a context mismatch or
            // tampering as InvalidCiphertextException; one is enough for a fake.
            throw InvalidCiphertext();
        }
        return plaintext;
    }

    /// <summary>An exception shaped like the one the SDK raises for a KMS error response.</summary>
    public static T ServiceError<T>(string errorCode, HttpStatusCode status = HttpStatusCode.BadRequest) where T : AmazonServiceException
        => (T)Activator.CreateInstance(typeof(T), $"{errorCode} from FakeKms.", ErrorType.Sender, errorCode, "fake-request-id", status)!;

    private static InvalidCiphertextException InvalidCiphertext() => ServiceError<InvalidCiphertextException>("InvalidCiphertextException");

    private static byte[] Aad(string keyId, Dictionary<string, string>? context)
    {
        var text = new StringBuilder(keyId);
        foreach (var (key, value) in (context ?? []).OrderBy(pair => pair.Key, StringComparer.Ordinal))
            text.Append('\0').Append(key).Append('=').Append(value);
        return Encoding.UTF8.GetBytes(text.ToString());
    }

    private static object FromCanceled(Type taskType, CancellationToken cancellationToken)
        => typeof(Task).GetMethod(nameof(Task.FromCanceled), 1, [typeof(CancellationToken)])!
            .MakeGenericMethod(taskType.GetGenericArguments()[0]).Invoke(null, [cancellationToken])!;

    private static object FromException(Type taskType, Exception exception)
        => typeof(Task).GetMethod(nameof(Task.FromException), 1, [typeof(Exception)])!
            .MakeGenericMethod(taskType.GetGenericArguments()[0]).Invoke(null, [exception])!;
}
