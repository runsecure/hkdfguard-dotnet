using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Grpc.Core;
using Grpc.Core.Interceptors;

namespace HkdfGuard.Cache.GoogleSecretManager;

/// <summary>
/// Zeroes the buffer gRPC received each response message into, once it has been deserialized.
/// Grpc.Net.Client reads every message into an array rented from the shared ArrayPool and returns it
/// uncleared, so a secret payload would otherwise stay in a pooled array that other code is handed
/// next. Deserialization copies the payload out first (into the ByteString the cache then zeroes),
/// so clearing the buffer afterwards loses nothing.
/// </summary>
internal sealed class ReceiveBufferScrubber : Interceptor
{
    public override TResponse BlockingUnaryCall<TRequest, TResponse>(TRequest request,
        ClientInterceptorContext<TRequest, TResponse> context, BlockingUnaryCallContinuation<TRequest, TResponse> continuation)
        => continuation(request, Scrubbing(context));

    public override AsyncUnaryCall<TResponse> AsyncUnaryCall<TRequest, TResponse>(TRequest request,
        ClientInterceptorContext<TRequest, TResponse> context, AsyncUnaryCallContinuation<TRequest, TResponse> continuation)
        => continuation(request, Scrubbing(context));

    // The same call, with a response marshaller that zeroes the received buffer after deserializing.
    private static ClientInterceptorContext<TRequest, TResponse> Scrubbing<TRequest, TResponse>(ClientInterceptorContext<TRequest, TResponse> context)
        where TRequest : class
        where TResponse : class
    {
        var method = context.Method;
        var deserialize = method.ResponseMarshaller.ContextualDeserializer;
        var marshaller = new Marshaller<TResponse>(method.ResponseMarshaller.ContextualSerializer, received =>
        {
            try
            {
                return deserialize(received);
            }
            finally
            {
                foreach (var segment in received.PayloadAsReadOnlySequence())
                    CryptographicOperations.ZeroMemory(MemoryMarshal.AsMemory(segment).Span);
            }
        });

        return new ClientInterceptorContext<TRequest, TResponse>(
            new Method<TRequest, TResponse>(method.Type, method.ServiceName, method.Name, method.RequestMarshaller, marshaller),
            context.Host, context.Options);
    }
}
