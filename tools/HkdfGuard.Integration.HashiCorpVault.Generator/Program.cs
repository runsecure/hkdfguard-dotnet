using HkdfGuard.Integration.HashiCorpVault.Generator;

// Regenerates src/HkdfGuard.Integration.HashiCorpVault/Generated from its openapi.json:
//
//     dotnet run --project tools/HkdfGuard.Integration.HashiCorpVault.Generator [-- --spec <openapi.json> --output <directory>]
//
// See GeneratorCommand.
return GeneratorCommand.Run(args, Directory.GetCurrentDirectory(), Console.Out, Console.Error);
