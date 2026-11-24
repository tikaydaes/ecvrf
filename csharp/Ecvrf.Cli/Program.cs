using Ecvrf;

if (args.Length < 1)
{
    Console.Error.WriteLine("usage: Ecvrf.Cli prove <sk> <alpha> | verify <pk> <pi> <alpha> | derive-pk <sk>");
    return 2;
}

static byte[] FromHex(string hex) => hex.Length == 0 ? [] : Convert.FromHexString(hex);

switch (args[0])
{
    case "prove":
        if (args.Length < 3) return 2;
        Console.WriteLine(Convert.ToHexStringLower(EcvrfEd25519.Prove(FromHex(args[1]), FromHex(args[2]))));
        return 0;
    case "verify":
        if (args.Length < 4) return 2;
        var (valid, beta) = EcvrfEd25519.Verify(FromHex(args[1]), FromHex(args[2]), FromHex(args[3]));
        if (!valid || beta is null) return 1;
        Console.WriteLine(Convert.ToHexStringLower(beta));
        return 0;
    case "derive-pk":
        if (args.Length < 2) return 2;
        Console.WriteLine(Convert.ToHexStringLower(EcvrfEd25519.DerivePublicKey(FromHex(args[1]))));
        return 0;
    default:
        Console.Error.WriteLine($"unknown command: {args[0]}");
        return 2;
}
