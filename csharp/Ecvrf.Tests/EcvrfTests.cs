using System.Text.Json;
using System.Text.Json.Serialization;

namespace Ecvrf.Tests;

public class EcvrfTests
{
    private static readonly VectorFile Vectors = LoadVectors();

    private static VectorFile LoadVectors()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "vectors", "vectors.json");
            if (File.Exists(candidate))
            {
                var json = File.ReadAllText(candidate);
                return JsonSerializer.Deserialize<VectorFile>(json)
                    ?? throw new InvalidOperationException("failed to parse vectors.json");
            }
            dir = dir.Parent;
        }
        throw new FileNotFoundException("vectors/vectors.json not found");
    }

    private static byte[] HexToBytes(string hex) => hex.Length == 0 ? [] : Convert.FromHexString(hex);

    [Fact]
    public void SuiteMetadata()
    {
        Assert.Equal("ECVRF-EDWARDS25519-SHA512-TAI", Vectors.Suite);
        Assert.Equal("RFC 9381", Vectors.Spec);
    }

    [Fact]
    public void DerivePublicKey_AllVectors()
    {
        foreach (var vec in Vectors.Vectors)
        {
            var pk = EcvrfEd25519.DerivePublicKey(HexToBytes(vec.Sk));
            Assert.Equal(vec.Pk, Convert.ToHexStringLower(pk));
            Assert.True(EcvrfEd25519.IsPublicKey(pk), $"[{vec.Label}] IsPublicKey returned false");
        }
    }

    [Fact]
    public void Prove_AllVectors()
    {
        foreach (var vec in Vectors.Vectors)
        {
            var pi = EcvrfEd25519.Prove(HexToBytes(vec.Sk), HexToBytes(vec.Alpha));
            Assert.Equal(vec.Pi, Convert.ToHexStringLower(pi));
        }
    }

    [Fact]
    public void Verify_AllVectors()
    {
        foreach (var vec in Vectors.Vectors)
        {
            var (valid, beta) = EcvrfEd25519.Verify(
                HexToBytes(vec.Pk),
                HexToBytes(vec.Pi),
                HexToBytes(vec.Alpha));
            Assert.True(valid, $"[{vec.Label}] Verify returned invalid");
            Assert.NotNull(beta);
            Assert.Equal(vec.Beta, Convert.ToHexStringLower(beta));
        }
    }

    [Fact]
    public void ProofToHash_AllVectors()
    {
        foreach (var vec in Vectors.Vectors)
        {
            var beta = EcvrfEd25519.ProofToHash(HexToBytes(vec.Pi));
            Assert.Equal(vec.Beta, Convert.ToHexStringLower(beta));
        }
    }

    [Fact]
    public void NegativeVerify_AllVectors()
    {
        foreach (var vec in Vectors.NegativeVectors)
        {
            var (valid, beta) = EcvrfEd25519.Verify(
                HexToBytes(vec.Pk),
                HexToBytes(vec.Pi),
                HexToBytes(vec.Alpha));
            Assert.True(valid == vec.ExpectedVerify, $"[{vec.Description}] expected {vec.ExpectedVerify}, got {valid}");
            if (!vec.ExpectedVerify)
                Assert.Null(beta);
        }
    }

    [Fact]
    public void Prove_RejectsWrongSkLength()
    {
        Assert.Throws<ArgumentException>(() => EcvrfEd25519.Prove(new byte[31], [0x01]));
        Assert.Throws<ArgumentException>(() => EcvrfEd25519.Prove(new byte[33], [0x01]));
    }
}

public class VectorFile
{
    [JsonPropertyName("suite")]
    public string Suite { get; set; } = "";

    [JsonPropertyName("spec")]
    public string Spec { get; set; } = "";

    [JsonPropertyName("vectors")]
    public List<PositiveVector> Vectors { get; set; } = [];

    [JsonPropertyName("negative_vectors")]
    public List<NegativeVector> NegativeVectors { get; set; } = [];
}

public class PositiveVector
{
    [JsonPropertyName("label")]
    public string Label { get; set; } = "";

    [JsonPropertyName("sk")]
    public string Sk { get; set; } = "";

    [JsonPropertyName("pk")]
    public string Pk { get; set; } = "";

    [JsonPropertyName("alpha")]
    public string Alpha { get; set; } = "";

    [JsonPropertyName("pi")]
    public string Pi { get; set; } = "";

    [JsonPropertyName("beta")]
    public string Beta { get; set; } = "";
}

public class NegativeVector
{
    [JsonPropertyName("description")]
    public string Description { get; set; } = "";

    [JsonPropertyName("pk")]
    public string Pk { get; set; } = "";

    [JsonPropertyName("alpha")]
    public string Alpha { get; set; } = "";

    [JsonPropertyName("pi")]
    public string Pi { get; set; } = "";

    [JsonPropertyName("expected_verify")]
    public bool ExpectedVerify { get; set; }
}
