using System.Collections.Generic;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Attributes.Jobs;
using BenchmarkDotNet.Running;
using Org.BouncyCastle.Crypto.Digests;

namespace Intrinsics
{
	[InProcess]
	public class Sha256Benchmark
	{
		private static readonly byte[] data1K = new byte[1024];
		private static readonly byte[] data1M = new byte[1024 * 1024];

		private readonly SHA256 openSsl = SHA256.Create();
		private readonly Sha256Digest bouncyCastle = new Sha256Digest();

		[Benchmark] public byte[] OpenSsl1K() => openSsl.ComputeHash(data1K);
		[Benchmark] public byte[] Intrinsics1K() => Sha256Arm64.ComputeHash(data1K);
		[Benchmark] public byte[] BouncyCastle1K() => BouncyCastle(data1K);

		[Benchmark] public byte[] OpenSsl1M() => openSsl.ComputeHash(data1M);
		[Benchmark] public byte[] Intrinsics1M() => Sha256Arm64.ComputeHash(data1M);
		[Benchmark] public byte[] BouncyCastle1M() => BouncyCastle(data1M);

		private byte[] BouncyCastle(byte[] data)
		{
			byte[] digest = new byte[bouncyCastle.GetDigestSize()];

			bouncyCastle.BlockUpdate(data, 0, data.Length);
			bouncyCastle.DoFinal(digest, 0);

			return digest;
		}
	}
}
