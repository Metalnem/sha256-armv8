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
		private static readonly byte[] data = new byte[1024 * 1024];

		private readonly SHA256 openSsl = SHA256.Create();
		private readonly Sha256Digest bouncyCastle = new Sha256Digest();

		[Benchmark]
		public byte[] OpenSsl()
		{
			return openSsl.ComputeHash(data);
		}

		[Benchmark]
		public byte[] Intrinsics()
		{
			return Sha256Arm64.ComputeHash(data);
		}

		[Benchmark]
		public byte[] BouncyCastle()
		{
			byte[] digest = new byte[bouncyCastle.GetDigestSize()];

			bouncyCastle.BlockUpdate(data, 0, data.Length);
			bouncyCastle.DoFinal(digest, 0);

			return digest;
		}
	}
}
