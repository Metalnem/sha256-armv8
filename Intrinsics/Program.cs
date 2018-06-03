using System;
using BenchmarkDotNet.Running;

namespace Intrinsics
{
	public static class Program
	{
		public static void Main(string[] args)
		{
			var summary = BenchmarkRunner.Run<Sha256Benchmark>();
		}

		public static void Test()
		{
			var data = new byte[100 * 1024 * 1024];

			// 20492a4d0d84f8beb1767f6616229f85d44c2827b64bdbfb260ee12fa1109e0e
			var hash = Sha256Arm64.ComputeHash(data);
			var s = BitConverter.ToString(hash).Replace("-", String.Empty).ToLower();

			Console.WriteLine(s);
		}
	}
}
