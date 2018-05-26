using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm.Arm64;

namespace Intrinsics
{
	public static class Program
	{
		private static readonly uint[] h = new uint[8]
		{
			0x6a09e667,
			0xbb67ae85,
			0x3c6ef372,
			0xa54ff53a,
			0x510e527f,
			0x9b05688c,
			0x1f83d9ab,
			0x5be0cd19,
		};

		private static readonly uint[] k = new uint[64]
		{
			0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
			0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
			0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
			0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
			0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
			0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
			0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
			0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
			0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
			0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
			0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
			0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
			0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
			0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
			0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
		};

		public static void Main(string[] args)
		{
			var data = new byte[100 * 1024 * 1024];
			var padding = new byte[64];

			padding[0] = 0x80;
			BinaryPrimitives.WriteUInt64BigEndian(padding.AsSpan().Slice(56), (ulong)data.Length * 8);

			var state = h.AsSpan().ToArray();

			Block(state, data);
			Block(state, padding);

			for (int i = 0; i < state.Length; ++i)
			{
				state[i] = BinaryPrimitives.ReverseEndianness(state[i]);
			}

			// 20492a4d0d84f8beb1767f6616229f85d44c2827b64bdbfb260ee12fa1109e0e
			var hash = MemoryMarshal.Cast<uint, byte>(state).ToArray();

			Console.WriteLine(BitConverter.ToString(hash).Replace("-", String.Empty).ToLower());
		}

		private static void Block(uint[] state, ReadOnlySpan<byte> data)
		{
			var msg = new byte[64];

			// Load state
			var state0 = Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref state[0]));
			var state1 = Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref state[4]));

			while (data.Length >= 64)
			{
				// Save state
				var abef_save = state0;
				var cdgh_save = state1;

				var from = MemoryMarshal.Cast<byte, uint>(data);
				var to = MemoryMarshal.Cast<byte, uint>(msg);

				// Reverse for little endian
				for (int i = 0; i < 16; ++i)
				{
					to[i] = BinaryPrimitives.ReverseEndianness(from[i]);
				}

				// Load message
				var msg0 = Unsafe.ReadUnaligned<Vector128<uint>>(ref msg[0]);
				var msg1 = Unsafe.ReadUnaligned<Vector128<uint>>(ref msg[16]);
				var msg2 = Unsafe.ReadUnaligned<Vector128<uint>>(ref msg[32]);
				var msg3 = Unsafe.ReadUnaligned<Vector128<uint>>(ref msg[48]);

				Vector128<uint> tmp0, tmp1, tmp2;
				tmp0 = Simd.Add(msg0, Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref k[0x00])));

				// Rounds 0-3
				msg0 = Sha256.SchedulePart1(msg0, msg1);
				tmp2 = state0;
				tmp1 = Simd.Add(msg1, Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref k[0x04])));
				state0 = Sha256.HashLower(state0, state1, tmp0);
				state1 = Sha256.HashUpper(state1, tmp2, tmp0);
				msg0 = Sha256.SchedulePart2(msg0, msg2, msg3);

				// Rounds 4-7
				msg1 = Sha256.SchedulePart1(msg1, msg2);
				tmp2 = state0;
				tmp0 = Simd.Add(msg2, Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref k[0x08])));
				state0 = Sha256.HashLower(state0, state1, tmp1);
				state1 = Sha256.HashUpper(state1, tmp2, tmp1);
				msg1 = Sha256.SchedulePart2(msg1, msg3, msg0);

				// Rounds 8-11
				msg2 = Sha256.SchedulePart1(msg2, msg3);
				tmp2 = state0;
				tmp1 = Simd.Add(msg3, Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref k[0x0c])));
				state0 = Sha256.HashLower(state0, state1, tmp0);
				state1 = Sha256.HashUpper(state1, tmp2, tmp0);
				msg2 = Sha256.SchedulePart2(msg2, msg0, msg1);

				// Rounds 12-15
				msg3 = Sha256.SchedulePart1(msg3, msg0);
				tmp2 = state0;
				tmp0 = Simd.Add(msg0, Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref k[0x10])));
				state0 = Sha256.HashLower(state0, state1, tmp1);
				state1 = Sha256.HashUpper(state1, tmp2, tmp1);
				msg3 = Sha256.SchedulePart2(msg3, msg1, msg2);

				// Rounds 16-19
				msg0 = Sha256.SchedulePart1(msg0, msg1);
				tmp2 = state0;
				tmp1 = Simd.Add(msg1, Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref k[0x14])));
				state0 = Sha256.HashLower(state0, state1, tmp0);
				state1 = Sha256.HashUpper(state1, tmp2, tmp0);
				msg0 = Sha256.SchedulePart2(msg0, msg2, msg3);

				// Rounds 20-23
				msg1 = Sha256.SchedulePart1(msg1, msg2);
				tmp2 = state0;
				tmp0 = Simd.Add(msg2, Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref k[0x18])));
				state0 = Sha256.HashLower(state0, state1, tmp1);
				state1 = Sha256.HashUpper(state1, tmp2, tmp1);
				msg1 = Sha256.SchedulePart2(msg1, msg3, msg0);

				// Rounds 24-27
				msg2 = Sha256.SchedulePart1(msg2, msg3);
				tmp2 = state0;
				tmp1 = Simd.Add(msg3, Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref k[0x1c])));
				state0 = Sha256.HashLower(state0, state1, tmp0);
				state1 = Sha256.HashUpper(state1, tmp2, tmp0);
				msg2 = Sha256.SchedulePart2(msg2, msg0, msg1);

				// Rounds 28-31
				msg3 = Sha256.SchedulePart1(msg3, msg0);
				tmp2 = state0;
				tmp0 = Simd.Add(msg0, Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref k[0x20])));
				state0 = Sha256.HashLower(state0, state1, tmp1);
				state1 = Sha256.HashUpper(state1, tmp2, tmp1);
				msg3 = Sha256.SchedulePart2(msg3, msg1, msg2);

				// Rounds 32-35
				msg0 = Sha256.SchedulePart1(msg0, msg1);
				tmp2 = state0;
				tmp1 = Simd.Add(msg1, Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref k[0x24])));
				state0 = Sha256.HashLower(state0, state1, tmp0);
				state1 = Sha256.HashUpper(state1, tmp2, tmp0);
				msg0 = Sha256.SchedulePart2(msg0, msg2, msg3);

				// Rounds 36-39
				msg1 = Sha256.SchedulePart1(msg1, msg2);
				tmp2 = state0;
				tmp0 = Simd.Add(msg2, Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref k[0x28])));
				state0 = Sha256.HashLower(state0, state1, tmp1);
				state1 = Sha256.HashUpper(state1, tmp2, tmp1);
				msg1 = Sha256.SchedulePart2(msg1, msg3, msg0);

				// Rounds 40-43
				msg2 = Sha256.SchedulePart1(msg2, msg3);
				tmp2 = state0;
				tmp1 = Simd.Add(msg3, Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref k[0x2c])));
				state0 = Sha256.HashLower(state0, state1, tmp0);
				state1 = Sha256.HashUpper(state1, tmp2, tmp0);
				msg2 = Sha256.SchedulePart2(msg2, msg0, msg1);

				// Rounds 44-47
				msg3 = Sha256.SchedulePart1(msg3, msg0);
				tmp2 = state0;
				tmp0 = Simd.Add(msg0, Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref k[0x30])));
				state0 = Sha256.HashLower(state0, state1, tmp1);
				state1 = Sha256.HashUpper(state1, tmp2, tmp1);
				msg3 = Sha256.SchedulePart2(msg3, msg1, msg2);

				// Rounds 48-51
				tmp2 = state0;
				tmp1 = Simd.Add(msg1, Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref k[0x34])));
				state0 = Sha256.HashLower(state0, state1, tmp0);
				state1 = Sha256.HashUpper(state1, tmp2, tmp0);

				// Rounds 52-55
				tmp2 = state0;
				tmp0 = Simd.Add(msg2, Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref k[0x38])));
				state0 = Sha256.HashLower(state0, state1, tmp1);
				state1 = Sha256.HashUpper(state1, tmp2, tmp1);

				// Rounds 56-59
				tmp2 = state0;
				tmp1 = Simd.Add(msg3, Unsafe.ReadUnaligned<Vector128<uint>>(ref Unsafe.As<uint, byte>(ref k[0x3c])));
				state0 = Sha256.HashLower(state0, state1, tmp0);
				state1 = Sha256.HashUpper(state1, tmp2, tmp0);

				// Rounds 60-63
				tmp2 = state0;
				state0 = Sha256.HashLower(state0, state1, tmp1);
				state1 = Sha256.HashUpper(state1, tmp2, tmp1);

				// Combine state
				state0 = Simd.Add(state0, abef_save);
				state1 = Simd.Add(state1, cdgh_save);

				data = data.Slice(64);
			}

			Unsafe.WriteUnaligned(ref Unsafe.As<uint, byte>(ref state[0]), state0);
			Unsafe.WriteUnaligned(ref Unsafe.As<uint, byte>(ref state[4]), state1);
		}
	}
}
