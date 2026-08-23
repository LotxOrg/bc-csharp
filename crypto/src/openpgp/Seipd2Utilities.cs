using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>
    /// The pieces RFC 9580 5.13.2 builds a version 2 Symmetrically Encrypted and Integrity
    /// Protected Data packet out of: the key derivation, the per-chunk nonce, and the AEAD cipher
    /// itself.
    /// </summary>
    /// <remarks>
    /// A v2 SEIPD packet is not one ciphertext but a series of independently authenticated chunks
    /// followed by a tag over the total length. That shape is what lets a reader verify as it goes
    /// instead of holding the whole message before it can trust any of it, and it is why a
    /// truncated ciphertext is detected rather than silently accepted.
    /// </remarks>
    internal static class Seipd2Utilities
    {
        /// <summary>The authentication tag every AEAD mode RFC 9580 allows produces, in bits.</summary>
        internal const int MacSizeInBits = 128;

        /// <summary>
        /// The chunk size octet used when a caller does not choose one: 2^18 octets, 256 KiB.
        /// </summary>
        /// <remarks>
        /// Every chunk costs a 16-octet tag, and both encryption and decryption hold one chunk at a
        /// time, so the octet trades space against overhead. At 256 KiB the tags come to well under
        /// a thousandth of the message while the buffer stays small enough to hold per connection.
        /// </remarks>
        internal const int DefaultChunkSizeOctet = 12;

        /// <summary>
        /// RFC 9580 5.13.2: "chunk_size = (uint32_t) 1 &lt;&lt; (c + 6)".
        /// </summary>
        internal static int ChunkLength(int chunkSizeOctet)
        {
            if (chunkSizeOctet < 0 || chunkSizeOctet > SymmetricEncIntegrityPacket.MaxChunkSizeOctet)
                throw new ArgumentOutOfRangeException(nameof(chunkSizeOctet));

            return 1 << (chunkSizeOctet + 6);
        }

        /// <summary>
        /// Derive the message key and the leading part of the nonce, per RFC 9580 5.13.2: HKDF with
        /// SHA-256, the session key as input keying material, the packet's salt as salt, and the
        /// packet's additional data as info. The leftmost octets are the key and what follows is
        /// all but the last eight octets of the nonce, which the chunk index fills in.
        /// </summary>
        internal static void DeriveMessageKeyAndIV(byte[] sessionKey, byte[] salt, byte[] aaData,
            SymmetricKeyAlgorithmTag cipherAlgorithm, AeadAlgorithmTag aeadAlgorithm,
            out KeyParameter messageKey, out byte[] iv)
        {
            int keyLength = SymmetricKeyUtilities.GetKeyLengthInOctets(cipherAlgorithm);
            int ivLength = AeadUtilities.GetIVLength(aeadAlgorithm);

            var hkdf = new HkdfBytesGenerator(new Sha256Digest());
            hkdf.Init(new HkdfParameters(sessionKey, salt, aaData));

            byte[] messageKeyAndIV = new byte[keyLength + ivLength - 8];
            hkdf.GenerateBytes(messageKeyAndIV, 0, messageKeyAndIV.Length);

            byte[][] split = AeadUtilities.SplitMessageKeyAndIv(messageKeyAndIV, cipherAlgorithm, aeadAlgorithm);

            Arrays.ZeroMemory(messageKeyAndIV);

            messageKey = new KeyParameter(split[0]);
            iv = split[1];
        }

        /// <summary>
        /// RFC 9580 5.13.2: "The leftmost N - 64 bits are the IV derived using HKDF. The rightmost
        /// 64 bits are the chunk index as a big-endian value. The index of the first chunk is zero."
        /// </summary>
        /// <remarks>
        /// The final tag continues the sequence: its index is the number of chunks that preceded it.
        /// </remarks>
        internal static byte[] CreateNonce(byte[] iv, long chunkIndex)
        {
            byte[] nonce = Arrays.Clone(iv);
            Pack.UInt64_To_BE((ulong)chunkIndex, nonce, nonce.Length - 8);
            return nonce;
        }

        /// <summary>
        /// The additional data authenticating the final tag: the packet's own additional data
        /// followed by "an 8-octet, big-endian value specifying the total number of plaintext octets
        /// encrypted. This allows detection of a truncated ciphertext."
        /// </summary>
        internal static byte[] CreateFinalAAData(byte[] aaData, long totalPlaintextLength)
        {
            byte[] finalAAData = new byte[aaData.Length + 8];
            Array.Copy(aaData, 0, finalAAData, 0, aaData.Length);
            Pack.UInt64_To_BE((ulong)totalPlaintextLength, finalAAData, aaData.Length);
            return finalAAData;
        }

        /// <summary>
        /// An AEAD cipher ready for one chunk. A fresh instance per chunk rather than a reset one,
        /// so that a mode holding state across a reset cannot carry it into the next chunk.
        /// </summary>
        internal static IAeadCipher CreateAeadCipher(SymmetricKeyAlgorithmTag cipherAlgorithm,
            AeadAlgorithmTag aeadAlgorithm, KeyParameter messageKey, byte[] nonce, byte[] aaData,
            bool forEncryption)
        {
            IAeadCipher cipher = CreateAeadCipher(cipherAlgorithm, aeadAlgorithm);

            cipher.Init(forEncryption, new AeadParameters(messageKey, MacSizeInBits, nonce, aaData));

            return cipher;
        }

        private static IAeadCipher CreateAeadCipher(SymmetricKeyAlgorithmTag cipherAlgorithm,
            AeadAlgorithmTag aeadAlgorithm)
        {
            switch (aeadAlgorithm)
            {
            case AeadAlgorithmTag.Eax:
                return new EaxBlockCipher(CreateBlockCipher(cipherAlgorithm));
            case AeadAlgorithmTag.Ocb:
                return new OcbBlockCipher(CreateBlockCipher(cipherAlgorithm),
                    CreateBlockCipher(cipherAlgorithm));
            case AeadAlgorithmTag.Gcm:
                return new GcmBlockCipher(CreateBlockCipher(cipherAlgorithm));
            default:
                throw new PgpException("unknown AEAD algorithm: " + aeadAlgorithm);
            }
        }

        /// <summary>
        /// The block cipher for an AEAD mode. RFC 9580 5.13.3 through 5.13.5 say of each mode that
        /// it "can only use block ciphers with 16-octet blocks", so the ciphers with 8-octet blocks
        /// are refused here rather than left to produce something no other implementation will read.
        /// </summary>
        private static IBlockCipher CreateBlockCipher(SymmetricKeyAlgorithmTag cipherAlgorithm)
        {
            switch (cipherAlgorithm)
            {
            case SymmetricKeyAlgorithmTag.Aes128:
            case SymmetricKeyAlgorithmTag.Aes192:
            case SymmetricKeyAlgorithmTag.Aes256:
                return AesUtilities.CreateEngine();
            case SymmetricKeyAlgorithmTag.Twofish:
                return new TwofishEngine();
            case SymmetricKeyAlgorithmTag.Camellia128:
            case SymmetricKeyAlgorithmTag.Camellia192:
            case SymmetricKeyAlgorithmTag.Camellia256:
                return new CamelliaEngine();
            default:
                throw new PgpException(
                    "symmetric algorithm " + cipherAlgorithm + " has no 16-octet block and cannot be used with AEAD");
            }
        }
    }
}
