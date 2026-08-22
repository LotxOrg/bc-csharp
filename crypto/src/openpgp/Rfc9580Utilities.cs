using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>
    /// Key derivation for the X25519 and X448 public key algorithms, which RFC 9580 introduced as
    /// algorithms of their own rather than as curves carried by ECDH.
    /// </summary>
    /// <remarks>
    /// The scheme is not the one <see cref="Rfc6637Utilities"/> implements for ECDH. RFC 9580
    /// 5.1.6 and 5.1.7 derive the key-wrapping key with HKDF over the concatenation of the
    /// ephemeral public key, the recipient's public key and the shared secret -- in that order --
    /// with a fixed info string and no salt, and neither a checksum nor padding is appended to the
    /// session key before it is wrapped.
    /// </remarks>
    public sealed class Rfc9580Utilities
    {
        private Rfc9580Utilities()
        {
        }

        // "OpenPGP X25519" and "OpenPGP X448".
        private static readonly byte[] X25519Info = Strings.ToByteArray("OpenPGP X25519");
        private static readonly byte[] X448Info = Strings.ToByteArray("OpenPGP X448");

        internal static bool IsNativeDiffieHellman(PublicKeyAlgorithmTag algorithm) =>
            algorithm == PublicKeyAlgorithmTag.X25519 || algorithm == PublicKeyAlgorithmTag.X448;

        /// <summary>The size of a public key, and of an ephemeral public key, in octets.</summary>
        internal static int PublicKeyLength(PublicKeyAlgorithmTag algorithm) =>
            algorithm == PublicKeyAlgorithmTag.X25519 ? X25519PublicBcpgKey.Length
            : algorithm == PublicKeyAlgorithmTag.X448 ? X448PublicBcpgKey.Length
            : throw new ArgumentException("not a native Diffie-Hellman algorithm: " + algorithm,
                nameof(algorithm));

        /// <summary>
        /// The key wrap RFC 9580 fixes for the algorithm: AES-128 for X25519, AES-256 for X448.
        /// </summary>
        internal static SymmetricKeyAlgorithmTag KeyWrapAlgorithm(PublicKeyAlgorithmTag algorithm) =>
            algorithm == PublicKeyAlgorithmTag.X25519 ? SymmetricKeyAlgorithmTag.Aes128
            : algorithm == PublicKeyAlgorithmTag.X448 ? SymmetricKeyAlgorithmTag.Aes256
            : throw new ArgumentException("not a native Diffie-Hellman algorithm: " + algorithm,
                nameof(algorithm));

        /// <summary>
        /// RFC 9580 5.1.6 and 5.1.7: a v3 PKESK packet carries the symmetric algorithm identifier
        /// in the clear beside the wrapped session key rather than inside it, and "the symmetric
        /// algorithm used MUST be AES-128, AES-192, or AES-256".
        /// </summary>
        internal static void ValidateSessionKeyAlgorithm(PublicKeyAlgorithmTag algorithm,
            SymmetricKeyAlgorithmTag sessionKeyAlgorithm)
        {
            switch (sessionKeyAlgorithm)
            {
            case SymmetricKeyAlgorithmTag.Aes128:
            case SymmetricKeyAlgorithmTag.Aes192:
            case SymmetricKeyAlgorithmTag.Aes256:
                break;
            default:
                throw new PgpException(
                    algorithm + " requires AES-128, AES-192 or AES-256, not " + sessionKeyAlgorithm);
            }
        }

        public static KeyParameter CreateKey(PublicKeyAlgorithmTag algorithm,
            byte[] ephemeralPublicKey, byte[] recipientPublicKey, byte[] sharedSecret)
        {
            bool isX25519 = algorithm == PublicKeyAlgorithmTag.X25519;

            IDigest digest = isX25519 ? new Sha256Digest() : (IDigest)new Sha512Digest();
            var hkdf = new HkdfBytesGenerator(digest);

            hkdf.Init(new HkdfParameters(
                Arrays.ConcatenateAll(ephemeralPublicKey, recipientPublicKey, sharedSecret),
                salt: null,
                info: isX25519 ? X25519Info : X448Info));

            byte[] kek = new byte[isX25519 ? 16 : 32];
            hkdf.GenerateBytes(kek, 0, kek.Length);

            return new KeyParameter(kek);
        }
    }
}
