using System;
using System.IO;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Basic packet for a PGP public key.</summary>
    public class PublicKeyEncSessionPacket
        : ContainedPacket //, PublicKeyAlgorithmTag
    {
        /// <summary>Version 3 PKESK packet.</summary>
        /// <remarks>
        /// Used only with <see cref="SymmetricEncIntegrityPacket.Version1">V1 SEIPD</see> or
        /// <see cref="SymmetricEncDataPacket">SED</see> packets.
        /// </remarks>
        public const int Version3 = 3;

        /// <summary>Version 6 PKESK packet.</summary>
        /// <remarks>
        /// Used only with <see cref="SymmetricEncIntegrityPacket.Version2">V2 SEIPD</see> packets.
        /// </remarks>
        public const int Version6 = 6;

        private readonly int m_version;
        private readonly ulong m_keyID;
        private readonly int m_keyVersion;
        private readonly byte[] m_fingerprint;
        private readonly PublicKeyAlgorithmTag m_algorithm;
        private readonly byte[][] m_data;

        internal PublicKeyEncSessionPacket(BcpgInputStream bcpgIn)
            : this(bcpgIn, newPacketFormat: false)
        {
        }

        internal PublicKeyEncSessionPacket(BcpgInputStream bcpgIn, bool newPacketFormat)
            : base(PacketTag.PublicKeyEncryptedSession, newPacketFormat)
        {
            m_version = bcpgIn.RequireByte();

            switch (m_version)
            {
            case Version3:
                m_keyID = StreamUtilities.RequireUInt64BE(bcpgIn);
                m_fingerprint = null;
                break;

            case Version6:
            {
                // RFC 9580 5.1.2: a one-octet size covering the key version octet and the
                // fingerprint, which "may be zero, if the key version number field and the
                // fingerprint field are omitted for an 'anonymous recipient'".
                int fieldsLength = bcpgIn.RequireByte();
                if (fieldsLength == 0)
                {
                    m_keyVersion = 0;
                    m_fingerprint = Array.Empty<byte>();
                    m_keyID = 0UL;
                }
                else
                {
                    m_keyVersion = bcpgIn.RequireByte();

                    m_fingerprint = new byte[fieldsLength - 1];
                    bcpgIn.ReadFully(m_fingerprint);

                    m_keyID = KeyIdFromFingerprint(m_keyVersion, m_fingerprint);
                }
                break;
            }

            default:
                throw new UnsupportedPacketVersionException("Unknown PKESK packet version: " + m_version);
            }

            m_algorithm = (PublicKeyAlgorithmTag)bcpgIn.RequireByte();

            switch (m_algorithm)
            {
            case PublicKeyAlgorithmTag.RsaEncrypt:
            case PublicKeyAlgorithmTag.RsaGeneral:
                m_data = new byte[][]{ new MPInteger(bcpgIn).GetEncoded() };
                break;
            case PublicKeyAlgorithmTag.ElGamalEncrypt:
            case PublicKeyAlgorithmTag.ElGamalGeneral:
                MPInteger p = new MPInteger(bcpgIn);
                MPInteger g = new MPInteger(bcpgIn);
                m_data = new byte[][]{
                    p.GetEncoded(),
                    g.GetEncoded(),
                };
                break;
            case PublicKeyAlgorithmTag.ECDH:
                m_data = new byte[][]{ Streams.ReadAll(bcpgIn) };
                break;
            case PublicKeyAlgorithmTag.X25519:
            case PublicKeyAlgorithmTag.X448:
                // RFC 9580 5.1.6 and 5.1.7: an ephemeral public key of fixed size, a one-octet
                // length, and then the fields that length covers. Read whole, like ECDH.
                m_data = new byte[][]{ Streams.ReadAll(bcpgIn) };
                break;
            default:
                throw new IOException("unknown PGP public key algorithm encountered");
            }
        }

        public PublicKeyEncSessionPacket(long keyId, PublicKeyAlgorithmTag algorithm, byte[][] data)
            : base(PacketTag.PublicKeyEncryptedSession)
        {
            m_version = Version3;
            m_keyID = (ulong)keyId;
            m_fingerprint = null;
            m_algorithm = algorithm;
            m_data = CloneData(data);
        }

        /// <summary>
        /// A version 6 packet, which names its recipient by fingerprint rather than by Key ID.
        /// </summary>
        /// <param name="keyVersion">
        /// The version of the key the session key is encrypted to, or zero together with an empty
        /// fingerprint for an anonymous recipient.
        /// </param>
        /// <param name="fingerprint">
        /// The recipient key's fingerprint, or an empty array for an anonymous recipient.
        /// </param>
        /// <param name="algorithm">The public key algorithm the session key was encrypted with.</param>
        /// <param name="data">The algorithm-specific encrypted session key fields.</param>
        public static PublicKeyEncSessionPacket CreateV6Packet(int keyVersion, byte[] fingerprint,
            PublicKeyAlgorithmTag algorithm, byte[][] data)
        {
            return new PublicKeyEncSessionPacket(keyVersion, fingerprint, algorithm, data);
        }

        private PublicKeyEncSessionPacket(int keyVersion, byte[] fingerprint, PublicKeyAlgorithmTag algorithm,
            byte[][] data)
            : base(PacketTag.PublicKeyEncryptedSession)
        {
            if (fingerprint == null)
                throw new ArgumentNullException(nameof(fingerprint));
            if (fingerprint.Length > 0 && 1 + fingerprint.Length > 255)
                throw new ArgumentException("fingerprint too long", nameof(fingerprint));

            m_version = Version6;
            m_keyVersion = fingerprint.Length == 0 ? 0 : keyVersion;
            m_fingerprint = Arrays.Clone(fingerprint);
            m_keyID = fingerprint.Length == 0 ? 0UL : KeyIdFromFingerprint(m_keyVersion, m_fingerprint);
            m_algorithm = algorithm;
            m_data = CloneData(data);
        }

        private static byte[][] CloneData(byte[][] data)
        {
            byte[][] result = new byte[data.Length][];
            for (int i = 0; i < data.Length; ++i)
            {
                result[i] = Arrays.Clone(data[i]);
            }
            return result;
        }

        /// <summary>
        /// RFC 9580 5.5.4.3: a version 6 Key ID is "the high-order 64 bits of the fingerprint",
        /// where 5.5.4.2 takes the low-order 64 bits for a version 4 one.
        /// </summary>
        private static ulong KeyIdFromFingerprint(int keyVersion, byte[] fingerprint)
        {
            if (fingerprint.Length < 8)
                return 0UL;

            return keyVersion == PublicKeyPacket.Version6
                ? Pack.BE_To_UInt64(fingerprint, 0)
                : Pack.BE_To_UInt64(fingerprint, fingerprint.Length - 8);
        }

        public int Version => m_version;

        /// <remarks>
        /// A Key ID is an 8-octet scalar. We convert it (big-endian) to an Int64 (UInt64 is not CLS compliant).
        /// </remarks>
        public long KeyId => (long)m_keyID;

        /// <summary>The version of the key named by a version 6 packet's fingerprint.</summary>
        public int KeyVersion => m_keyVersion;

        /// <summary>
        /// The recipient's fingerprint, which only a version 6 packet carries; empty for an
        /// anonymous recipient and null for a version 3 packet.
        /// </summary>
        public byte[] GetFingerprint() => Arrays.Clone(m_fingerprint);

        /// <summary>
        /// Whether the packet withholds the key it was encrypted to. RFC 9580 5.1.8 allows "a Key
        /// ID of all zeros, or an omitted key fingerprint, to hide the intended decryption key. In
        /// this case, the receiving implementation would try all available private keys" -- which
        /// costs the reader a trial decryption per key and "helps reduce traffic analysis".
        /// </summary>
        public bool IsAnonymous => m_version == Version6 ? m_fingerprint.Length == 0 : m_keyID == 0UL;

        public PublicKeyAlgorithmTag Algorithm => m_algorithm;

        public byte[][] GetEncSessionKey() => m_data;

        public override void Encode(BcpgOutputStream bcpgOut)
        {
            uint headerLength = m_version == Version6
                ? 1U + 1U + (uint)(m_fingerprint.Length == 0 ? 0 : 1 + m_fingerprint.Length) + 1U
                : 1U + 8U + 1U;

            uint bodyLength = headerLength;
            foreach (var data in m_data)
            {
                bodyLength += (uint)data.Length;
            }

            bcpgOut.WritePacketHeader(HasNewPacketFormat, PacketTag.PublicKeyEncryptedSession, bodyLength);

            byte[] header = new byte[headerLength];

            if (m_version == Version6)
            {
                header[0] = (byte)m_version;

                if (m_fingerprint.Length == 0)
                {
                    header[1] = 0;
                    header[2] = (byte)m_algorithm;
                }
                else
                {
                    header[1] = (byte)(1 + m_fingerprint.Length);
                    header[2] = (byte)m_keyVersion;
                    Array.Copy(m_fingerprint, 0, header, 3, m_fingerprint.Length);
                    header[3 + m_fingerprint.Length] = (byte)m_algorithm;
                }
            }
            else
            {
                header[0] = (byte)m_version;
                Pack.UInt64_To_BE(m_keyID, header, 1);
                header[9] = (byte)m_algorithm;
            }

            bcpgOut.Write(header, 0, header.Length);

            foreach (var data in m_data)
            {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                bcpgOut.Write(data.AsSpan());
#else
                bcpgOut.Write(data, 0, data.Length);
#endif
            }
        }
    }
}
