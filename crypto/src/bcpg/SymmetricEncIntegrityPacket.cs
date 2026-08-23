using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    public class SymmetricEncIntegrityPacket
        : InputStreamPacket
    {
        /// <summary>Version 1 SEIPD packet.</summary>
        /// <remarks>
        /// Used only with <see cref="SymmetricKeyEncSessionPacket.Version4"/> or
        /// <see cref="PublicKeyEncSessionPacket.Version3"/>.
        /// </remarks>
        public const int Version1 = 1;

        /// <summary>Version 2 SEIPD packet.</summary>
        /// <remarks>
        /// Used only with <see cref="SymmetricKeyEncSessionPacket.Version6"/> or
        /// <see cref="PublicKeyEncSessionPacket.Version6"/>.
        /// </remarks>
        public const int Version2 = 2;

        /// <summary>The length of a v2 packet's salt, in octets. RFC 9580 5.13.2 fixes it at 32.</summary>
        public const int SaltLength = 32;

        /// <summary>
        /// The largest chunk size octet a v2 packet may carry. RFC 9580 5.13.2: "An implementation
        /// MUST accept chunk size octets with values from 0 to 16. An implementation MUST NOT create
        /// data with a chunk size octet value larger than 16 (4 MiB chunks)."
        /// </summary>
        public const int MaxChunkSizeOctet = 16;

        public static SymmetricEncIntegrityPacket CreateV1Packet() => new SymmetricEncIntegrityPacket();

        public static SymmetricEncIntegrityPacket CreateV2Packet(SymmetricKeyAlgorithmTag cipherAlgorithm,
            AeadAlgorithmTag aeadAlgorithm, int chunkSize, byte[] salt)
        {
            return new SymmetricEncIntegrityPacket(cipherAlgorithm, aeadAlgorithm, chunkSize, salt);
        }

        private readonly int m_version;
        private readonly SymmetricKeyAlgorithmTag m_cipherAlgorithm;
        private readonly AeadAlgorithmTag m_aeadAlgorithm;
        private readonly int m_chunkSize;
        private readonly byte[] m_salt;

        internal SymmetricEncIntegrityPacket(BcpgInputStream bcpgIn)
            : this(bcpgIn, newPacketFormat: false)
        {
        }

        internal SymmetricEncIntegrityPacket(BcpgInputStream bcpgIn, bool newPacketFormat)
            : base(bcpgIn, PacketTag.SymmetricEncryptedIntegrityProtected, newPacketFormat)
        {
            m_version = bcpgIn.RequireByte();

            switch (m_version)
            {
            case Version1:
                break;

            case Version2:
                m_cipherAlgorithm = (SymmetricKeyAlgorithmTag)bcpgIn.RequireByte();
                m_aeadAlgorithm = (AeadAlgorithmTag)bcpgIn.RequireByte();
                m_chunkSize = bcpgIn.RequireByte();

                if (m_chunkSize > MaxChunkSizeOctet)
                    throw new MalformedPacketException("chunkSize out of range");

                m_salt = new byte[SaltLength];
                bcpgIn.ReadFully(m_salt);
                break;

            default:
                throw new UnsupportedPacketVersionException("Unknown SEIPD packet version: " + m_version);
            }
        }

        private SymmetricEncIntegrityPacket()
            : base(bcpgIn: null, PacketTag.SymmetricEncryptedIntegrityProtected)
        {
            m_version = Version1;
        }

        private SymmetricEncIntegrityPacket(SymmetricKeyAlgorithmTag cipherAlgorithm,
            AeadAlgorithmTag aeadAlgorithm, int chunkSize, byte[] salt)
            : base(bcpgIn: null, PacketTag.SymmetricEncryptedIntegrityProtected)
        {
            if (chunkSize < 0 || chunkSize > MaxChunkSizeOctet)
                throw new ArgumentOutOfRangeException(nameof(chunkSize));
            if (salt == null)
                throw new ArgumentNullException(nameof(salt));
            if (salt.Length != SaltLength)
                throw new ArgumentException("salt must be " + SaltLength + " octets", nameof(salt));

            m_version = Version2;
            m_cipherAlgorithm = cipherAlgorithm;
            m_aeadAlgorithm = aeadAlgorithm;
            m_chunkSize = chunkSize;
            m_salt = Arrays.Clone(salt);
        }

        public int Version => m_version;

        /// <summary>The symmetric cipher, which only a v2 packet names.</summary>
        public SymmetricKeyAlgorithmTag CipherAlgorithm => m_cipherAlgorithm;

        /// <summary>The AEAD mode, which only a v2 packet names.</summary>
        public AeadAlgorithmTag AeadAlgorithm => m_aeadAlgorithm;

        /// <summary>The chunk size octet; the chunk holds <c>1 &lt;&lt; (ChunkSize + 6)</c> octets.</summary>
        public int ChunkSize => m_chunkSize;

        public byte[] GetSalt() => Arrays.Clone(m_salt);

        internal byte[] Salt => m_salt;

        /// <summary>
        /// The additional data every chunk of this packet is authenticated under, and the prefix of
        /// the final tag's additional data. It is also the HKDF info parameter.
        /// </summary>
        public byte[] GetAAData() => CreateAAData(m_version, m_cipherAlgorithm, m_aeadAlgorithm, m_chunkSize);

        /// <summary>
        /// RFC 9580 5.13.2: "the Packet Type ID in OpenPGP format encoding (bits 7 and 6 are set, and
        /// bits 5-0 carry the Packet Type ID), version number, cipher algorithm ID, AEAD algorithm ID,
        /// and chunk size octet".
        /// </summary>
        public static byte[] CreateAAData(int version, SymmetricKeyAlgorithmTag cipherAlgorithm,
            AeadAlgorithmTag aeadAlgorithm, int chunkSize)
        {
            return new byte[5]
            {
                (byte)PacketTag.SymmetricEncryptedIntegrityProtected | 0xC0,
                (byte)version,
                (byte)cipherAlgorithm,
                (byte)aeadAlgorithm,
                (byte)chunkSize,
            };
        }
    }
}
