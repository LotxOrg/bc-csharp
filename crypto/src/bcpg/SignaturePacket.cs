using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Date;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Generic signature packet.</remarks>
    public class SignaturePacket
        : ContainedPacket
    {
        public const int Version2 = 2;
        public const int Version3 = 3;
        public const int Version4 = 4;  // https://datatracker.ietf.org/doc/rfc4880/
        public const int Version5 = 5;  // https://datatracker.ietf.org/doc/draft-koch-librepgp/
        public const int Version6 = 6;  // https://www.rfc-editor.org/rfc/rfc9580.html

        private int version;
        private int signatureType;
        private long m_creationTime;
        private ulong m_keyID;
        private PublicKeyAlgorithmTag keyAlgorithm;
        private HashAlgorithmTag hashAlgorithm;
        private MPInteger[] signature;
        private byte[] fingerprint;
        private SignatureSubpacket[] hashedData;
        private SignatureSubpacket[] unhashedData;
        private byte[] signatureEncoding;
        private byte[] m_salt = null; // v6 only
        private IssuerFingerprint m_issuerFingerprint = null;

        internal SignaturePacket(BcpgInputStream bcpgIn)
            : this(bcpgIn, newPacketFormat: false)
        {
        }

        internal SignaturePacket(BcpgInputStream bcpgIn, bool newPacketFormat)
            : base(PacketTag.Signature, newPacketFormat)
        {
            version = bcpgIn.RequireByte();

            if (version == 3 || version == 2)
            {
                //int l =
                bcpgIn.RequireByte();

                signatureType = bcpgIn.RequireByte();
                m_creationTime = (long)StreamUtilities.RequireUInt32BE(bcpgIn) * 1000L;
                m_keyID = StreamUtilities.RequireUInt64BE(bcpgIn);
                keyAlgorithm = (PublicKeyAlgorithmTag)bcpgIn.RequireByte();
                hashAlgorithm = (HashAlgorithmTag)bcpgIn.RequireByte();
            }
            else if (version == 4 || version == Version6)
            {
                signatureType = bcpgIn.RequireByte();
                keyAlgorithm = (PublicKeyAlgorithmTag)bcpgIn.RequireByte();
                hashAlgorithm = (HashAlgorithmTag)bcpgIn.RequireByte();

                // ReadSignatureSubpackets already reads the four-octet area
                // length a version 6 signature uses in place of two.
                hashedData = ReadSignatureSubpackets(bcpgIn);

                foreach (var p in hashedData)
                {
                    if (p is IssuerKeyId issuerKeyId)
                    {
                        m_keyID = ParseKeyIdOrThrow(issuerKeyId);
                    }
                    else if (p is SignatureCreationTime signatureCreationTime)
                    {
                        m_creationTime = ParseCreationTimeOrThrow(signatureCreationTime);
                    }
                    else if (p is IssuerFingerprint issuerFingerprint)
                    {
                        // A version 6 signature carries no Issuer Key ID: RFC
                        // 9580 replaces it with the Issuer Fingerprint, and the
                        // key ID is the leading eight octets of that.
                        m_issuerFingerprint = issuerFingerprint;
                    }
                }

                unhashedData = ReadSignatureSubpackets(bcpgIn);

                foreach (var p in unhashedData)
                {
                    if (p is IssuerKeyId issuerKeyId)
                    {
                        m_keyID = ParseKeyIdOrThrow(issuerKeyId);
                    }
                    else if (p is IssuerFingerprint issuerFingerprint && m_issuerFingerprint == null)
                    {
                        m_issuerFingerprint = issuerFingerprint;
                    }
                }

                SetIssuerKeyId();
                SetCreationTime();
            }
            else
            {
                Streams.Drain(bcpgIn);

                throw new UnsupportedPacketVersionException("unsupported version: " + version);
            }

            fingerprint = new byte[2];
            bcpgIn.ReadFully(fingerprint);

            if (version == Version6)
            {
                // RFC 9580 5.2.3: a one-octet salt size, then the salt.
                int saltSize = bcpgIn.RequireByte();
                m_salt = new byte[saltSize];
                bcpgIn.ReadFully(m_salt);
            }

            switch (keyAlgorithm)
            {
            case PublicKeyAlgorithmTag.RsaGeneral:
            case PublicKeyAlgorithmTag.RsaSign:
                MPInteger v = new MPInteger(bcpgIn);
                signature = new MPInteger[1]{ v };
                break;
            case PublicKeyAlgorithmTag.Dsa:
            case PublicKeyAlgorithmTag.ElGamalEncrypt: // yep, this really does happen sometimes.
            case PublicKeyAlgorithmTag.ElGamalGeneral:
                MPInteger r = new MPInteger(bcpgIn);
                MPInteger s = new MPInteger(bcpgIn);
                signature = new MPInteger[2]{ r, s };
                break;
            case PublicKeyAlgorithmTag.ECDsa:
            case PublicKeyAlgorithmTag.EdDsa_Legacy:
                MPInteger ecR = new MPInteger(bcpgIn);
                MPInteger ecS = new MPInteger(bcpgIn);
                signature = new MPInteger[2]{ ecR, ecS };
                break;
            case PublicKeyAlgorithmTag.Ed25519:
                // RFC 9580 5.2.3.4: 64 octets of the native signature, not MPIs.
                signature = null;
                signatureEncoding = new byte[Ed25519.SignatureSize];
                bcpgIn.ReadFully(signatureEncoding);
                break;
            case PublicKeyAlgorithmTag.Ed448:
                // RFC 9580 5.2.3.5: 114 octets of the native signature.
                signature = null;
                signatureEncoding = new byte[Ed448.SignatureSize];
                bcpgIn.ReadFully(signatureEncoding);
                break;
            default:
                if (keyAlgorithm < PublicKeyAlgorithmTag.Experimental_1 ||
                    keyAlgorithm > PublicKeyAlgorithmTag.Experimental_11)
                {
                    throw new IOException("unknown signature key algorithm: " + keyAlgorithm);
                }

                signature = null;
                signatureEncoding = Streams.ReadAll(bcpgIn);
                break;
            }
        }

        /**
         * Generate a version 4 signature packet.
         *
         * @param signatureType
         * @param keyAlgorithm
         * @param hashAlgorithm
         * @param hashedData
         * @param unhashedData
         * @param fingerprint
         * @param signature
         */
        public SignaturePacket(int signatureType, long keyId, PublicKeyAlgorithmTag keyAlgorithm,
            HashAlgorithmTag hashAlgorithm, SignatureSubpacket[] hashedData, SignatureSubpacket[] unhashedData,
            byte[] fingerprint, MPInteger[] signature)
            : this(Version4, signatureType, keyId, keyAlgorithm, hashAlgorithm, hashedData, unhashedData, fingerprint,
                signature)
        {
        }

        /**
         * Generate a version 2/3 signature packet.
         *
         * @param signatureType
         * @param keyAlgorithm
         * @param hashAlgorithm
         * @param fingerprint
         * @param signature
         */
        public SignaturePacket(int version, int signatureType, long keyId, PublicKeyAlgorithmTag keyAlgorithm,
            HashAlgorithmTag hashAlgorithm, long creationTime, byte[] fingerprint, MPInteger[] signature)
            : this(version, signatureType, keyId, keyAlgorithm, hashAlgorithm, null, null, fingerprint, signature)
        {
            m_creationTime = creationTime;
        }

        public SignaturePacket(int version, int signatureType, long keyId, PublicKeyAlgorithmTag keyAlgorithm,
            HashAlgorithmTag hashAlgorithm, SignatureSubpacket[] hashedData, SignatureSubpacket[] unhashedData,
            byte[] fingerprint, MPInteger[] signature)
            : this(version, newPacketFormat: false, signatureType, keyId, keyAlgorithm, hashAlgorithm, hashedData,
                unhashedData, fingerprint, signature)
        {
        }

        public SignaturePacket(int version, bool newPacketFormat, int signatureType, long keyId,
            PublicKeyAlgorithmTag keyAlgorithm, HashAlgorithmTag hashAlgorithm, SignatureSubpacket[] hashedData,
            SignatureSubpacket[] unhashedData, byte[] fingerprint, MPInteger[] signature)
            : base(PacketTag.Signature, newPacketFormat)
        {
            this.version = version;
            this.signatureType = signatureType;
            m_keyID = (ulong)keyId;
            this.keyAlgorithm = keyAlgorithm;
            this.hashAlgorithm = hashAlgorithm;
            this.hashedData = hashedData;
            this.unhashedData = unhashedData;
            this.fingerprint = fingerprint;
            this.signature = signature;

            if (hashedData != null)
            {
                SetCreationTime();
            }
        }

        /// <summary>
        /// A signature whose algorithm-specific part is a native octet string rather than MPIs.
        /// </summary>
        /// <remarks>
        /// RFC 9580 5.2.3.3 and 5.2.3.4 give Ed25519 and Ed448 signatures "64 octets of the native
        /// signature" and "114 octets of the native signature" -- not the pair of MPIs the
        /// deprecated EdDSALegacy form uses.
        /// </remarks>
        public SignaturePacket(int version, bool newPacketFormat, int signatureType, long keyId,
            PublicKeyAlgorithmTag keyAlgorithm, HashAlgorithmTag hashAlgorithm, SignatureSubpacket[] hashedData,
            SignatureSubpacket[] unhashedData, byte[] fingerprint, byte[] signatureEncoding)
            : base(PacketTag.Signature, newPacketFormat)
        {
            this.version = version;
            this.signatureType = signatureType;
            m_keyID = (ulong)keyId;
            this.keyAlgorithm = keyAlgorithm;
            this.hashAlgorithm = hashAlgorithm;
            this.hashedData = hashedData;
            this.unhashedData = unhashedData;
            this.fingerprint = fingerprint;
            this.signatureEncoding = Arrays.Clone(signatureEncoding);

            if (hashedData != null)
            {
                SetCreationTime();
            }
        }

        public int Version => version;

        public int SignatureType => signatureType;

        /// <summary>Returns the key ID that created the signature.</summary>
        /// <remarks>
        /// A Key ID is an 8-octet scalar. We convert it (big-endian) to an Int64 (UInt64 is not CLS compliant).
        /// </remarks>
        public long KeyId => (long)m_keyID;

        /**
         * Return the signatures fingerprint.
         * @return fingerprint (digest prefix) of the signature
         */
        public byte[] GetFingerprint() => Arrays.Clone(fingerprint);


        /**
         * Return the signature's salt.
         * Only for v6 signatures.
         * @return salt
         */
        public byte[] GetSalt() => m_salt;

        /**
         * return the signature trailer that must be included with the data
         * to reconstruct the signature
         *
         * @return byte[]
         */
        public byte[] GetSignatureTrailer()
        {
            if (version == 3)
            {
                long time = m_creationTime / 1000L;

                byte[] trailer = new byte[5];
                trailer[0] = (byte)signatureType;
                Pack.UInt32_To_BE((uint)time, trailer, 1);
                return trailer;
            }

            MemoryStream sOut = new MemoryStream();

            sOut.WriteByte((byte)Version);
            sOut.WriteByte((byte)SignatureType);
            sOut.WriteByte((byte)KeyAlgorithm);
            sOut.WriteByte((byte)HashAlgorithm);

            // Mark position and reserve space for the length: four octets for a
            // version 6 signature, two for a version 4 one.
            bool isV6 = version == Version6;
            int lengthSize = isV6 ? 4 : 2;
            long lengthPosition = sOut.Position;
            for (int i = 0; i < lengthSize; ++i)
            {
                sOut.WriteByte(0x00);
            }

            SignatureSubpacket[] hashed = GetHashedSubPackets();
            for (int i = 0; i != hashed.Length; i++)
            {
                hashed[i].Encode(sOut);
            }

            uint dataLength = Convert.ToUInt32(sOut.Position - lengthPosition - lengthSize);
            uint hDataLength = Convert.ToUInt32(sOut.Position);

            sOut.WriteByte((byte)Version);
            sOut.WriteByte(0xFF);
            StreamUtilities.WriteUInt32BE(sOut, hDataLength);

            // Reset position and fill in length
            sOut.Position = lengthPosition;
            if (isV6)
            {
                StreamUtilities.WriteUInt32BE(sOut, dataLength);
            }
            else
            {
                StreamUtilities.WriteUInt16BE(sOut, Convert.ToUInt16(dataLength));
            }

            return sOut.ToArray();
        }

        public PublicKeyAlgorithmTag KeyAlgorithm => keyAlgorithm;

        public HashAlgorithmTag HashAlgorithm => hashAlgorithm;

        /**
         * return the signature as a set of integers - note this is normalised to be the
         * ASN.1 encoding of what appears in the signature packet.
         */
        public MPInteger[] GetSignature() => signature;

        /**
         * Return the byte encoding of the signature section.
         * @return uninterpreted signature bytes.
         */
        public byte[] GetSignatureBytes()
        {
            if (signatureEncoding != null)
                return Arrays.Clone(signatureEncoding);

            MemoryStream bOut = new MemoryStream();

            using (var pOut = new BcpgOutputStream(bOut))
            {
                foreach (MPInteger sigObj in signature)
                {
                    try
                    {
                        sigObj.Encode(pOut);
                    }
                    catch (IOException e)
                    {
                        throw new Exception("internal error: " + e);
                    }
                }
            }

            return bOut.ToArray();
        }

        // TODO[api] Ideally '..Subpackets'
        public SignatureSubpacket[] GetHashedSubPackets() => hashedData;

        // TODO[api] Ideally '..Subpackets'
        public SignatureSubpacket[] GetUnhashedSubPackets() => unhashedData;

        /// <summary>Return the creation time in milliseconds since 1 Jan., 1970 UTC.</summary>
        public long CreationTime => m_creationTime;

        public override void Encode(BcpgOutputStream bcpgOut)
        {
            MemoryStream bOut = new MemoryStream();
            using (var pOut = new BcpgOutputStream(bOut))
            {
                pOut.WriteByte((byte)version);

                if (version == Version3 || version == Version2)
                {
                    byte nextBlockLength = 5;
                    pOut.Write(nextBlockLength, (byte)signatureType);
                    StreamUtilities.WriteUInt32BE(pOut, (uint)(m_creationTime / 1000L));
                    StreamUtilities.WriteUInt64BE(pOut, m_keyID);
                    pOut.Write((byte)keyAlgorithm, (byte)hashAlgorithm);
                }
                else if (version == Version4 || version == Version5 || version == Version6)
                {
                    pOut.Write((byte)signatureType, (byte)keyAlgorithm, (byte)hashAlgorithm);
                    EncodeLengthAndData(pOut, GetEncodedSubpackets(hashedData), version);
                    EncodeLengthAndData(pOut, GetEncodedSubpackets(unhashedData), version);
                }
                else
                {
                    throw new IOException("unknown version: " + version);
                }

                pOut.Write(fingerprint);

                if (version == Version6)
                {
                    pOut.WriteByte((byte)m_salt.Length);
                    pOut.Write(m_salt);
                }

                if (signature != null)
                {
                    pOut.WriteObjects(signature);
                }
                else
                {
                    pOut.Write(signatureEncoding);
                }
            }

            bcpgOut.WritePacket(HasNewPacketFormat, PacketTag.Signature, bOut.ToArray());
        }

        private static ulong ParseKeyIdOrThrow(IssuerKeyId issuerKeyId)
        {
            try
            {
                return (ulong)issuerKeyId.GetKeyID();
            }
            catch (ArgumentException e)
            {
                throw new MalformedPacketException("Malformed IssuerKeyID subpacket.", e);
            }
        }

        private static ulong ParseKeyIdOrThrow(IssuerFingerprint issuerFingerprint)
        {
            try
            {
                return (ulong)issuerFingerprint.GetKeyID();
            }
            catch (ArgumentException e)
            {
                throw new MalformedPacketException("Malformed IssuerFingerprint subpacket.", e);
            }
        }

        private static long ParseCreationTimeOrThrow(SignatureCreationTime signatureCreationTime)
        {
            try
            {
                return DateTimeUtilities.DateTimeToUnixMs(signatureCreationTime.GetTime());
            }
            catch (Exception e)
            {
                throw new MalformedPacketException("Malformed SignatureCreationTime subpacket.", e);
            }
        }

        private SignatureSubpacket[] ReadSignatureSubpackets(BcpgInputStream bcpgIn)
        {
            uint hashedLength;
            if (version == 6)
            {
                hashedLength = StreamUtilities.RequireUInt32BE(bcpgIn);
            }
            else
            {
                hashedLength = StreamUtilities.RequireUInt16BE(bcpgIn);
            }

            // TODO[pgp] Are we really intending to apply the individual limit to the whole list?
            if (hashedLength > SignatureSubpacketsParser.MaxSubpacketLength)
                throw new MalformedPacketException(
                    $"Signature subpackets encoding length ({hashedLength}) exceeds max limit ({SignatureSubpacketsParser.MaxSubpacketLength})");

            byte[] hashed = new byte[hashedLength];
            bcpgIn.ReadFully(hashed);

            SignatureSubpacketsParser sIn = new SignatureSubpacketsParser(new MemoryStream(hashed, false));

            var result = new List<SignatureSubpacket>();
            SignatureSubpacket sub;
            while ((sub = sIn.ReadPacket()) != null)
            {
                result.Add(sub);
            }
            return result.ToArray();
        }

        private static void EncodeLengthAndData(BcpgOutputStream pOut, byte[] data, int version)
        {
            // Version 6 counts its subpacket areas in four octets, where
            // version 4 uses two.
            if (version == Version6)
            {
                StreamUtilities.WriteUInt32BE(pOut, (uint)data.Length);
            }
            else
            {
                StreamUtilities.WriteUInt16BE(pOut, (ushort)data.Length);
            }

            pOut.Write(data);
        }

        private static byte[] GetEncodedSubpackets(SignatureSubpacket[] ps)
        {
            MemoryStream sOut = new MemoryStream();

            foreach (SignatureSubpacket p in ps)
            {
                p.Encode(sOut);
            }

            return sOut.ToArray();
        }

        private void SetCreationTime()
        {
            foreach (SignatureSubpacket p in hashedData)
            {
                if (p is SignatureCreationTime signatureCreationTime)
                {
                    m_creationTime = DateTimeUtilities.DateTimeToUnixMs(signatureCreationTime.GetTime());
                    break;
                }
            }
        }

        /**
         * Iterate over the hashed and unhashed signature subpackets to identify either a {@link IssuerKeyID} or
         * {@link IssuerFingerprint} subpacket to derive the issuer key-ID from.
         * The issuer {@link IssuerKeyID} and {@link IssuerFingerprint} subpacket information is "self-authenticating",
         * as its authenticity can be verified by checking the signature with the corresponding key.
         * Therefore, we can also check the unhashed signature subpacket area.
         */
        private void SetIssuerKeyId()
        {
            if (m_keyID != 0L)
                return;

            // RFC 9580: a version 6 signature has no Issuer Key ID subpacket.
            // Its issuer is named by fingerprint, and the key ID is derived
            // from that.
            if (m_issuerFingerprint != null)
            {
                m_keyID = (ulong)m_issuerFingerprint.GetKeyID();
                if (m_keyID != 0L)
                    return;
            }

            for (int idx = 0; idx != hashedData.Length; idx++)
            {
                SignatureSubpacket p = hashedData[idx];

                if (p is IssuerKeyId issuerKeyId)
                {
                    m_keyID = ParseKeyIdOrThrow(issuerKeyId);
                    return;
                }

                if (p is IssuerFingerprint issuerFingerprint)
                {
                    m_keyID = ParseKeyIdOrThrow(issuerFingerprint);
                    return;
                }
            }

            for (int idx = 0; idx != unhashedData.Length; idx++)
            {
                SignatureSubpacket p = unhashedData[idx];

                if (p is IssuerKeyId issuerKeyId)
                {
                    m_keyID = ParseKeyIdOrThrow(issuerKeyId);
                    return;
                }

                if (p is IssuerFingerprint issuerFingerprint)
                {
                    m_keyID = ParseKeyIdOrThrow(issuerFingerprint);
                    return;
                }
            }
        }

        public static SignaturePacket FromByteArray(byte[] data)
        {
            BcpgInputStream input = BcpgInputStream.Wrap(new MemoryStream(data, writable: false));

            return new SignaturePacket(input);
        }
    }
}
