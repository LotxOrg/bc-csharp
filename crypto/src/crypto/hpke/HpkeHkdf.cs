using System;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Hpke
{
    /// <summary>The labeled KDF of RFC 9180 section 4.</summary>
    internal sealed class HpkeHkdf
    {
        private static readonly byte[] VersionLabel = Strings.ToByteArray("HPKE-v1");

        private readonly HkdfBytesGenerator m_kdf;
        private readonly IDigest m_hash;

        internal HpkeHkdf(short kdfId)
        {
            switch (kdfId)
            {
            case HpkeSuite.kdf_HKDF_SHA256:
                m_hash = new Sha256Digest();
                break;
            case HpkeSuite.kdf_HKDF_SHA384:
                m_hash = new Sha384Digest();
                break;
            case HpkeSuite.kdf_HKDF_SHA512:
                m_hash = new Sha512Digest();
                break;
            default:
                throw new ArgumentException("invalid kdf id", nameof(kdfId));
            }

            m_kdf = new HkdfBytesGenerator(m_hash);
        }

        internal int HashSize => m_hash.GetDigestSize();

        internal byte[] LabeledExtract(byte[] salt, byte[] suiteID, string label, byte[] ikm)
        {
            byte[] labeledIkm = Arrays.ConcatenateAll(VersionLabel, suiteID, Strings.ToByteArray(label), ikm);

            return Extract(salt, labeledIkm);
        }

        internal byte[] LabeledExpand(byte[] prk, byte[] suiteID, string label, byte[] info, int L)
        {
            if (L > (1 << 16))
                throw new ArgumentException("Expand length cannot be larger than 2^16", nameof(L));

            byte[] lengthPrefix = new byte[2];
            Pack.UInt16_To_BE((ushort)L, lengthPrefix);

            byte[] labeledInfo = Arrays.ConcatenateAll(lengthPrefix, VersionLabel, suiteID, Strings.ToByteArray(label));

            return Expand(prk, Arrays.ConcatenateAll(labeledInfo, info), L);
        }

        /// <summary>
        /// HKDF-Extract of RFC 5869 section 2.2, which is HMAC keyed with the salt over the input keying
        /// material. Done here rather than through HkdfBytesGenerator, whose own extract step is private.
        /// </summary>
        internal byte[] Extract(byte[] salt, byte[] ikm)
        {
            if (salt == null)
            {
                salt = new byte[HashSize];
            }

            var hmac = new HMac(m_hash);
            hmac.Init(new KeyParameter(salt));

            if (ikm != null)
            {
                hmac.BlockUpdate(ikm, 0, ikm.Length);
            }

            byte[] prk = new byte[hmac.GetMacSize()];
            hmac.DoFinal(prk, 0);

            return prk;
        }

        internal byte[] Expand(byte[] prk, byte[] info, int L)
        {
            if (L > (1 << 16))
                throw new ArgumentException("Expand length cannot be larger than 2^16", nameof(L));

            m_kdf.Init(HkdfParameters.SkipExtractParameters(prk, info ?? Array.Empty<byte>()));

            byte[] rv = new byte[L];
            m_kdf.GenerateBytes(rv, 0, rv.Length);

            return rv;
        }
    }
}
