using System;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Hpke
{
    /// <summary>
    /// Hybrid Public Key Encryption, RFC 9180.
    /// </summary>
    /// <remarks>
    /// Ported from bc-java, which upstream bc-csharp has not taken yet. Delete this in favour of theirs
    /// when it arrives. The ML-KEM and X-Wing KEMs of that package are not here -- they are drafts, and
    /// nothing in this tree asks for them -- so those KEM ids are refused rather than silently ignored.
    /// </remarks>
    public class HpkeSuite
    {
        public const byte mode_base = 0x00;
        public const byte mode_psk = 0x01;
        public const byte mode_auth = 0x02;
        public const byte mode_auth_psk = 0x03;

        public const short kem_P256_SHA256 = 16;
        public const short kem_P384_SHA384 = 17;
        public const short kem_P521_SHA512 = 18;
        public const short kem_X25519_SHA256 = 32;
        public const short kem_X448_SHA512 = 33;

        public const short kdf_HKDF_SHA256 = 0x0001;
        public const short kdf_HKDF_SHA384 = 0x0002;
        public const short kdf_HKDF_SHA512 = 0x0003;

        public const short aead_AES_GCM128 = 0x0001;
        public const short aead_AES_GCM256 = 0x0002;
        public const short aead_CHACHA20_POLY1305 = 0x0003;
        public const short aead_EXPORT_ONLY = unchecked((short)0xFFFF);

        private static readonly byte[] DefaultPsk = null;
        private static readonly byte[] DefaultPskId = null;

        private readonly byte m_mode;
        private readonly short m_kemId;
        private readonly short m_kdfId;
        private readonly short m_aeadId;
        private readonly HpkeKem m_kem;
        private readonly HpkeHkdf m_hkdf;
        private readonly int m_encSize;
        private readonly short m_Nk;

        public HpkeSuite(byte mode, short kemId, short kdfId, short aeadId)
            : this(mode, kemId, kdfId, aeadId, CreateKem(kemId), 0)
        {
            m_encSize = m_kem.EncryptionSize;
        }

        public HpkeSuite(byte mode, short kemId, short kdfId, short aeadId, HpkeKem kem, int encSize)
        {
            m_mode = mode;
            m_kemId = kemId;
            m_kdfId = kdfId;
            m_aeadId = aeadId;
            m_hkdf = new HpkeHkdf(kdfId);
            m_kem = kem;
            m_Nk = aeadId == aead_AES_GCM128 ? (short)16 : (short)32;
            m_encSize = encSize;
        }

        public int EncSize => m_encSize;

        public short AeadId => m_aeadId;

        private static HpkeKem CreateKem(short kemId)
        {
            switch (kemId)
            {
            case kem_P256_SHA256:
            case kem_P384_SHA384:
            case kem_P521_SHA512:
            case kem_X25519_SHA256:
            case kem_X448_SHA512:
                return new HpkeDHKem(kemId);
            default:
                throw new ArgumentException("invalid kem id", nameof(kemId));
            }
        }

        public AsymmetricCipherKeyPair GeneratePrivateKey() => m_kem.GeneratePrivateKey();

        public byte[] SerializePublicKey(AsymmetricKeyParameter pk) => m_kem.SerializePublicKey(pk);

        public byte[] SerializePrivateKey(AsymmetricKeyParameter sk) => m_kem.SerializePrivateKey(sk);

        public AsymmetricKeyParameter DeserializePublicKey(byte[] pkEncoded) =>
            m_kem.DeserializePublicKey(pkEncoded);

        public AsymmetricCipherKeyPair DeserializePrivateKey(byte[] skEncoded, byte[] pkEncoded) =>
            m_kem.DeserializePrivateKey(skEncoded, pkEncoded);

        public AsymmetricCipherKeyPair DeriveKeyPair(byte[] ikm) => m_kem.DeriveKeyPair(ikm);

        /// <returns>The ciphertext and the encapsulated key, in that order.</returns>
        public byte[][] Seal(AsymmetricKeyParameter pkR, byte[] info, byte[] aad, byte[] pt, byte[] psk,
            byte[] pskId, AsymmetricCipherKeyPair skS)
        {
            HpkeContextWithEncapsulation ctx = SetupSender(pkR, info, psk, pskId, skS);

            return new byte[][] { ctx.Seal(aad, pt), ctx.GetEncapsulation() };
        }

        public byte[] Open(byte[] enc, AsymmetricCipherKeyPair skR, byte[] info, byte[] aad, byte[] ct,
            byte[] psk, byte[] pskId, AsymmetricKeyParameter pkS)
        {
            return SetupReceiver(enc, skR, info, psk, pskId, pkS).Open(aad, ct);
        }

        /// <returns>The encapsulated key and the exported secret, in that order.</returns>
        public byte[][] SendExport(AsymmetricKeyParameter pkR, byte[] info, byte[] exporterContext, int L,
            byte[] psk, byte[] pskId, AsymmetricCipherKeyPair skS)
        {
            HpkeContextWithEncapsulation ctx = SetupSender(pkR, info, psk, pskId, skS);

            return new byte[][] { ctx.GetEncapsulation(), ctx.Export(exporterContext, L) };
        }

        public byte[] ReceiveExport(byte[] enc, AsymmetricCipherKeyPair skR, byte[] info, byte[] exporterContext,
            int L, byte[] psk, byte[] pskId, AsymmetricKeyParameter pkS)
        {
            return SetupReceiver(enc, skR, info, psk, pskId, pkS).Export(exporterContext, L);
        }

        public HpkeContextWithEncapsulation SetupBaseS(AsymmetricKeyParameter pkR, byte[] info)
        {
            byte[][] output = m_kem.Encap(pkR);

            return new HpkeContextWithEncapsulation(
                KeySchedule(mode_base, output[0], info, DefaultPsk, DefaultPskId), output[1]);
        }

        public HpkeContextWithEncapsulation SetupBaseS(AsymmetricKeyParameter pkR, byte[] info,
            AsymmetricCipherKeyPair kpE)
        {
            byte[][] output = m_kem.Encap(pkR, kpE);

            return new HpkeContextWithEncapsulation(
                KeySchedule(mode_base, output[0], info, DefaultPsk, DefaultPskId), output[1]);
        }

        public HpkeContext SetupBaseR(byte[] enc, AsymmetricCipherKeyPair skR, byte[] info)
        {
            byte[] sharedSecret = m_kem.Decap(enc, skR);

            return KeySchedule(mode_base, sharedSecret, info, DefaultPsk, DefaultPskId);
        }

        public HpkeContextWithEncapsulation SetupPskS(AsymmetricKeyParameter pkR, byte[] info, byte[] psk,
            byte[] pskId)
        {
            byte[][] output = m_kem.Encap(pkR);

            return new HpkeContextWithEncapsulation(KeySchedule(mode_psk, output[0], info, psk, pskId), output[1]);
        }

        public HpkeContext SetupPskR(byte[] enc, AsymmetricCipherKeyPair skR, byte[] info, byte[] psk, byte[] pskId)
        {
            byte[] sharedSecret = m_kem.Decap(enc, skR);

            return KeySchedule(mode_psk, sharedSecret, info, psk, pskId);
        }

        public HpkeContextWithEncapsulation SetupAuthS(AsymmetricKeyParameter pkR, byte[] info,
            AsymmetricCipherKeyPair skS)
        {
            byte[][] output = m_kem.AuthEncap(pkR, skS);

            return new HpkeContextWithEncapsulation(
                KeySchedule(mode_auth, output[0], info, DefaultPsk, DefaultPskId), output[1]);
        }

        public HpkeContext SetupAuthR(byte[] enc, AsymmetricCipherKeyPair skR, byte[] info,
            AsymmetricKeyParameter pkS)
        {
            byte[] sharedSecret = m_kem.AuthDecap(enc, skR, pkS);

            return KeySchedule(mode_auth, sharedSecret, info, DefaultPsk, DefaultPskId);
        }

        public HpkeContextWithEncapsulation SetupAuthPskS(AsymmetricKeyParameter pkR, byte[] info, byte[] psk,
            byte[] pskId, AsymmetricCipherKeyPair skS)
        {
            byte[][] output = m_kem.AuthEncap(pkR, skS);

            return new HpkeContextWithEncapsulation(KeySchedule(mode_auth_psk, output[0], info, psk, pskId),
                output[1]);
        }

        public HpkeContext SetupAuthPskR(byte[] enc, AsymmetricCipherKeyPair skR, byte[] info, byte[] psk,
            byte[] pskId, AsymmetricKeyParameter pkS)
        {
            byte[] sharedSecret = m_kem.AuthDecap(enc, skR, pkS);

            return KeySchedule(mode_auth_psk, sharedSecret, info, psk, pskId);
        }

        private HpkeContextWithEncapsulation SetupSender(AsymmetricKeyParameter pkR, byte[] info, byte[] psk,
            byte[] pskId, AsymmetricCipherKeyPair skS)
        {
            switch (m_mode)
            {
            case mode_base:
                return SetupBaseS(pkR, info);
            case mode_auth:
                return SetupAuthS(pkR, info, skS);
            case mode_psk:
                return SetupPskS(pkR, info, psk, pskId);
            case mode_auth_psk:
                return SetupAuthPskS(pkR, info, psk, pskId, skS);
            default:
                throw new InvalidOperationException("Unknown mode");
            }
        }

        private HpkeContext SetupReceiver(byte[] enc, AsymmetricCipherKeyPair skR, byte[] info, byte[] psk,
            byte[] pskId, AsymmetricKeyParameter pkS)
        {
            switch (m_mode)
            {
            case mode_base:
                return SetupBaseR(enc, skR, info);
            case mode_auth:
                return SetupAuthR(enc, skR, info, pkS);
            case mode_psk:
                return SetupPskR(enc, skR, info, psk, pskId);
            case mode_auth_psk:
                return SetupAuthPskR(enc, skR, info, psk, pskId, pkS);
            default:
                throw new InvalidOperationException("Unknown mode");
            }
        }

        private void VerifyPskInputs(byte mode, byte[] psk, byte[] pskId)
        {
            bool gotPsk = !Arrays.AreEqual(psk, DefaultPsk);
            bool gotPskId = !Arrays.AreEqual(pskId, DefaultPskId);

            if (gotPsk != gotPskId)
                throw new ArgumentException("Inconsistent PSK inputs");
            if (gotPsk && (mode % 2 == 0))
                throw new ArgumentException("PSK input provided when not needed");
            if (!gotPsk && (mode % 2 == 1))
                throw new ArgumentException("Missing required PSK input");
        }

        private HpkeContext KeySchedule(byte mode, byte[] sharedSecret, byte[] info, byte[] psk, byte[] pskId)
        {
            VerifyPskInputs(mode, psk, pskId);

            byte[] ids = new byte[6];
            Pack.UInt16_To_BE((ushort)m_kemId, ids, 0);
            Pack.UInt16_To_BE((ushort)m_kdfId, ids, 2);
            Pack.UInt16_To_BE((ushort)m_aeadId, ids, 4);

            byte[] suiteId = Arrays.Concatenate(Strings.ToByteArray("HPKE"), ids);

            byte[] pskIdHash = m_hkdf.LabeledExtract(null, suiteId, "psk_id_hash", pskId);
            byte[] infoHash = m_hkdf.LabeledExtract(null, suiteId, "info_hash", info);
            byte[] keyScheduleContext = Arrays.ConcatenateAll(new byte[]{ mode }, pskIdHash, infoHash);

            byte[] secret = m_hkdf.LabeledExtract(sharedSecret, suiteId, "secret", psk);
            byte[] key = m_hkdf.LabeledExpand(secret, suiteId, "key", keyScheduleContext, m_Nk);
            byte[] baseNonce = m_hkdf.LabeledExpand(secret, suiteId, "base_nonce", keyScheduleContext, 12);
            byte[] exporterSecret = m_hkdf.LabeledExpand(secret, suiteId, "exp", keyScheduleContext,
                m_hkdf.HashSize);

            return new HpkeContext(new HpkeAead(m_aeadId, key, baseNonce), m_hkdf, exporterSecret, suiteId);
        }
    }
}
