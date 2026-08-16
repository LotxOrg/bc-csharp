using System;

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Hpke
{
    /// <summary>The AEAD of RFC 9180 section 5.2, with the sequence-number nonce it defines.</summary>
    public sealed class HpkeAead
    {
        private readonly short m_aeadId;
        private readonly byte[] m_key;
        private readonly byte[] m_baseNonce;
        private readonly IAeadCipher m_cipher;
        private ulong m_seq;

        public HpkeAead(short aeadId, byte[] key, byte[] baseNonce)
        {
            m_aeadId = aeadId;
            m_key = key;
            m_baseNonce = baseNonce;
            m_seq = 0UL;

            switch (aeadId)
            {
            case HpkeSuite.aead_AES_GCM128:
            case HpkeSuite.aead_AES_GCM256:
                m_cipher = new GcmBlockCipher(AesUtilities.CreateEngine());
                break;
            case HpkeSuite.aead_CHACHA20_POLY1305:
                m_cipher = new ChaCha20Poly1305();
                break;
            case HpkeSuite.aead_EXPORT_ONLY:
                m_cipher = null;
                break;
            default:
                throw new ArgumentException("invalid aead id", nameof(aeadId));
            }
        }

        public byte[] Seal(byte[] aad, byte[] pt) => Process(true, aad, pt, 0, pt.Length);

        public byte[] Seal(byte[] aad, byte[] pt, int ptOffset, int ptLength)
        {
            Arrays.ValidateSegment(pt, ptOffset, ptLength);
            return Process(true, aad, pt, ptOffset, ptLength);
        }

        public byte[] Open(byte[] aad, byte[] ct) => Process(false, aad, ct, 0, ct.Length);

        public byte[] Open(byte[] aad, byte[] ct, int ctOffset, int ctLength)
        {
            Arrays.ValidateSegment(ct, ctOffset, ctLength);
            return Process(false, aad, ct, ctOffset, ctLength);
        }

        private byte[] ComputeNonce()
        {
            byte[] seqBytes = new byte[8];
            Pack.UInt64_To_BE(m_seq, seqBytes);

            byte[] nonce = Arrays.Clone(m_baseNonce);
            Bytes.XorTo(8, seqBytes, 0, nonce, nonce.Length - 8);

            return nonce;
        }

        private void IncrementSeq()
        {
            if (m_seq == ulong.MaxValue)
                throw new InvalidOperationException("HPKE message limit reached");

            m_seq++;
        }

        private byte[] Process(bool forEncryption, byte[] aad, byte[] buf, int off, int len)
        {
            if (m_aeadId == HpkeSuite.aead_EXPORT_ONLY)
                throw new InvalidOperationException("Export only mode, cannot be used to seal/open");

            ICipherParameters parameters = new ParametersWithIV(new KeyParameter(m_key), ComputeNonce());

            m_cipher.Init(forEncryption, parameters);
            m_cipher.ProcessAadBytes(aad, 0, aad.Length);

            byte[] output = new byte[m_cipher.GetOutputSize(len)];
            int pos = m_cipher.ProcessBytes(buf, off, len, output, 0);
            pos += m_cipher.DoFinal(output, pos);

            if (pos != output.Length)
                throw new InvalidOperationException();

            IncrementSeq();

            return output;
        }
    }
}
