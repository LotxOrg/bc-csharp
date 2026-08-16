namespace Org.BouncyCastle.Crypto.Hpke
{
    /// <summary>An established HPKE context, per RFC 9180 section 5.1.</summary>
    public class HpkeContext
    {
        internal readonly HpkeAead m_aead;
        internal readonly HpkeHkdf m_hkdf;
        internal readonly byte[] m_exporterSecret;
        internal readonly byte[] m_suiteId;

        internal HpkeContext(HpkeAead aead, HpkeHkdf hkdf, byte[] exporterSecret, byte[] suiteId)
        {
            m_aead = aead;
            m_hkdf = hkdf;
            m_exporterSecret = exporterSecret;
            m_suiteId = suiteId;
        }

        public byte[] Export(byte[] exportContext, int L) =>
            m_hkdf.LabeledExpand(m_exporterSecret, m_suiteId, "sec", exportContext, L);

        public byte[] Seal(byte[] aad, byte[] message) => m_aead.Seal(aad, message);

        public byte[] Seal(byte[] aad, byte[] pt, int ptOffset, int ptLength) =>
            m_aead.Seal(aad, pt, ptOffset, ptLength);

        public byte[] Open(byte[] aad, byte[] ct) => m_aead.Open(aad, ct);

        public byte[] Open(byte[] aad, byte[] ct, int ctOffset, int ctLength) =>
            m_aead.Open(aad, ct, ctOffset, ctLength);

        public byte[] Extract(byte[] salt, byte[] ikm) => m_hkdf.Extract(salt, ikm);

        public byte[] Expand(byte[] prk, byte[] info, int L) => m_hkdf.Expand(prk, info, L);
    }
}
