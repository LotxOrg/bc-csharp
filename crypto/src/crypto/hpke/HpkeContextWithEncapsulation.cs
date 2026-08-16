using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Hpke
{
    /// <summary>A sender's HPKE context, which also carries the encapsulated key to send with it.</summary>
    public class HpkeContextWithEncapsulation
        : HpkeContext
    {
        internal readonly byte[] m_encapsulation;

        public HpkeContextWithEncapsulation(HpkeContext context, byte[] encapsulation)
            : base(context.m_aead, context.m_hkdf, context.m_exporterSecret, context.m_suiteId)
        {
            m_encapsulation = encapsulation;
        }

        public byte[] GetEncapsulation() => Arrays.Clone(m_encapsulation);
    }
}
