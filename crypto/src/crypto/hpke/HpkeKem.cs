using System;

namespace Org.BouncyCastle.Crypto.Hpke
{
    /// <summary>A Key Encapsulation Mechanism, per RFC 9180 section 4.</summary>
    public abstract class HpkeKem
    {
        internal abstract AsymmetricCipherKeyPair GeneratePrivateKey();

        internal abstract AsymmetricCipherKeyPair DeriveKeyPair(byte[] ikm);

        /// <returns>The shared secret and the encapsulated key, in that order.</returns>
        internal abstract byte[][] Encap(AsymmetricKeyParameter recipientPublicKey);

        /// <returns>The shared secret and the encapsulated key, in that order.</returns>
        internal abstract byte[][] Encap(AsymmetricKeyParameter pkR, AsymmetricCipherKeyPair kpE);

        internal abstract byte[][] AuthEncap(AsymmetricKeyParameter pkR, AsymmetricCipherKeyPair kpS);

        internal virtual byte[][] Encap(AsymmetricKeyParameter pkR, byte[] ier)
        {
            throw new NotSupportedException("KEM does not support encapsulation from raw randomness");
        }

        internal abstract byte[] Decap(byte[] encapsulatedKey, AsymmetricCipherKeyPair recipientKeyPair);

        internal abstract byte[] AuthDecap(byte[] enc, AsymmetricCipherKeyPair kpR, AsymmetricKeyParameter pkS);

        internal abstract byte[] SerializePublicKey(AsymmetricKeyParameter publicKey);

        internal abstract byte[] SerializePrivateKey(AsymmetricKeyParameter key);

        internal abstract AsymmetricKeyParameter DeserializePublicKey(byte[] encodedPublicKey);

        internal abstract AsymmetricCipherKeyPair DeserializePrivateKey(byte[] skEncoded, byte[] pkEncoded);

        internal abstract int EncryptionSize { get; }
    }
}
