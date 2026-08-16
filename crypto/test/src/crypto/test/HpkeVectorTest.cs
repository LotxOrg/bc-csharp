using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Hpke;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Tests
{
    /// <summary>
    /// The X25519 test vectors of RFC 9180 appendix A, which are what say whether this port is right.
    /// </summary>
    /// <remarks>
    /// A.1 and A.2 are the two suites over DHKEM(X25519, HKDF-SHA256): AES-128-GCM and ChaCha20Poly1305.
    /// Every intermediate the appendix publishes is checked, not just the ciphertext, so a failure says
    /// which step is wrong rather than only that something is.
    /// </remarks>
    [TestFixture]
    public class HpkeVectorTest
    {
        private const string Info = "4f6465206f6e2061204772656369616e2055726e";
        private const string Plaintext = "4265617574792069732074727574682c20747275746820626561757479";

        // RFC 9180 A.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.
        private const string A1_ikmE = "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234";
        private const string A1_pkEm = "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431";
        private const string A1_skEm = "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736";
        private const string A1_ikmR = "6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037";
        private const string A1_pkRm = "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d";
        private const string A1_skRm = "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8";
        private const string A1_enc = A1_pkEm;
        private const string A1_ct0 =
            "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a";
        private const string A1_ct1 =
            "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84";
        private const string A1_export0 = "3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee";
        private const string A1_export1 = "2e8f0b54673c7029649d4eb9d5e33bf1872cf76d623ff164ac185da9e88c21a5";
        private const string A1_export2 = "e9e43065102c3836401bed8c3c3c75ae46be1639869391d62c61f1ec7af54931";

        // RFC 9180 A.2: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305.
        private const string A2_ikmE = "909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b";
        private const string A2_pkEm = "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a";
        private const string A2_skEm = "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600";
        private const string A2_ikmR = "1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df";
        private const string A2_pkRm = "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a";
        private const string A2_skRm = "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb";
        private const string A2_enc = A2_pkEm;
        private const string A2_ct0 =
            "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28";

        private static byte[] FromHex(string s) => Hex.Decode(s);

        /// <summary>
        /// The appendix publishes what DeriveKeyPair's expand step produces, which is not what
        /// SerializePrivateKey returns: RFC 9180 section 7.1.2 says that for X25519 it MUST clamp its
        /// output, clamping being the operations on k in RFC 7748 section 5. So the vector is clamped
        /// here to get the value the function is required to produce.
        /// </summary>
        private static byte[] Clamped(string s)
        {
            byte[] k = FromHex(s);
            k[0] &= 248;
            k[31] &= 127;
            k[31] |= 64;

            return k;
        }

        private static HpkeSuite Suite(short aeadId) =>
            new HpkeSuite(HpkeSuite.mode_base, HpkeSuite.kem_X25519_SHA256, HpkeSuite.kdf_HKDF_SHA256, aeadId);

        [Test]
        public void DeriveKeyPairMatchesTheVector()
        {
            var hpke = Suite(HpkeSuite.aead_AES_GCM128);

            var kpE = hpke.DeriveKeyPair(FromHex(A1_ikmE));
            Assert.AreEqual(FromHex(A1_pkEm), hpke.SerializePublicKey(kpE.Public), "A.1 ephemeral public key");
            Assert.AreEqual(Clamped(A1_skEm), hpke.SerializePrivateKey(kpE.Private), "A.1 ephemeral private key");

            var kpR = hpke.DeriveKeyPair(FromHex(A1_ikmR));
            Assert.AreEqual(FromHex(A1_pkRm), hpke.SerializePublicKey(kpR.Public), "A.1 recipient public key");
            Assert.AreEqual(Clamped(A1_skRm), hpke.SerializePrivateKey(kpR.Private), "A.1 recipient private key");
        }

        [Test]
        public void EncapsulationMatchesTheVector()
        {
            var hpke = Suite(HpkeSuite.aead_AES_GCM128);

            var kpE = hpke.DeriveKeyPair(FromHex(A1_ikmE));
            var kpR = hpke.DeriveKeyPair(FromHex(A1_ikmR));

            var ctx = hpke.SetupBaseS(kpR.Public, FromHex(Info), kpE);

            Assert.AreEqual(FromHex(A1_enc), ctx.GetEncapsulation(), "A.1 enc");
        }

        [Test]
        public void SealMatchesTheVectorAcrossTheSequence()
        {
            var hpke = Suite(HpkeSuite.aead_AES_GCM128);

            var kpE = hpke.DeriveKeyPair(FromHex(A1_ikmE));
            var kpR = hpke.DeriveKeyPair(FromHex(A1_ikmR));

            var ctx = hpke.SetupBaseS(kpR.Public, FromHex(Info), kpE);

            // Two messages, because the second is what proves the sequence number reaches the nonce.
            Assert.AreEqual(FromHex(A1_ct0), ctx.Seal(Hex.Decode("436f756e742d30"), FromHex(Plaintext)), "A.1 ct 0");
            Assert.AreEqual(FromHex(A1_ct1), ctx.Seal(Hex.Decode("436f756e742d31"), FromHex(Plaintext)), "A.1 ct 1");
        }

        [Test]
        public void OpenMatchesTheVectorAcrossTheSequence()
        {
            var hpke = Suite(HpkeSuite.aead_AES_GCM128);

            var kpR = hpke.DeriveKeyPair(FromHex(A1_ikmR));
            var ctx = hpke.SetupBaseR(FromHex(A1_enc), kpR, FromHex(Info));

            Assert.AreEqual(FromHex(Plaintext), ctx.Open(Hex.Decode("436f756e742d30"), FromHex(A1_ct0)), "A.1 pt 0");
            Assert.AreEqual(FromHex(Plaintext), ctx.Open(Hex.Decode("436f756e742d31"), FromHex(A1_ct1)), "A.1 pt 1");
        }

        [Test]
        public void ExportMatchesTheVector()
        {
            var hpke = Suite(HpkeSuite.aead_AES_GCM128);

            var kpR = hpke.DeriveKeyPair(FromHex(A1_ikmR));
            var ctx = hpke.SetupBaseR(FromHex(A1_enc), kpR, FromHex(Info));

            Assert.AreEqual(FromHex(A1_export0), ctx.Export(Array.Empty<byte>(), 32), "A.1 export, empty context");
            Assert.AreEqual(FromHex(A1_export1), ctx.Export(Hex.Decode("00"), 32), "A.1 export, context 00");
            Assert.AreEqual(FromHex(A1_export2), ctx.Export(Hex.Decode("54657374436f6e74657874"), 32),
                "A.1 export, context TestContext");
        }

        [Test]
        public void ChaCha20Poly1305MatchesTheVector()
        {
            var hpke = Suite(HpkeSuite.aead_CHACHA20_POLY1305);

            var kpE = hpke.DeriveKeyPair(FromHex(A2_ikmE));
            var kpR = hpke.DeriveKeyPair(FromHex(A2_ikmR));

            Assert.AreEqual(FromHex(A2_pkEm), hpke.SerializePublicKey(kpE.Public), "A.2 ephemeral public key");
            Assert.AreEqual(Clamped(A2_skEm), hpke.SerializePrivateKey(kpE.Private), "A.2 ephemeral private key");
            Assert.AreEqual(FromHex(A2_pkRm), hpke.SerializePublicKey(kpR.Public), "A.2 recipient public key");
            Assert.AreEqual(Clamped(A2_skRm), hpke.SerializePrivateKey(kpR.Private), "A.2 recipient private key");

            var ctx = hpke.SetupBaseS(kpR.Public, FromHex(Info), kpE);

            Assert.AreEqual(FromHex(A2_enc), ctx.GetEncapsulation(), "A.2 enc");
            Assert.AreEqual(FromHex(A2_ct0), ctx.Seal(Hex.Decode("436f756e742d30"), FromHex(Plaintext)), "A.2 ct 0");
        }

        [Test]
        public void SealAndOpenRoundTripWithAFreshKeyPair()
        {
            var hpke = Suite(HpkeSuite.aead_CHACHA20_POLY1305);

            var kpR = hpke.GeneratePrivateKey();
            byte[] message = Hex.Decode("00112233445566778899aabbccddeeff");

            byte[][] sealed_ = hpke.Seal(kpR.Public, FromHex(Info), Array.Empty<byte>(), message, null, null, null);

            byte[] opened = hpke.Open(sealed_[1], kpR, FromHex(Info), Array.Empty<byte>(), sealed_[0], null, null,
                null);

            Assert.AreEqual(message, opened);
        }

        [Test]
        public void OpeningWithTheWrongPrivateKeyIsRefused()
        {
            var hpke = Suite(HpkeSuite.aead_CHACHA20_POLY1305);

            var kpR = hpke.GeneratePrivateKey();
            var wrong = hpke.GeneratePrivateKey();
            byte[] message = Hex.Decode("00112233445566778899aabbccddeeff");

            byte[][] sealed_ = hpke.Seal(kpR.Public, FromHex(Info), Array.Empty<byte>(), message, null, null, null);

            // The AEAD tag is what says the key is wrong, rather than returning rubbish.
            Assert.Throws<InvalidCipherTextException>(() =>
                hpke.Open(sealed_[1], wrong, FromHex(Info), Array.Empty<byte>(), sealed_[0], null, null, null));
        }

        [Test]
        public void PostQuantumKemIdsAreRefusedRatherThanIgnored()
        {
            // Not ported: their drafts are not final and nothing here asks for them.
            Assert.Throws<ArgumentException>(() =>
                new HpkeSuite(HpkeSuite.mode_base, 0x0041, HpkeSuite.kdf_HKDF_SHA256, HpkeSuite.aead_CHACHA20_POLY1305));
        }
    }
}
