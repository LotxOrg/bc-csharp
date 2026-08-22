using System;
using System.IO;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>
    /// The X25519 and X448 public key algorithms of RFC 9580, which that document introduced as
    /// algorithms of their own (25 and 26) rather than as curves carried by ECDH.
    /// </summary>
    [TestFixture]
    public class PgpX25519Test
        : SimpleTest
    {
        public override string Name => "PgpX25519Test";

        /// <summary>
        /// RFC 9580 A.8.2, which gives every input and the derived key, so this checks the
        /// derivation itself rather than only that encrypting and decrypting agree with each other.
        /// </summary>
        [Test]
        public void KeyDerivationMatchesTheRfcVector()
        {
            byte[] ephemeralPublicKey = Hex.Decode(
                "87cf18d5f1b53f817cce5a004cf393cc8958bddc065f25f84af509b17dd36764");
            byte[] recipientPublicKey = Hex.Decode(
                "8693248367f9e5015db922f8f48095dda784987f2d5985b12fbad16caf5e4435");
            byte[] sharedSecret = Hex.Decode(
                "67e30e69cdc7bab2a2680d78aca46a2f8b6e2ae44d398bdc6f92c5ad4a492514");
            byte[] expected = Hex.Decode("f66dadcff64592239b254539b64ff607");

            var key = Rfc9580Utilities.CreateKey(PublicKeyAlgorithmTag.X25519, ephemeralPublicKey,
                recipientPublicKey, sharedSecret);

            IsTrue("HKDF output does not match RFC 9580 A.8.2",
                Arrays.AreEqual(expected, key.GetKey()));
        }

        [Test]
        public void X25519MessageRoundTrips()
        {
            CheckRoundTrip(PublicKeyAlgorithmTag.X25519, SymmetricKeyAlgorithmTag.Aes256);
        }

        [Test]
        public void X448MessageRoundTrips()
        {
            CheckRoundTrip(PublicKeyAlgorithmTag.X448, SymmetricKeyAlgorithmTag.Aes256);
        }

        [Test]
        public void X25519MessageRoundTripsWithAes128()
        {
            CheckRoundTrip(PublicKeyAlgorithmTag.X25519, SymmetricKeyAlgorithmTag.Aes128);
        }

        /// <summary>
        /// RFC 9580 5.1.6: in a v3 PKESK packet the symmetric algorithm identifier travels beside
        /// the wrapped key rather than inside it, and "the symmetric algorithm used MUST be
        /// AES-128, AES-192, or AES-256".
        /// </summary>
        [Test]
        public void ASessionKeyAlgorithmOtherThanAesIsRefused()
        {
            var keyPair = GenerateKeyPair(PublicKeyAlgorithmTag.X25519, out _);

            var generator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5,
                withIntegrityPacket: true, new SecureRandom());
            generator.AddMethod(keyPair);

            var exception = Assert.Throws<PgpException>(() =>
            {
                using (var output = new MemoryStream())
                {
                    generator.Open(output, new byte[16]).Dispose();
                }
            });

            // The generator wraps whatever the method throws, so the reason is the inner exception.
            Assert.That(exception.InnerException, Is.InstanceOf<PgpException>());
            Assert.That(exception.InnerException.Message, Does.Contain("AES-128"));
        }

        private void CheckRoundTrip(PublicKeyAlgorithmTag algorithm,
            SymmetricKeyAlgorithmTag sessionKeyAlgorithm)
        {
            byte[] message = Encoding.UTF8.GetBytes("the quick brown fox");

            var publicKey = GenerateKeyPair(algorithm, out var privateKeyParameters);
            var privateKey = new PgpPrivateKey(publicKey.KeyId, publicKey.PublicKeyPacket,
                privateKeyParameters);

            byte[] encrypted = Encrypt(publicKey, sessionKeyAlgorithm, message);

            var objects = new PgpObjectFactory(encrypted);
            var encryptedData = (PgpEncryptedDataList)objects.NextPgpObject();
            var forUs = (PgpPublicKeyEncryptedData)encryptedData[0];

            IsEquals("wrong key id", publicKey.KeyId, forUs.KeyId);
            IsEquals("wrong session key algorithm", sessionKeyAlgorithm,
                forUs.GetSymmetricAlgorithm(privateKey));

            var literal = (PgpLiteralData)new PgpObjectFactory(forUs.GetDataStream(privateKey))
                .NextPgpObject();

            using (var recovered = new MemoryStream())
            {
                Streams.PipeAll(literal.GetInputStream(), recovered);

                IsTrue("message did not survive the round trip",
                    Arrays.AreEqual(message, recovered.ToArray()));
            }
        }

        private static byte[] Encrypt(PgpPublicKey publicKey,
            SymmetricKeyAlgorithmTag sessionKeyAlgorithm, byte[] message)
        {
            var generator = new PgpEncryptedDataGenerator(sessionKeyAlgorithm,
                withIntegrityPacket: true, new SecureRandom());
            generator.AddMethod(publicKey);

            using (var output = new MemoryStream())
            {
                using (var encryptedOut = generator.Open(output, new byte[1 << 12]))
                {
                    var literal = new PgpLiteralDataGenerator();
                    using (var literalOut = literal.Open(encryptedOut, PgpLiteralData.Binary, "_",
                        message.Length, DateTime.UtcNow))
                    {
                        literalOut.Write(message, 0, message.Length);
                    }
                }

                return output.ToArray();
            }
        }

        private static PgpPublicKey GenerateKeyPair(PublicKeyAlgorithmTag algorithm,
            out AsymmetricKeyParameter privateKey)
        {
            var random = new SecureRandom();

            if (algorithm == PublicKeyAlgorithmTag.X25519)
            {
                var generator = new X25519KeyPairGenerator();
                generator.Init(new X25519KeyGenerationParameters(random));
                var pair = generator.GenerateKeyPair();
                privateKey = pair.Private;

                return new PgpPublicKey(algorithm, pair.Public, DateTime.UtcNow);
            }
            else
            {
                var generator = new X448KeyPairGenerator();
                generator.Init(new X448KeyGenerationParameters(random));
                var pair = generator.GenerateKeyPair();
                privateKey = pair.Private;

                return new PgpPublicKey(algorithm, pair.Public, DateTime.UtcNow);
            }
        }

        public override void PerformTest()
        {
            KeyDerivationMatchesTheRfcVector();
            X25519MessageRoundTrips();
            X448MessageRoundTrips();
            X25519MessageRoundTripsWithAes128();
            ASessionKeyAlgorithmOtherThanAesIsRefused();
        }
    }
}
