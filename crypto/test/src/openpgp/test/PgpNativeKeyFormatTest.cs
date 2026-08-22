using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>
    /// The four algorithms RFC 9580 gave numbers of their own -- X25519, X448, Ed25519 and Ed448 --
    /// are stated in the key packet as native octet strings rather than as the MPI-with-prefix forms
    /// their deprecated counterparts use. A key built as one of them has to come back as the same
    /// key when the packet is read again; anything else is a key whose fingerprint depends on who is
    /// looking at it, and every signature over it is then worthless.
    /// </summary>
    [TestFixture]
    public class PgpNativeKeyFormatTest
        : SimpleTest
    {
        public override string Name => "PgpNativeKeyFormatTest";

        [TestCase(PublicKeyAlgorithmTag.X25519, typeof(X25519PublicBcpgKey))]
        [TestCase(PublicKeyAlgorithmTag.X448, typeof(X448PublicBcpgKey))]
        [TestCase(PublicKeyAlgorithmTag.Ed25519, typeof(Ed25519PublicBcpgKey))]
        [TestCase(PublicKeyAlgorithmTag.Ed448, typeof(Ed448PublicBcpgKey))]
        public void ANativeKeySurvivesItsOwnEncoding(PublicKeyAlgorithmTag algorithm,
            Type expectedKeyClass)
        {
            var key = new PgpPublicKey(algorithm, GenerateKey(algorithm), DateTime.UtcNow);

            Assert.That(key.PublicKeyPacket.Key, Is.InstanceOf(expectedKeyClass),
                "the key was built in some other algorithm's format");

            var reparsed = new PgpPublicKeyRing(key.GetEncoded()).GetPublicKey();

            Assert.That(reparsed.Algorithm, Is.EqualTo(algorithm));
            Assert.That(reparsed.PublicKeyPacket.Key, Is.InstanceOf(expectedKeyClass));
            Assert.That(reparsed.GetFingerprint(), Is.EqualTo(key.GetFingerprint()),
                "the key came back as a different key");
        }

        /// <summary>
        /// The deprecated forms are still reachable, and still produce what they always did: the
        /// same curve stated as ECDH or EdDSALegacy, which is what a version 4 key from before
        /// RFC 9580 looks like.
        /// </summary>
        [TestCase(PublicKeyAlgorithmTag.ECDH, PublicKeyAlgorithmTag.X25519, typeof(ECDHPublicBcpgKey))]
        [TestCase(PublicKeyAlgorithmTag.ECDH, PublicKeyAlgorithmTag.X448, typeof(ECDHPublicBcpgKey))]
        [TestCase(PublicKeyAlgorithmTag.EdDsa_Legacy, PublicKeyAlgorithmTag.Ed25519,
            typeof(EdDsaPublicBcpgKey))]
        [TestCase(PublicKeyAlgorithmTag.EdDsa_Legacy, PublicKeyAlgorithmTag.Ed448,
            typeof(EdDsaPublicBcpgKey))]
        public void ADeprecatedFormIsStillBuiltWhenItIsAskedFor(PublicKeyAlgorithmTag algorithm,
            PublicKeyAlgorithmTag curve, Type expectedKeyClass)
        {
            var key = new PgpPublicKey(algorithm, GenerateKey(curve), DateTime.UtcNow);

            Assert.That(key.PublicKeyPacket.Key, Is.InstanceOf(expectedKeyClass));

            var reparsed = new PgpPublicKeyRing(key.GetEncoded()).GetPublicKey();

            Assert.That(reparsed.Algorithm, Is.EqualTo(algorithm));
            Assert.That(reparsed.PublicKeyPacket.Key, Is.InstanceOf(expectedKeyClass));
            Assert.That(reparsed.GetFingerprint(), Is.EqualTo(key.GetFingerprint()));
        }

        private static AsymmetricKeyParameter GenerateKey(PublicKeyAlgorithmTag algorithm)
        {
            var random = new SecureRandom();

            switch (algorithm)
            {
            case PublicKeyAlgorithmTag.X25519:
            {
                var generator = new X25519KeyPairGenerator();
                generator.Init(new X25519KeyGenerationParameters(random));
                return generator.GenerateKeyPair().Public;
            }
            case PublicKeyAlgorithmTag.X448:
            {
                var generator = new X448KeyPairGenerator();
                generator.Init(new X448KeyGenerationParameters(random));
                return generator.GenerateKeyPair().Public;
            }
            case PublicKeyAlgorithmTag.Ed25519:
            {
                var generator = new Ed25519KeyPairGenerator();
                generator.Init(new Ed25519KeyGenerationParameters(random));
                return generator.GenerateKeyPair().Public;
            }
            case PublicKeyAlgorithmTag.Ed448:
            {
                var generator = new Ed448KeyPairGenerator();
                generator.Init(new Ed448KeyGenerationParameters(random));
                return generator.GenerateKeyPair().Public;
            }
            default:
                throw new ArgumentException("no generator for " + algorithm, nameof(algorithm));
            }
        }

        public override void PerformTest()
        {
            ANativeKeySurvivesItsOwnEncoding(PublicKeyAlgorithmTag.X25519, typeof(X25519PublicBcpgKey));
            ANativeKeySurvivesItsOwnEncoding(PublicKeyAlgorithmTag.X448, typeof(X448PublicBcpgKey));
            ANativeKeySurvivesItsOwnEncoding(PublicKeyAlgorithmTag.Ed25519,
                typeof(Ed25519PublicBcpgKey));
            ANativeKeySurvivesItsOwnEncoding(PublicKeyAlgorithmTag.Ed448, typeof(Ed448PublicBcpgKey));

            ADeprecatedFormIsStillBuiltWhenItIsAskedFor(PublicKeyAlgorithmTag.ECDH,
                PublicKeyAlgorithmTag.X25519, typeof(ECDHPublicBcpgKey));
            ADeprecatedFormIsStillBuiltWhenItIsAskedFor(PublicKeyAlgorithmTag.EdDsa_Legacy,
                PublicKeyAlgorithmTag.Ed25519, typeof(EdDsaPublicBcpgKey));
        }
    }
}
