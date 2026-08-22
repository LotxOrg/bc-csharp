using System;
using System.IO;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>
    /// A certificate built entirely out of the algorithms RFC 9580 gave numbers of their own:
    /// an Ed25519 primary key that certifies and signs, and an X25519 subkey that receives mail.
    /// This is what a current implementation generates by default, so it has to work end to end --
    /// generated, written out, read back, signed with, verified, encrypted to and decrypted.
    /// </summary>
    [TestFixture]
    public class PgpNativeKeyRingTest
        : SimpleTest
    {
        public override string Name => "PgpNativeKeyRingTest";

        private static readonly char[] Passphrase = "passphrase".ToCharArray();

        [Test]
        public void ANativeKeyRingSignsVerifiesEncryptsAndDecrypts()
        {
            var random = new SecureRandom();
            var secretRing = GenerateNativeKeyRing(random);

            // Written out and read back, so that what is exercised is the secret key format on the
            // wire rather than the objects that were just built in memory.
            var reparsed = new PgpSecretKeyRing(secretRing.GetEncoded());

            PgpSecretKey primary = null, subKey = null;
            foreach (PgpSecretKey key in reparsed.GetSecretKeys())
            {
                if (key.IsMasterKey)
                {
                    primary = key;
                }
                else
                {
                    subKey = key;
                }
            }

            Assert.That(primary, Is.Not.Null);
            Assert.That(subKey, Is.Not.Null);
            Assert.That(primary.PublicKey.Algorithm, Is.EqualTo(PublicKeyAlgorithmTag.Ed25519));
            Assert.That(subKey.PublicKey.Algorithm, Is.EqualTo(PublicKeyAlgorithmTag.X25519));

            var primaryPrivate = primary.ExtractPrivateKeyUtf8(Passphrase);
            Assert.That(primaryPrivate.Key, Is.InstanceOf<Ed25519PrivateKeyParameters>());

            var subKeyPrivate = subKey.ExtractPrivateKeyUtf8(Passphrase);
            Assert.That(subKeyPrivate.Key, Is.InstanceOf<X25519PrivateKeyParameters>());

            // The self-signatures the generator made have to verify against the key that was read
            // back, which is what fails if the secret half does not match the public half.
            Assert.That(SelfSignatureVerifies(primary.PublicKey), Is.True,
                "the primary key's own user id certification does not verify");
            Assert.That(BindingVerifies(primary.PublicKey, subKey.PublicKey), Is.True,
                "the subkey binding does not verify");

            byte[] message = Encoding.UTF8.GetBytes("native all the way down");

            Assert.That(SignAndVerify(primaryPrivate, primary.PublicKey, message), Is.True,
                "a signature made with the extracted private key does not verify");

            Assert.That(Decrypt(Encrypt(subKey.PublicKey, message, random), subKeyPrivate),
                Is.EqualTo(message));
        }

        private static PgpSecretKeyRing GenerateNativeKeyRing(SecureRandom random)
        {
            var primaryGenerator = new Ed25519KeyPairGenerator();
            primaryGenerator.Init(new Ed25519KeyGenerationParameters(random));

            var primary = new PgpKeyPair(PublicKeyAlgorithmTag.Ed25519,
                primaryGenerator.GenerateKeyPair(), DateTime.UtcNow);

            var primaryPackets = new PgpSignatureSubpacketGenerator();
            primaryPackets.SetKeyFlags(true, PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign);

            var generator = new PgpKeyRingGenerator(
                PgpSignature.PositiveCertification, primary, "native@example.com",
                SymmetricKeyAlgorithmTag.Aes256, HashAlgorithmTag.Sha256,
                Strings.ToUtf8ByteArray(new string(Passphrase)), useSha1: true,
                primaryPackets.Generate(), null, random);

            var subKeyGenerator = new X25519KeyPairGenerator();
            subKeyGenerator.Init(new X25519KeyGenerationParameters(random));

            var subPackets = new PgpSignatureSubpacketGenerator();
            subPackets.SetKeyFlags(true, PgpKeyFlags.CanEncryptCommunications);

            generator.AddSubKey(
                new PgpKeyPair(PublicKeyAlgorithmTag.X25519, subKeyGenerator.GenerateKeyPair(),
                    DateTime.UtcNow),
                subPackets.Generate(), null, HashAlgorithmTag.Sha256);

            return generator.GenerateSecretKeyRing();
        }

        private static bool SelfSignatureVerifies(PgpPublicKey primary)
        {
            foreach (string userId in primary.GetUserIds())
            {
                foreach (PgpSignature signature in primary.GetSignaturesForId(userId))
                {
                    signature.InitVerify(primary);

                    if (!signature.VerifyCertification(userId, primary))
                        return false;
                }
            }

            return true;
        }

        private static bool BindingVerifies(PgpPublicKey primary, PgpPublicKey subKey)
        {
            foreach (PgpSignature signature in
                subKey.GetSignaturesOfType(PgpSignature.SubkeyBinding))
            {
                signature.InitVerify(primary);

                if (!signature.VerifyCertification(primary, subKey))
                    return false;
            }

            return true;
        }

        private static bool SignAndVerify(PgpPrivateKey privateKey, PgpPublicKey publicKey,
            byte[] message)
        {
            var generator = new PgpSignatureGenerator(
                PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.BinaryDocument, privateKey);
            generator.Update(message);

            var signature = generator.Generate();
            signature.InitVerify(publicKey);
            signature.Update(message);

            return signature.Verify();
        }

        private static byte[] Encrypt(PgpPublicKey key, byte[] message, SecureRandom random)
        {
            var generator = new PgpEncryptedDataGenerator(
                SymmetricKeyAlgorithmTag.Aes256, withIntegrityPacket: true, random);
            generator.AddMethod(key);

            using (var output = new MemoryStream())
            {
                using (var encrypted = generator.Open(output, new byte[1 << 12]))
                {
                    var literal = new PgpLiteralDataGenerator();
                    using (var plaintext = literal.Open(encrypted, PgpLiteralData.Binary, "_",
                        message.Length, DateTime.UtcNow))
                    {
                        plaintext.Write(message, 0, message.Length);
                    }
                }

                return output.ToArray();
            }
        }

        private static byte[] Decrypt(byte[] encrypted, PgpPrivateKey privateKey)
        {
            var list = (PgpEncryptedDataList)new PgpObjectFactory(encrypted).NextPgpObject();
            var forUs = (PgpPublicKeyEncryptedData)list[0];

            var literal = (PgpLiteralData)new PgpObjectFactory(forUs.GetDataStream(privateKey))
                .NextPgpObject();

            using (var recovered = new MemoryStream())
            {
                Streams.PipeAll(literal.GetInputStream(), recovered);

                return recovered.ToArray();
            }
        }

        public override void PerformTest()
        {
            ANativeKeyRingSignsVerifiesEncryptsAndDecrypts();
        }
    }
}
