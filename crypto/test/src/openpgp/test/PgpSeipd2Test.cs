using System;
using System.IO;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>
    /// The version 6 PKESK and version 2 SEIPD packets of RFC 9580: a session key named by
    /// fingerprint rather than by Key ID, and a body encrypted in independently authenticated
    /// chunks under a real AEAD mode rather than in CFB with a SHA-1 modification detection code.
    /// </summary>
    [TestFixture]
    public class PgpSeipd2Test
    {
        /// <summary>RFC 9580 A.4, the sample version 6 transferable secret key.</summary>
        private const string SampleV6SecretKey =
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "\n" +
            "xUsGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laMAGXKB\n" +
            "exK+cH6NX1hs5hNhIB00TrJmosgv3mg1ditlsLfCsQYfGwoAAABCBYJjh3/jAwsJ\n" +
            "BwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n" +
            "2azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lwgyU2kCcUmKfvBXbAf6rh\n" +
            "RYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaEQsiPlR4zxP/TP7mhfVEe\n" +
            "7XWPxtnMUMtf15OyA51YBMdLBmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/\n" +
            "LVmFsS+60WyvXkQ1AE1gCk95TUR3XFeibg/u/tVY6a//1q0NWC1X+yui3O24wpsG\n" +
            "GBsKAAAALAWCY4d/4wKbDCIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n" +
            "2azJAAAAAAQBIKbpGG2dWTX8j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDE\n" +
            "M0g12vYxoWM8Y81W+bHBw805I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUr\n" +
            "k0mXubZvyl4GBg==\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";

        /// <summary>
        /// RFC 9580 A.8.5, the complete X25519-AEAD-OCB encrypted packet sequence: "Hello, world!"
        /// encrypted to the sample certificate with AES-128 in OCB mode.
        /// </summary>
        private const string SampleX25519OcbMessage =
            "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "wV0GIQYSyD8ecG9jCP4VGkF3Q6HwM3kOk+mXhIjR2zeNqZMIhRmHzxjV8bU/gXzO\n" +
            "WgBM85PMiVi93AZfJfhK9QmxfdNnZBjeo1VDeVZheQHgaVf7yopqR6W1FT6NOrfS\n" +
            "aQIHAgZhZBZTW+CwcW1g4FKlbExAf56zaw76/prQoN+bAzxpohup69LA7JW/Vp0l\n" +
            "yZnuSj3hcFj0DfqLTGgr4/u717J+sPWbtQBfgMfG9AOIwwrUBqsFE9zW+f1zdlYo\n" +
            "bhF30A+IitsxxA==\n" +
            "-----END PGP MESSAGE-----\n";

        private const string ExpectedPlaintext = "Hello, world!";

        /// <summary>
        /// The whole of RFC 9580 A.8 end to end. Nothing here is our own output, so it checks the
        /// derivation, the nonces, the additional data and the chunking against the document rather
        /// than against ourselves.
        /// </summary>
        [Test]
        public void DecryptsTheRfcX25519OcbVector()
        {
            var encryptedData = FirstPublicKeyEncryptedData(SampleX25519OcbMessage,
                out PgpEncryptedDataList encList);

            Assert.AreEqual(PublicKeyEncSessionPacket.Version6, VersionOf(encList),
                "the sample carries a v6 PKESK packet");
            Assert.IsTrue(encryptedData.IsIntegrityProtected());

            var privateKey = FindPrivateKey(SampleV6SecretKey, encryptedData.KeyId);

            Assert.AreEqual(SymmetricKeyAlgorithmTag.Aes128, encryptedData.GetSymmetricAlgorithm(privateKey),
                "A.8.3 names AES-128, and a v6 PKESK takes it from the SEIPD packet");

            using (var decrypted = encryptedData.GetDataStream(privateKey))
            {
                Assert.AreEqual(ExpectedPlaintext, ReadLiteralData(decrypted));
            }
        }

        /// <summary>
        /// The tag closing the packet covers the total plaintext length, so a ciphertext cut short
        /// has to be refused rather than read as a shorter message.
        /// </summary>
        /// <remarks>
        /// The packet is re-framed to declare its shorter length, so that what is being tested is
        /// the authentication rather than the packet parser noticing it ran out of octets.
        /// </remarks>
        [Test]
        public void RefusesATruncatedMessage()
        {
            byte[] message = Decode(SampleX25519OcbMessage);

            // A.8.3: the SEIPD packet is "d2 69 ...", a one-octet tag and a one-octet length.
            int seipd = message.Length - (2 + 0x69);
            Assert.AreEqual(0xD2, message[seipd], "expected the SEIPD packet where A.8.5 puts it");
            Assert.AreEqual(0x69, message[seipd + 1]);

            const int Dropped = 16;

            byte[] truncated = Arrays.CopyOfRange(message, 0, message.Length - Dropped);
            truncated[seipd + 1] = (byte)(0x69 - Dropped);

            var encryptedData = FirstPublicKeyEncryptedData(truncated, out _);
            var privateKey = FindPrivateKey(SampleV6SecretKey, encryptedData.KeyId);

            Assert.Throws(Is.InstanceOf<PgpException>(), () =>
            {
                using (var decrypted = encryptedData.GetDataStream(privateKey))
                {
                    Streams.Drain(decrypted);
                }
            });
        }

        /// <summary>A single flipped octet of ciphertext must fail its chunk's tag.</summary>
        [Test]
        public void RefusesATamperedMessage()
        {
            byte[] message = Decode(SampleX25519OcbMessage);

            // 0x26 into the SEIPD packet body is the first octet of chunk #0 (A.8.3); the packet
            // itself starts after the PKESK, so just disturb something well inside the ciphertext.
            message[message.Length - 40] ^= 0x01;

            var encryptedData = FirstPublicKeyEncryptedData(message, out _);
            var privateKey = FindPrivateKey(SampleV6SecretKey, encryptedData.KeyId);

            Assert.Throws(Is.InstanceOf<PgpException>(), () =>
            {
                using (var decrypted = encryptedData.GetDataStream(privateKey))
                {
                    Streams.Drain(decrypted);
                }
            });
        }

        /// <summary>
        /// Every AEAD mode RFC 9580 defines, since each has its own nonce length and the nonce is
        /// where the chunk index goes.
        /// </summary>
        [Test]
        public void RoundTripsThroughEveryAeadMode()
        {
            foreach (AeadAlgorithmTag aead in new[]{
                AeadAlgorithmTag.Eax, AeadAlgorithmTag.Ocb, AeadAlgorithmTag.Gcm })
            {
                RoundTrip(aead, chunkSizeOctet: 6, plaintextLength: 13);
            }
        }

        /// <summary>
        /// A chunk size octet of 0 gives 64-octet chunks, so this crosses several of them and ends
        /// on a partial one -- which is where a mistake in the chunk index or in the lookahead that
        /// tells the last chunk from the final tag would show.
        /// </summary>
        [Test]
        public void RoundTripsDataSpanningManyChunks()
        {
            RoundTrip(AeadAlgorithmTag.Ocb, chunkSizeOctet: 0, plaintextLength: 64 * 5 + 7);
        }

        /// <summary>
        /// The awkward case: the plaintext ends exactly on a chunk boundary, so the final tag
        /// follows a full chunk with nothing between them.
        /// </summary>
        [Test]
        public void RoundTripsDataThatExactlyFillsItsChunks()
        {
            RoundTrip(AeadAlgorithmTag.Gcm, chunkSizeOctet: 0, plaintextLength: 64 * 3);
        }

        /// <summary>No chunks at all, and the final tag attesting to a length of zero.</summary>
        [Test]
        public void RoundTripsAnEmptyPlaintext()
        {
            RoundTrip(AeadAlgorithmTag.Ocb, chunkSizeOctet: 0, plaintextLength: 0);
        }

        /// <summary>
        /// An anonymous packet names no key at all, so nothing in the stored message says whose it
        /// is -- which is the point of RFC 9580 5.1.8.
        /// </summary>
        [Test]
        public void RoundTripsAnAnonymousRecipient()
        {
            PgpPublicKey encryptionKey = EncryptionKeyOf(SampleV6SecretKey);

            byte[] content = Encoding.UTF8.GetBytes(ExpectedPlaintext);
            byte[] message = Encrypt(encryptionKey, content, AeadAlgorithmTag.Ocb, chunkSizeOctet: 6,
                anonymous: true);

            var encryptedData = FirstPublicKeyEncryptedData(message, out _);

            Assert.AreEqual(PublicKeyEncSessionPacket.Version6, encryptedData.Version);
            Assert.IsTrue(encryptedData.IsAnonymous, "the packet should withhold its recipient");
            Assert.AreEqual(0L, encryptedData.KeyId, "an anonymous packet names no key");

            // The fingerprint is not merely zeroed but absent, so the packet is shorter than a
            // named one by the whole of it.
            byte[] named = Encrypt(encryptionKey, content, AeadAlgorithmTag.Ocb, chunkSizeOctet: 6,
                anonymous: false);
            Assert.AreEqual(named.Length - (1 + 32), message.Length,
                "an anonymous v6 packet drops the key version octet and the 32-octet fingerprint");

            var privateKey = FindPrivateKey(SampleV6SecretKey, encryptionKey.KeyId);

            using (var decrypted = encryptedData.TryGetDataStream(privateKey))
            {
                Assert.IsNotNull(decrypted);

                var factory = new PgpObjectFactory(decrypted);
                var literal = (PgpLiteralData)factory.NextPgpObject();

                using (var input = literal.GetInputStream())
                {
                    Assert.AreEqual(ExpectedPlaintext, Encoding.UTF8.GetString(Streams.ReadAll(input)));
                }
            }
        }

        /// <summary>
        /// The reader has no choice but to try the keys it holds. Keys that do not fit must answer
        /// null rather than throw, and must not consume the packet, or working through a set of
        /// them would not be possible on one object.
        /// </summary>
        [Test]
        public void TriesKeysUntilOneFitsAnAnonymousRecipient()
        {
            PgpPublicKey encryptionKey = EncryptionKeyOf(SampleV6SecretKey);

            byte[] content = Encoding.UTF8.GetBytes(ExpectedPlaintext);
            byte[] message = Encrypt(encryptionKey, content, AeadAlgorithmTag.Ocb, chunkSizeOctet: 6,
                anonymous: true);

            var encryptedData = FirstPublicKeyEncryptedData(message, out _);

            // Several keys of the same algorithm that are simply not the one.
            for (int i = 0; i < 3; ++i)
            {
                Assert.IsNull(encryptedData.TryGetDataStream(MakeX25519KeyPair().PrivateKey),
                    "a key that is not the one should answer null");
            }

            var privateKey = FindPrivateKey(SampleV6SecretKey, encryptionKey.KeyId);

            using (var decrypted = encryptedData.TryGetDataStream(privateKey))
            {
                Assert.IsNotNull(decrypted, "the packet must survive the failed attempts");

                var factory = new PgpObjectFactory(decrypted);
                var literal = (PgpLiteralData)factory.NextPgpObject();

                using (var input = literal.GetInputStream())
                {
                    Assert.AreEqual(ExpectedPlaintext, Encoding.UTF8.GetString(Streams.ReadAll(input)));
                }
            }
        }

        /// <summary>A named packet answers null for the wrong key too, so callers need one path.</summary>
        [Test]
        public void AnswersNullForTheWrongKeyOnANamedRecipient()
        {
            PgpPublicKey encryptionKey = EncryptionKeyOf(SampleV6SecretKey);

            byte[] message = Encrypt(encryptionKey, Encoding.UTF8.GetBytes(ExpectedPlaintext),
                AeadAlgorithmTag.Ocb, chunkSizeOctet: 6);

            var encryptedData = FirstPublicKeyEncryptedData(message, out _);

            Assert.IsFalse(encryptedData.IsAnonymous);
            Assert.IsNull(encryptedData.TryGetDataStream(MakeX25519KeyPair().PrivateKey));
            Assert.IsNotNull(encryptedData.TryGetDataStream(
                FindPrivateKey(SampleV6SecretKey, encryptionKey.KeyId)));
        }

        private static PgpKeyPair MakeX25519KeyPair()
        {
            var generator = new X25519KeyPairGenerator();
            generator.Init(new X25519KeyGenerationParameters(new SecureRandom()));

            return new PgpKeyPair(PublicKeyAlgorithmTag.X25519, generator.GenerateKeyPair(), DateTime.UtcNow);
        }

        private void RoundTrip(AeadAlgorithmTag aeadAlgorithm, int chunkSizeOctet, int plaintextLength)
        {
            string what = aeadAlgorithm + ", chunk octet " + chunkSizeOctet + ", " + plaintextLength + " octets";

            byte[] content = new byte[plaintextLength];
            for (int i = 0; i < content.Length; ++i)
            {
                content[i] = (byte)i;
            }

            PgpPublicKey encryptionKey = EncryptionKeyOf(SampleV6SecretKey);

            byte[] message = Encrypt(encryptionKey, content, aeadAlgorithm, chunkSizeOctet);

            var encryptedData = FirstPublicKeyEncryptedData(message, out _);

            Assert.AreEqual(PublicKeyEncSessionPacket.Version6, encryptedData.Version, what);
            Assert.AreEqual(encryptionKey.KeyId, encryptedData.KeyId, what);

            var privateKey = FindPrivateKey(SampleV6SecretKey, encryptedData.KeyId);

            Assert.AreEqual(SymmetricKeyAlgorithmTag.Aes128, encryptedData.GetSymmetricAlgorithm(privateKey), what);

            using (var decrypted = encryptedData.GetDataStream(privateKey))
            {
                var factory = new PgpObjectFactory(decrypted);
                var literal = (PgpLiteralData)factory.NextPgpObject();

                byte[] recovered;
                using (var input = literal.GetInputStream())
                {
                    recovered = Streams.ReadAll(input);
                }

                Assert.IsTrue(Arrays.AreEqual(content, recovered), what);
                Assert.IsTrue(encryptedData.Verify(), what);
            }
        }

        private static byte[] Encrypt(PgpPublicKey encryptionKey, byte[] content,
            AeadAlgorithmTag aeadAlgorithm, int chunkSizeOctet)
        {
            return Encrypt(encryptionKey, content, aeadAlgorithm, chunkSizeOctet, anonymous: false);
        }

        private static byte[] Encrypt(PgpPublicKey encryptionKey, byte[] content,
            AeadAlgorithmTag aeadAlgorithm, int chunkSizeOctet, bool anonymous)
        {
            byte[] literal = MakeLiteralData(content);

            var generator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes128, aeadAlgorithm,
                chunkSizeOctet, new SecureRandom());

            if (anonymous)
            {
                generator.AddAnonymousMethod(encryptionKey);
            }
            else
            {
                generator.AddMethod(encryptionKey);
            }

            var bOut = new MemoryStream();
            using (var encOut = generator.Open(bOut, literal.Length))
            {
                encOut.Write(literal, 0, literal.Length);
            }

            return bOut.ToArray();
        }

        private static byte[] MakeLiteralData(byte[] content)
        {
            var bOut = new MemoryStream();
            var generator = new PgpLiteralDataGenerator();

            using (var lOut = generator.Open(bOut, PgpLiteralData.Binary, PgpLiteralData.Console, content.Length,
                DateTime.UtcNow))
            {
                lOut.Write(content, 0, content.Length);
            }

            return bOut.ToArray();
        }

        private static PgpPublicKey EncryptionKeyOf(string armoredSecretKey)
        {
            using (var decoderStream = PgpUtilities.GetDecoderStream(
                new MemoryStream(Encoding.ASCII.GetBytes(armoredSecretKey), false)))
            {
                var bundle = new PgpSecretKeyRingBundle(decoderStream);

                foreach (PgpSecretKeyRing ring in bundle.GetKeyRings())
                {
                    foreach (PgpPublicKey key in ring.GetPublicKeys())
                    {
                        if (key.IsEncryptionKey)
                            return key;
                    }
                }
            }

            throw new InvalidOperationException("no encryption key in the sample");
        }

        private static int VersionOf(PgpEncryptedDataList encList)
        {
            // The list keeps the packets it was built from; the version is what distinguishes the
            // two shapes, so read it back off the data object.
            var data = (PgpPublicKeyEncryptedData)encList[0];
            return data.Version;
        }

        private static byte[] Decode(string armored)
        {
            using (var armoredIn = new ArmoredInputStream(
                new MemoryStream(Encoding.ASCII.GetBytes(armored), false)))
            {
                return Streams.ReadAll(armoredIn);
            }
        }

        private static PgpPublicKeyEncryptedData FirstPublicKeyEncryptedData(string armored,
            out PgpEncryptedDataList encList)
        {
            return FirstPublicKeyEncryptedData(Decode(armored), out encList);
        }

        private static PgpPublicKeyEncryptedData FirstPublicKeyEncryptedData(byte[] message,
            out PgpEncryptedDataList encList)
        {
            var factory = new PgpObjectFactory(new MemoryStream(message, false));
            encList = (PgpEncryptedDataList)factory.NextPgpObject();
            return (PgpPublicKeyEncryptedData)encList[0];
        }

        private static PgpPrivateKey FindPrivateKey(string armoredSecretKey, long keyId)
        {
            using (var decoderStream = PgpUtilities.GetDecoderStream(
                new MemoryStream(Encoding.ASCII.GetBytes(armoredSecretKey), false)))
            {
                var bundle = new PgpSecretKeyRingBundle(decoderStream);

                PgpSecretKey secretKey = bundle.GetSecretKey(keyId)
                    ?? throw new InvalidOperationException("no secret key for " + keyId.ToString("X16"));

                return secretKey.ExtractPrivateKey(null);
            }
        }

        private static string ReadLiteralData(Stream decrypted)
        {
            var factory = new PgpObjectFactory(decrypted);

            var literal = (PgpLiteralData)factory.NextPgpObject();

            using (var input = literal.GetInputStream())
            {
                return Encoding.UTF8.GetString(Streams.ReadAll(input));
            }
        }
    }
}
