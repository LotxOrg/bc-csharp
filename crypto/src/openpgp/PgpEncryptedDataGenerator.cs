using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;

using Org.BouncyCastle.Asn1.Cryptlib;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>Generator for encrypted objects.</summary>
    public class PgpEncryptedDataGenerator
        : IStreamGenerator
    {
        private BcpgOutputStream pOut;
        private CipherStream cOut;
        private IBufferedCipher c;
        private bool withIntegrityPacket;
        private bool oldFormat;
        private DigestStream digestOut;
        private Seipd2OutputStream m_aeadOut;

        private abstract class EncMethod
            : ContainedPacket
        {
            internal EncMethod()
#pragma warning disable CS0618 // Type or member is obsolete
                : base()
#pragma warning restore CS0618 // Type or member is obsolete
            {
            }

            protected byte[] sessionInfo;
            protected SymmetricKeyAlgorithmTag encAlgorithm;
            protected KeyParameter key;

            public abstract void AddSessionInfo(byte[] si, SecureRandom random);
        }

        private class PbeMethod
            : EncMethod
        {
            private readonly S2k m_s2k;

            internal PbeMethod(SymmetricKeyAlgorithmTag encAlgorithm, S2k s2k, KeyParameter key)
            {
                this.encAlgorithm = encAlgorithm;
                m_s2k = s2k;
                this.key = key;
            }

            public KeyParameter GetKey() => key;

            public override void AddSessionInfo(byte[] si, SecureRandom random)
            {
                string cName = PgpUtilities.GetSymmetricCipherName(encAlgorithm);
                IBufferedCipher c = CipherUtilities.GetCipher(cName + "/CFB/NoPadding");

                byte[] iv = new byte[c.GetBlockSize()];
                c.Init(true, new ParametersWithRandom(new ParametersWithIV(key, iv), random));

                this.sessionInfo = c.DoFinal(si, 0, si.Length - 2);
            }

            public override void Encode(BcpgOutputStream pOut) =>
                SymmetricKeyEncSessionPacket.CreateV4Packet(encAlgorithm, m_s2k, sessionInfo).Encode(pOut);
        }

        private class PubMethod
            : EncMethod
        {
            internal PgpPublicKey pubKey;
            internal bool sessionKeyObfuscation;
            internal bool useV6;
            internal bool anonymous;
            internal byte[][] data;

            internal PubMethod(PgpPublicKey pubKey, bool sessionKeyObfuscation, bool useV6, bool anonymous)
            {
                this.pubKey = pubKey;
                this.sessionKeyObfuscation = sessionKeyObfuscation;
                this.useV6 = useV6;
                this.anonymous = anonymous;
            }

            public override void AddSessionInfo(
                byte[] sessionInfo,
                SecureRandom random)
            {
                byte[] encryptedSessionInfo = EncryptSessionInfo(sessionInfo, random);

                this.data = ProcessSessionInfo(encryptedSessionInfo);
            }

            /// <summary>
            /// What the public key algorithm is given. RFC 9580 5.1.3 concatenates "the 1-octet
            /// algorithm identifier, <em>if it was passed (in the case of a v3 PKESK packet)</em>,
            /// the session key, a 2-octet checksum" -- so a v6 packet is the same block with its
            /// leading octet removed, 5.1.2 having moved that identifier into the SEIPD packet.
            /// </summary>
            private byte[] SessionInfoForVersion(byte[] sessionInfo) =>
                useV6 ? Arrays.CopyOfRange(sessionInfo, 1, sessionInfo.Length) : sessionInfo;

            private byte[] EncryptSessionInfo(byte[] sessionInfo, SecureRandom random)
            {
                var cryptoPublicKey = pubKey.GetKey();

                if (Rfc9580Utilities.IsNativeDiffieHellman(pubKey.Algorithm))
                    return EncryptSessionInfoNativeDH(sessionInfo, cryptoPublicKey, random);

                if (pubKey.Algorithm != PublicKeyAlgorithmTag.ECDH)
                {
                    IBufferedCipher c;
                    switch (pubKey.Algorithm)
                    {
                    case PublicKeyAlgorithmTag.RsaEncrypt:
                    case PublicKeyAlgorithmTag.RsaGeneral:
                        c = CipherUtilities.GetCipher("RSA//PKCS1Padding");
                        break;
                    case PublicKeyAlgorithmTag.ElGamalEncrypt:
                    case PublicKeyAlgorithmTag.ElGamalGeneral:
                        c = CipherUtilities.GetCipher("ElGamal/ECB/PKCS1Padding");
                        break;
                    case PublicKeyAlgorithmTag.Dsa:
                        throw new PgpException("Can't use DSA for encryption.");
                    case PublicKeyAlgorithmTag.ECDsa:
                        throw new PgpException("Can't use ECDSA for encryption.");
                    case PublicKeyAlgorithmTag.EdDsa_Legacy:
                        throw new PgpException("Can't use EdDSA for encryption.");
                    default:
                        throw new PgpException("unknown asymmetric algorithm: " + pubKey.Algorithm);
                    }

                    c.Init(true, new ParametersWithRandom(cryptoPublicKey, random));
                    return c.DoFinal(SessionInfoForVersion(sessionInfo));
                }

                ECDHPublicBcpgKey ecPubKey = (ECDHPublicBcpgKey)pubKey.PublicKeyPacket.Key;
                var curveOid = ecPubKey.CurveOid;

                if (EdECObjectIdentifiers.id_X25519.Equals(curveOid) ||
                    CryptlibObjectIdentifiers.curvey25519.Equals(curveOid))
                {
                    X25519KeyPairGenerator gen = new X25519KeyPairGenerator();
                    gen.Init(new X25519KeyGenerationParameters(random));

                    AsymmetricCipherKeyPair ephKp = gen.GenerateKeyPair();

                    X25519Agreement agreement = new X25519Agreement();
                    agreement.Init(ephKp.Private);

                    byte[] secret = new byte[agreement.AgreementSize];
                    agreement.CalculateAgreement(cryptoPublicKey, secret, 0);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    Span<byte> ephPubEncoding = stackalloc byte[1 + X25519PublicKeyParameters.KeySize];
                    ((X25519PublicKeyParameters)ephKp.Public).Encode(ephPubEncoding[1..]);
#else
                    byte[] ephPubEncoding = new byte[1 + X25519PublicKeyParameters.KeySize];
                    ((X25519PublicKeyParameters)ephKp.Public).Encode(ephPubEncoding, 1);
#endif
                    ephPubEncoding[0] = 0x40;

                    return EncryptSessionInfo(ecPubKey, sessionInfo, secret, ephPubEncoding, random);
                }
                else if (EdECObjectIdentifiers.id_X448.Equals(curveOid))
                {
                    X448KeyPairGenerator gen = new X448KeyPairGenerator();
                    gen.Init(new X448KeyGenerationParameters(random));

                    AsymmetricCipherKeyPair ephKp = gen.GenerateKeyPair();

                    X448Agreement agreement = new X448Agreement();
                    agreement.Init(ephKp.Private);

                    byte[] secret = new byte[agreement.AgreementSize];
                    agreement.CalculateAgreement(cryptoPublicKey, secret, 0);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    Span<byte> ephPubEncoding = stackalloc byte[1 + X448PublicKeyParameters.KeySize];
                    ((X448PublicKeyParameters)ephKp.Public).Encode(ephPubEncoding[1..]);
#else
                    byte[] ephPubEncoding = new byte[1 + X448PublicKeyParameters.KeySize];
                    ((X448PublicKeyParameters)ephKp.Public).Encode(ephPubEncoding, 1);
#endif
                    ephPubEncoding[0] = 0x40;

                    return EncryptSessionInfo(ecPubKey, sessionInfo, secret, ephPubEncoding, random);
                }
                else
                {
                    // Generate the ephemeral key pair
                    ECDomainParameters ecParams = ((ECPublicKeyParameters)cryptoPublicKey).Parameters;
                    ECKeyPairGenerator gen = new ECKeyPairGenerator();
                    gen.Init(new ECKeyGenerationParameters(ecParams, random));

                    AsymmetricCipherKeyPair ephKp = gen.GenerateKeyPair();

                    ECDHBasicAgreement agreement = new ECDHBasicAgreement();
                    agreement.Init(ephKp.Private);
                    BigInteger S = agreement.CalculateAgreement(cryptoPublicKey);
                    byte[] secret = BigIntegers.AsUnsignedByteArray(agreement.GetFieldSize(), S);

                    var q = ((ECPublicKeyParameters)ephKp.Public).Q;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    int encodedLength = q.GetEncodedLength(false);
                    Span<byte> ephPubEncoding = encodedLength <= 512
                        ? stackalloc byte[encodedLength]
                        : new byte[encodedLength];
                    q.EncodeTo(false, ephPubEncoding);
#else
                    byte[] ephPubEncoding = q.GetEncoded(false);
#endif

                    return EncryptSessionInfo(ecPubKey, sessionInfo, secret, ephPubEncoding, random);
                }
            }

            /// <summary>
            /// RFC 9580 5.1.6 and 5.1.7, for the X25519 and X448 algorithms the same document
            /// introduced. The layout is the ephemeral public key, a one-octet length, and the
            /// fields it covers -- for a v3 packet the symmetric algorithm identifier in the clear
            /// followed by the wrapped session key, and for a v6 packet the wrapped session key
            /// alone. Unlike ECDH, neither a checksum nor padding is wrapped with the key.
            /// </summary>
            private byte[] EncryptSessionInfoNativeDH(byte[] sessionInfo,
                AsymmetricKeyParameter cryptoPublicKey, SecureRandom random)
            {
                var algorithm = pubKey.Algorithm;

                // "In this case" in 5.1.6 and 5.1.7 is the v3 packet, whose algorithm identifier
                // travels in the clear; a v6 packet carries none for the rule to apply to.
                if (!useV6)
                {
                    Rfc9580Utilities.ValidateSessionKeyAlgorithm(algorithm,
                        (SymmetricKeyAlgorithmTag)sessionInfo[0]);
                }

                byte[] ephemeralPublicKey, recipientPublicKey, secret;

                if (algorithm == PublicKeyAlgorithmTag.X25519)
                {
                    if (!(cryptoPublicKey is X25519PublicKeyParameters recipient))
                        throw new PgpException("key is not an X25519 key");

                    var gen = new X25519KeyPairGenerator();
                    gen.Init(new X25519KeyGenerationParameters(random));
                    var ephKp = gen.GenerateKeyPair();

                    var agreement = new X25519Agreement();
                    agreement.Init(ephKp.Private);
                    secret = new byte[agreement.AgreementSize];
                    agreement.CalculateAgreement(recipient, secret, 0);

                    ephemeralPublicKey = ((X25519PublicKeyParameters)ephKp.Public).GetEncoded();
                    recipientPublicKey = recipient.GetEncoded();
                }
                else
                {
                    if (!(cryptoPublicKey is X448PublicKeyParameters recipient))
                        throw new PgpException("key is not an X448 key");

                    var gen = new X448KeyPairGenerator();
                    gen.Init(new X448KeyGenerationParameters(random));
                    var ephKp = gen.GenerateKeyPair();

                    var agreement = new X448Agreement();
                    agreement.Init(ephKp.Private);
                    secret = new byte[agreement.AgreementSize];
                    agreement.CalculateAgreement(recipient, secret, 0);

                    ephemeralPublicKey = ((X448PublicKeyParameters)ephKp.Public).GetEncoded();
                    recipientPublicKey = recipient.GetEncoded();
                }

                var key = Rfc9580Utilities.CreateKey(algorithm, ephemeralPublicKey, recipientPublicKey,
                    secret);

                IWrapper w = PgpUtilities.CreateWrapper(Rfc9580Utilities.KeyWrapAlgorithm(algorithm));
                w.Init(true, new ParametersWithRandom(key, random));

                // The session info is the algorithm identifier, the session key, and a two-octet
                // checksum. Only the key is wrapped.
                byte[] sessionKey = Arrays.CopyOfRange(sessionInfo, 1, sessionInfo.Length - 2);
                byte[] wrapped = w.Wrap(sessionKey, 0, sessionKey.Length);

                int fieldsLength = useV6 ? wrapped.Length : 1 + wrapped.Length;

                byte[] rv = new byte[ephemeralPublicKey.Length + 1 + fieldsLength];
                Array.Copy(ephemeralPublicKey, 0, rv, 0, ephemeralPublicKey.Length);
                rv[ephemeralPublicKey.Length] = (byte)fieldsLength;

                int wrappedOffset = ephemeralPublicKey.Length + 1;
                if (!useV6)
                {
                    rv[wrappedOffset] = sessionInfo[0];
                    wrappedOffset++;
                }

                Array.Copy(wrapped, 0, rv, wrappedOffset, wrapped.Length);

                return rv;
            }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            private byte[] EncryptSessionInfo(ECDHPublicBcpgKey ecPubKey, byte[] sessionInfo, byte[] secret,
                ReadOnlySpan<byte> ephPubEncoding, SecureRandom random)
#else
            private byte[] EncryptSessionInfo(ECDHPublicBcpgKey ecPubKey, byte[] sessionInfo, byte[] secret,
                byte[] ephPubEncoding, SecureRandom random)
#endif
            {
                var key = new KeyParameter(Rfc6637Utilities.CreateKey(pubKey.PublicKeyPacket, secret));

                IWrapper w = PgpUtilities.CreateWrapper(ecPubKey.SymmetricKeyAlgorithm);
                w.Init(true, new ParametersWithRandom(key, random));

                byte[] paddedSessionData = PgpPad.PadSessionData(SessionInfoForVersion(sessionInfo),
                    sessionKeyObfuscation);

                byte[] C = w.Wrap(paddedSessionData, 0, paddedSessionData.Length);
                byte[] VB = new MPInteger(new BigInteger(1, ephPubEncoding)).GetEncoded();

                byte[] rv = new byte[VB.Length + 1 + C.Length];

                Array.Copy(VB, 0, rv, 0, VB.Length);
                rv[VB.Length] = (byte)C.Length;
                Array.Copy(C, 0, rv, VB.Length + 1, C.Length);

                return rv;
            }

            private byte[][] ProcessSessionInfo(byte[] encryptedSessionInfo)
            {
                byte[][] data;

                switch (pubKey.Algorithm)
                {
                case PublicKeyAlgorithmTag.RsaEncrypt:
                case PublicKeyAlgorithmTag.RsaGeneral:
                    data = new byte[1][]{ ConvertToEncodedMpi(encryptedSessionInfo) };
                    break;
                case PublicKeyAlgorithmTag.ElGamalEncrypt:
                case PublicKeyAlgorithmTag.ElGamalGeneral:
                    int halfLength = encryptedSessionInfo.Length / 2;
                    byte[] b1 = new byte[halfLength];
                    byte[] b2 = new byte[halfLength];

                    Array.Copy(encryptedSessionInfo, 0, b1, 0, halfLength);
                    Array.Copy(encryptedSessionInfo, halfLength, b2, 0, halfLength);

                    data = new byte[2][]{
                    ConvertToEncodedMpi(b1),
                    ConvertToEncodedMpi(b2),
                };
                    break;
                case PublicKeyAlgorithmTag.ECDH:
                case PublicKeyAlgorithmTag.X25519:
                case PublicKeyAlgorithmTag.X448:
                    data = new byte[1][]{ encryptedSessionInfo };
                    break;
                default:
                    throw new PgpException("unknown asymmetric algorithm: " + pubKey.Algorithm);
                }

                return data;
            }

            private static byte[] ConvertToEncodedMpi(byte[] encryptedSessionInfo)
            {
                try
                {
                    return new MPInteger(new BigInteger(1, encryptedSessionInfo)).GetEncoded();
                }
                catch (IOException e)
                {
                    throw new PgpException("Invalid MPI encoding: " + e.Message, e);
                }
            }

            public override void Encode(BcpgOutputStream pOut)
            {
                PublicKeyEncSessionPacket packet;

                if (useV6)
                {
                    packet = anonymous
                        ? PublicKeyEncSessionPacket.CreateV6Packet(keyVersion: 0, Array.Empty<byte>(),
                            pubKey.Algorithm, data)
                        : PublicKeyEncSessionPacket.CreateV6Packet(pubKey.Version, pubKey.GetFingerprint(),
                            pubKey.Algorithm, data);
                }
                else
                {
                    packet = new PublicKeyEncSessionPacket(anonymous ? 0L : pubKey.KeyId, pubKey.Algorithm, data);
                }

                packet.Encode(pOut);
            }
        }

        private readonly List<EncMethod> methods = new List<EncMethod>();
        private readonly SymmetricKeyAlgorithmTag defAlgorithm;
        private readonly SecureRandom rand;
        private readonly bool m_useAead;
        private readonly AeadAlgorithmTag m_aeadAlgorithm;
        private readonly int m_chunkSizeOctet;

        public PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag encAlgorithm)
        {
            this.defAlgorithm = encAlgorithm;
            this.rand = CryptoServicesRegistrar.GetSecureRandom();
        }

        public PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag encAlgorithm, bool withIntegrityPacket)
        {
            this.defAlgorithm = encAlgorithm;
            this.withIntegrityPacket = withIntegrityPacket;
            this.rand = CryptoServicesRegistrar.GetSecureRandom();
        }

        /// <summary>Existing SecureRandom constructor.</summary>
        /// <param name="encAlgorithm">The symmetric algorithm to use.</param>
        /// <param name="random">Source of randomness.</param>
        public PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag encAlgorithm, SecureRandom random)
        {
            this.defAlgorithm = encAlgorithm;
            this.rand = random ?? throw new ArgumentNullException(nameof(random));
        }

        /// <summary>Creates a cipher stream which will have an integrity packet associated with it.</summary>
        public PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag encAlgorithm, bool withIntegrityPacket,
            SecureRandom random)
        {
            this.defAlgorithm = encAlgorithm;
            this.rand = random ?? throw new ArgumentNullException(nameof(random));
            this.withIntegrityPacket = withIntegrityPacket;
        }

        /// <summary>Base constructor.</summary>
        /// <param name="encAlgorithm">The symmetric algorithm to use.</param>
        /// <param name="random">Source of randomness.</param>
        /// <param name="oldFormat">PGP 2.6.x compatibility required.</param>
        public PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag encAlgorithm, SecureRandom random, bool oldFormat)
        {
            this.defAlgorithm = encAlgorithm;
            this.rand = random ?? throw new ArgumentNullException(nameof(random));
            this.oldFormat = oldFormat;
        }

        /// <summary>
        /// Produce a version 6 PKESK packet and a version 2 SEIPD packet, encrypting under the
        /// given AEAD mode rather than in CFB with a modification detection code.
        /// </summary>
        /// <remarks>
        /// RFC 9580 10.3.2.1 pairs the two versions strictly: a v6 PKESK packet must be followed by
        /// a v2 SEIPD packet and a v3 one by a v1 SEIPD packet, with no crossing. Whether a
        /// recipient can read this is a fact about their certificate rather than about their key --
        /// the Features subpacket (5.2.3.32) sets 0x08 for a keyholder who can, and an
        /// implementation "SHOULD NOT use a feature listed when sending to a user who does not state
        /// that they can use it".
        /// </remarks>
        /// <param name="encAlgorithm">
        /// The symmetric algorithm to use. It must have a 16-octet block, which the AEAD modes of
        /// 5.13.3 through 5.13.5 all require.
        /// </param>
        /// <param name="aeadAlgorithm">The AEAD mode: EAX, OCB or GCM.</param>
        public PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag encAlgorithm, AeadAlgorithmTag aeadAlgorithm)
            : this(encAlgorithm, aeadAlgorithm, Seipd2Utilities.DefaultChunkSizeOctet,
                CryptoServicesRegistrar.GetSecureRandom())
        {
        }

        /// <inheritdoc cref="PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag, AeadAlgorithmTag)"/>
        /// <param name="encAlgorithm">The symmetric algorithm to use.</param>
        /// <param name="aeadAlgorithm">The AEAD mode: EAX, OCB or GCM.</param>
        /// <param name="chunkSizeOctet">
        /// The chunk size octet, from 0 to 16; each chunk holds <c>1 &lt;&lt; (octet + 6)</c> octets and
        /// costs a 16-octet tag.
        /// </param>
        /// <param name="random">Source of randomness.</param>
        public PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag encAlgorithm, AeadAlgorithmTag aeadAlgorithm,
            int chunkSizeOctet, SecureRandom random)
        {
            if (chunkSizeOctet < 0 || chunkSizeOctet > SymmetricEncIntegrityPacket.MaxChunkSizeOctet)
                throw new ArgumentOutOfRangeException(nameof(chunkSizeOctet));

            this.defAlgorithm = encAlgorithm;
            this.rand = random ?? throw new ArgumentNullException(nameof(random));
            this.withIntegrityPacket = true;
            this.m_useAead = true;
            this.m_aeadAlgorithm = aeadAlgorithm;
            this.m_chunkSizeOctet = chunkSizeOctet;
        }

        /// <summary>Add a PBE encryption method to the encrypted object.</summary>
        /// <remarks>
        /// Conversion of the passphrase characters to bytes is performed using Convert.ToByte(), which is
        /// the historical behaviour of the library (1.7 and earlier).
        /// </remarks>
        public void AddMethod(char[] passPhrase, HashAlgorithmTag s2kDigest)
        {
            var rawPassPhrase = PgpUtilities.EncodePassPhrase(passPhrase, utf8: false);

            ImplAddPbeMethod(rawPassPhrase, clearPassPhrase: true, s2kDigest, itCount: 0x60);
        }

        /// <summary>Add a PBE encryption method to the encrypted object.</summary>
        /// <remarks>
        /// The passphrase is encoded to bytes using UTF8.
        /// </remarks>
        public void AddMethodUtf8(char[] passPhrase, HashAlgorithmTag s2kDigest)
        {
            var rawPassPhrase = PgpUtilities.EncodePassPhrase(passPhrase, utf8: true);

            ImplAddPbeMethod(rawPassPhrase, clearPassPhrase: true, s2kDigest, itCount: 0x60);
        }

        /// <summary>Add a PBE encryption method to the encrypted object.</summary>
        /// <remarks>
        /// Allows the caller to handle the encoding of the passphrase to bytes.
        /// </remarks>
        public void AddMethodRaw(byte[] rawPassPhrase, HashAlgorithmTag s2kDigest) =>
            ImplAddPbeMethod(rawPassPhrase, clearPassPhrase: false, s2kDigest, itCount: 0x60);

        /// <summary>Add a PBE encryption method to the encrypted object.</summary>
        /// <remarks>
        /// Conversion of the passphrase characters to bytes is performed using Convert.ToByte(), which is
        /// the historical behaviour of the library (1.7 and earlier).
        /// </remarks>
        public void AddMethod(char[] passPhrase, HashAlgorithmTag s2kDigest, int itCount)
        {
            var rawPassPhrase = PgpUtilities.EncodePassPhrase(passPhrase, utf8: false);

            ImplAddPbeMethod(rawPassPhrase, clearPassPhrase: true, s2kDigest, itCount);
        }

        /// <summary>Add a PBE encryption method to the encrypted object.</summary>
        /// <remarks>
        /// The passphrase is encoded to bytes using UTF8.
        /// </remarks>
        public void AddMethodUtf8(char[] passPhrase, HashAlgorithmTag s2kDigest, int itCount)
        {
            var rawPassPhrase = PgpUtilities.EncodePassPhrase(passPhrase, utf8: true);

            ImplAddPbeMethod(rawPassPhrase, clearPassPhrase: true, s2kDigest, itCount);
        }

        /// <summary>Add a PBE encryption method to the encrypted object.</summary>
        /// <remarks>
        /// Allows the caller to handle the encoding of the passphrase to bytes.
        /// </remarks>
        public void AddMethodRaw(byte[] rawPassPhrase, HashAlgorithmTag s2kDigest, int itCount) =>
            ImplAddPbeMethod(rawPassPhrase, clearPassPhrase: false, s2kDigest, itCount);

        internal void ImplAddPbeMethod(byte[] rawPassPhrase, bool clearPassPhrase, HashAlgorithmTag s2kDigest,
            int itCount)
        {
            if (m_useAead)
            {
                throw new PgpException(
                    "a passphrase method needs a v6 SKESK packet to accompany a v2 SEIPD packet, " +
                    "which is not implemented");
            }

            var s2k = S2k.GenerateSaltedAndIterated(rand, s2kDigest, itCount);
            var key = PgpUtilities.DoMakeKeyFromPassPhrase(defAlgorithm, s2k, rawPassPhrase, clearPassPhrase);
            var encMethod = new PbeMethod(defAlgorithm, s2k, key);
            methods.Add(encMethod);
        }

        /// <summary>Add a public key encrypted session key to the encrypted object.</summary>
        public void AddMethod(PgpPublicKey key) => AddMethod(key, sessionKeyObfuscation: true);

        public void AddMethod(PgpPublicKey key, bool sessionKeyObfuscation)
        {
            if (!key.IsEncryptionKey)
                throw new ArgumentException("passed in key not an encryption key!", nameof(key));

            methods.Add(new PubMethod(key, sessionKeyObfuscation, m_useAead, anonymous: false));
        }

        /// <summary>
        /// Add a public key encrypted session key that does not say which key it was encrypted to.
        /// </summary>
        /// <remarks>
        /// RFC 9580 5.1.8 allows the recipient to be withheld -- a Key ID of all zeros in a version
        /// 3 packet, an omitted fingerprint in a version 6 one -- so that the message says nothing
        /// about who can open it. The cost falls on the reader, who "would try all available
        /// private keys, checking for a valid decrypted session key"; see
        /// <see cref="PgpPublicKeyEncryptedData.TryGetDataStream"/>, which is the primitive that
        /// makes working through a set of keys something other than a sequence of exceptions.
        /// </remarks>
        public void AddAnonymousMethod(PgpPublicKey key) => AddAnonymousMethod(key, sessionKeyObfuscation: true);

        /// <inheritdoc cref="AddAnonymousMethod(PgpPublicKey)"/>
        /// <param name="key">The recipient's encryption key.</param>
        /// <param name="sessionKeyObfuscation">
        /// Whether to pad the wrapped session key, where the algorithm pads.
        /// </param>
        public void AddAnonymousMethod(PgpPublicKey key, bool sessionKeyObfuscation)
        {
            if (!key.IsEncryptionKey)
                throw new ArgumentException("passed in key not an encryption key!", nameof(key));

            methods.Add(new PubMethod(key, sessionKeyObfuscation, m_useAead, anonymous: true));
        }

        private static void AddCheckSum(byte[] sessionInfo)
        {
            Debug.Assert(sessionInfo != null);
            Debug.Assert(sessionInfo.Length >= 3);

            int check = 0;

            for (int i = 1; i < sessionInfo.Length - 2; i++)
            {
                check += sessionInfo[i];
            }

            sessionInfo[sessionInfo.Length - 2] = (byte)(check >> 8);
            sessionInfo[sessionInfo.Length - 1] = (byte)(check);
        }

        private static byte[] CreateSessionInfo(SymmetricKeyAlgorithmTag algorithm, KeyParameter key)
        {
            int keyLength = key.KeyLength;
            byte[] sessionInfo = new byte[keyLength + 3];
            sessionInfo[0] = (byte)algorithm;
            key.CopyKeyTo(sessionInfo, 1, keyLength);
            AddCheckSum(sessionInfo);
            return sessionInfo;
        }

        /// <summary>
        /// <p>
        /// If buffer is non null stream assumed to be partial, otherwise the length will be used
        /// to output a fixed length packet.
        /// </p>
        /// <p>
        /// The stream created can be closed off by either calling Close()
        /// on the stream or Close() on the generator. Closing the returned
        /// stream does not close off the Stream parameter <c>outStr</c>.
        /// </p>
        /// </summary>
        private Stream Open(Stream outStr, long length, byte[] buffer)
        {
            if (cOut != null)
                throw new InvalidOperationException("generator already in open state");
            if (methods.Count == 0)
                throw new InvalidOperationException("No encryption methods specified");
            if (outStr == null)
                throw new ArgumentNullException(nameof(outStr));

            pOut = new BcpgOutputStream(outStr);

            KeyParameter key;

            if (methods.Count == 1)
            {
                if (methods[0] is PbeMethod pbeMethod)
                {
                    key = pbeMethod.GetKey();
                }
                else if (methods[0] is PubMethod pubMethod)
                {
                    key = PgpUtilities.MakeRandomKey(defAlgorithm, rand);

                    byte[] sessionInfo = CreateSessionInfo(defAlgorithm, key);

                    try
                    {
                        pubMethod.AddSessionInfo(sessionInfo, rand);
                    }
                    catch (Exception e)
                    {
                        throw new PgpException("exception encrypting session key", e);
                    }
                }
                else
                {
                    throw new InvalidOperationException();
                }

                methods[0].Encode(pOut);
            }
            else // multiple methods
            {
                key = PgpUtilities.MakeRandomKey(defAlgorithm, rand);
                byte[] sessionInfo = CreateSessionInfo(defAlgorithm, key);

                foreach (EncMethod m in methods)
                {
                    try
                    {
                        m.AddSessionInfo(sessionInfo, rand);
                    }
                    catch (Exception e)
                    {
                        throw new PgpException("exception encrypting session key", e);
                    }

                    m.Encode(pOut);
                }
            }

            if (m_useAead)
                return OpenAead(outStr, length, buffer, key);

            string cName = PgpUtilities.GetSymmetricCipherName(defAlgorithm)
                ?? throw new PgpException("null cipher specified");

            try
            {
                if (withIntegrityPacket)
                {
                    cName += "/CFB/NoPadding";
                }
                else
                {
                    cName += "/OpenPGPCFB/NoPadding";
                }

                c = CipherUtilities.GetCipher(cName);

                // TODO Confirm the IV should be all zero bytes (not inLineIv - see below)
                byte[] iv = new byte[c.GetBlockSize()];
                c.Init(true, new ParametersWithRandom(new ParametersWithIV(key, iv), rand));

                if (buffer == null)
                {
                    //
                    // we have to Add block size + 2 for the Generated IV and + 1 + 22 if integrity protected
                    //
                    if (withIntegrityPacket)
                    {
                        pOut = new BcpgOutputStream(outStr, PacketTag.SymmetricEncryptedIntegrityProtected, length + c.GetBlockSize() + 2 + 1 + 22);
                        pOut.WriteByte(1);        // version number
                    }
                    else
                    {
                        pOut = new BcpgOutputStream(outStr, PacketTag.SymmetricKeyEncrypted, length + c.GetBlockSize() + 2, oldFormat);
                    }
                }
                else
                {
                    if (withIntegrityPacket)
                    {
                        pOut = new BcpgOutputStream(outStr, PacketTag.SymmetricEncryptedIntegrityProtected, buffer);
                        pOut.WriteByte(1);        // version number
                    }
                    else
                    {
                        pOut = new BcpgOutputStream(outStr, PacketTag.SymmetricKeyEncrypted, buffer);
                    }
                }

                int blockSize = c.GetBlockSize();
                byte[] inLineIv = new byte[blockSize + 2];
                rand.NextBytes(inLineIv, 0, blockSize);
                Array.Copy(inLineIv, inLineIv.Length - 4, inLineIv, inLineIv.Length - 2, 2);

                Stream myOut = cOut = new CipherStream(pOut, null, c);

                if (withIntegrityPacket)
                {
                    IDigest digest = PgpUtilities.CreateDigest(HashAlgorithmTag.Sha1);
                    myOut = digestOut = new DigestStream(myOut, null, digest);
                }

                myOut.Write(inLineIv, 0, inLineIv.Length);

                return new WrappedGeneratorStream(this, myOut);
            }
            catch (Exception e)
            {
                throw new PgpException("Exception creating cipher", e);
            }
        }

        /// <summary>
        /// Write the header of a version 2 SEIPD packet and return a stream that encrypts what is
        /// written to it in authenticated chunks.
        /// </summary>
        private Stream OpenAead(Stream outStr, long length, byte[] buffer, KeyParameter key)
        {
            byte[] salt = new byte[SymmetricEncIntegrityPacket.SaltLength];
            rand.NextBytes(salt);

            try
            {
                if (buffer == null)
                {
                    pOut = new BcpgOutputStream(outStr, PacketTag.SymmetricEncryptedIntegrityProtected,
                        Seipd2BodyLength(length));
                }
                else
                {
                    pOut = new BcpgOutputStream(outStr, PacketTag.SymmetricEncryptedIntegrityProtected, buffer);
                }

                pOut.WriteByte(SymmetricEncIntegrityPacket.Version2);
                pOut.WriteByte((byte)defAlgorithm);
                pOut.WriteByte((byte)m_aeadAlgorithm);
                pOut.WriteByte((byte)m_chunkSizeOctet);
                pOut.Write(salt, 0, salt.Length);

                byte[] sessionKey = key.GetKey();
                try
                {
                    m_aeadOut = new Seipd2OutputStream(pOut, defAlgorithm, m_aeadAlgorithm, m_chunkSizeOctet,
                        sessionKey, salt);
                }
                finally
                {
                    Arrays.ZeroMemory(sessionKey);
                }

                return new WrappedGeneratorStream(this, m_aeadOut);
            }
            catch (PgpException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new PgpException("Exception creating cipher", e);
            }
        }

        /// <summary>
        /// The exact size of a version 2 SEIPD packet body for a plaintext of the given length: the
        /// four fields and the salt, the plaintext itself, a tag for every chunk it is divided
        /// into, and the tag that closes the packet.
        /// </summary>
        private long Seipd2BodyLength(long length)
        {
            long chunkLength = Seipd2Utilities.ChunkLength(m_chunkSizeOctet);
            long tagLength = AeadUtilities.GetAuthTagLength(m_aeadAlgorithm);

            // An empty plaintext produces no chunks at all, which the ceiling gives for free.
            long chunks = (length + chunkLength - 1) / chunkLength;

            return 4 + SymmetricEncIntegrityPacket.SaltLength + length + (chunks + 1) * tagLength;
        }

        /// <summary>
        /// <p>
        /// Return an output stream which will encrypt the data as it is written to it.
        /// </p>
        /// <p>
        /// The stream created can be closed off by either calling Close()
        /// on the stream or Close() on the generator. Closing the returned
        /// stream does not close off the Stream parameter <c>outStr</c>.
        /// </p>
        /// </summary>
        public Stream Open(Stream outStr, long length) => Open(outStr, length, buffer: null);

        /// <summary>
        /// <p>
        /// Return an output stream which will encrypt the data as it is written to it.
        /// The stream will be written out in chunks according to the size of the passed in buffer.
        /// </p>
        /// <p>
        /// The stream created can be closed off by either calling Close()
        /// on the stream or Close() on the generator. Closing the returned
        /// stream does not close off the Stream parameter <c>outStr</c>.
        /// </p>
        /// <p>
        /// <b>Note</b>: if the buffer is not a power of 2 in length only the largest power of 2
        /// bytes worth of the buffer will be used.
        /// </p>
        /// </summary>
        public Stream Open(Stream outStr, byte[] buffer) => Open(outStr, length: 0, buffer);

        [Obsolete("Dispose any opened Stream directly")]
        public void Close()
        {
            if (m_aeadOut != null)
            {
                // Disposing writes whatever is left of the last chunk and then the tag over the
                // total length, both of which belong inside the packet.
                m_aeadOut.Dispose();
                m_aeadOut = null;

                try
                {
                    pOut.Finish();
                }
                catch (Exception e)
                {
                    throw new IOException(e.Message, e);
                }

                pOut = null;
                return;
            }

            if (cOut != null)
            {
                // TODO Should this all be under the try/catch block?
                if (digestOut != null)
                {
                    //
                    // hand code a mod detection packet
                    //
                    var bOut = new BcpgOutputStream(digestOut, PacketTag.ModificationDetectionCode, length: 20);

                    // For clarity; really only required if using partial body lengths
                    bOut.Finish();
                    bOut.Flush();

                    byte[] dig = DigestUtilities.DoFinal(digestOut.WriteDigest);

                    cOut.Write(dig, 0, dig.Length);
                }

                cOut.Flush();

                try
                {
                    pOut.Write(c.DoFinal());
                    pOut.Finish();
                }
                catch (Exception e)
                {
                    throw new IOException(e.Message, e);
                }

                cOut = null;
                pOut = null;
            }
        }
    }
}
