using System;
using System.IO;

using Org.BouncyCastle.Asn1.Cryptlib;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>A public key encrypted data object.</remarks>
    public class PgpPublicKeyEncryptedData
        : PgpEncryptedData
    {
        private readonly PublicKeyEncSessionPacket m_keyData;

        internal PgpPublicKeyEncryptedData(PublicKeyEncSessionPacket keyData, InputStreamPacket encData)
            : base(encData)
        {
            m_keyData = keyData;
        }

        private static IBufferedCipher GetKeyCipher(PublicKeyAlgorithmTag algorithm)
        {
            try
            {
                switch (algorithm)
                {
                case PublicKeyAlgorithmTag.RsaEncrypt:
                case PublicKeyAlgorithmTag.RsaGeneral:
                    return CipherUtilities.GetCipher("RSA//PKCS1Padding");
                case PublicKeyAlgorithmTag.ElGamalEncrypt:
                case PublicKeyAlgorithmTag.ElGamalGeneral:
                    return CipherUtilities.GetCipher("ElGamal/ECB/PKCS1Padding");
                default:
                    throw new PgpException("unknown asymmetric algorithm: " + algorithm);
                }
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

        /// <summary>The Key ID for the key used to encrypt the data.</summary>
        /// <remarks>
        /// A Key ID is an 8-octet scalar. We convert it (big-endian) to an Int64 (UInt64 is not CLS compliant).
        /// </remarks>
        public long KeyId => m_keyData.KeyId;

        /// <summary>The version of the PKESK packet: 3, or 6 where the recipient is named by fingerprint.</summary>
        public int Version => m_keyData.Version;

        /// <summary>
        /// Whether the packet withholds the key it was encrypted to, so that <see cref="KeyId"/>
        /// names nothing and the reader has to work through the keys it holds.
        /// </summary>
        /// <remarks>
        /// RFC 9580 5.1.8: a Key ID of all zeros, or an omitted fingerprint, hides the intended
        /// decryption key, and "this format helps reduce traffic analysis of messages".
        /// </remarks>
        public bool IsAnonymous => m_keyData.IsAnonymous;

        /// <summary>
        /// The decrypted data stream, or null where this is not the key the session key was
        /// encrypted to.
        /// </summary>
        /// <remarks>
        /// This is what an anonymous packet needs: a caller can try each key it holds without
        /// treating the ones that do not fit as errors. A key of the wrong algorithm is refused
        /// outright, and a key of the right algorithm that fails to unwrap the session key -- which
        /// the key wrap's own integrity check, or the session key checksum, detects -- answers null
        /// rather than throwing. Anything else is a real failure and is thrown.
        /// <para>
        /// It answers null for a named packet whose key does not match as well, so a caller need
        /// not treat the two shapes differently.
        /// </para>
        /// <para>
        /// A failed attempt does not consume the packet: the session key is recovered before the
        /// encrypted data stream is opened, so a caller may keep trying keys on the same object.
        /// </para>
        /// </remarks>
        public Stream TryGetDataStream(PgpPrivateKey privKey)
        {
            if (privKey == null)
                throw new ArgumentNullException(nameof(privKey));

            // Established before any decryption is attempted, so that a mismatch here is not
            // confused with a key that could have fitted and did not.
            if (privKey.PublicKeyPacket.Algorithm != m_keyData.Algorithm)
                return null;

            if (!IsAnonymous && privKey.KeyId != m_keyData.KeyId)
                return null;

            try
            {
                return GetDataStream(privKey);
            }
            catch (PgpKeyValidationException)
            {
                // The session key came back, but its checksum says it is not the session key.
                return null;
            }
            catch (InvalidCipherTextException)
            {
                return null;
            }
            catch (PgpException e) when (e.InnerException is InvalidCipherTextException)
            {
                return null;
            }
        }

        /// <summary>
        /// Return the algorithm code for the symmetric algorithm used to encrypt the data.
        /// </summary>
        public SymmetricKeyAlgorithmTag GetSymmetricAlgorithm(PgpPrivateKey privKey)
        {
            // RFC 9580 5.1.2: a v6 packet passes no algorithm identifier to the public key
            // algorithm, "as it is included in the v2 SEIPD packet".
            if (m_keyData.Version == PublicKeyEncSessionPacket.Version6)
                return RequireSeipd2Packet().CipherAlgorithm;

            byte[] sessionData = RecoverSessionData(privKey);

            return (SymmetricKeyAlgorithmTag)sessionData[0];
        }

        /// <summary>Return the decrypted data stream for the packet.</summary>
        public Stream GetDataStream(PgpPrivateKey privKey)
        {
            if (m_keyData.Version == PublicKeyEncSessionPacket.Version6)
                return GetDataStreamV6(privKey);

            byte[] sessionData = RecoverSessionData(privKey);

            if (!ConfirmCheckSum(sessionData))
                throw new PgpKeyValidationException("key checksum failed");

            SymmetricKeyAlgorithmTag symmAlg = (SymmetricKeyAlgorithmTag)sessionData[0];
            if (symmAlg == SymmetricKeyAlgorithmTag.Null)
                return GetInputStream();

            string cipherName = PgpUtilities.GetSymmetricCipherName(symmAlg);

            IBufferedCipher cipher;
            try
            {
                cipher = CreateBufferedCipher(cipherName);
            }
            catch (PgpException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new PgpException("exception creating cipher", e);
            }

            try
            {
                var key = ParameterUtilities.CreateKeyParameter(cipherName, sessionData, 1, sessionData.Length - 3);

                cipher.Init(forEncryption: false, new ParametersWithIV(key, iv: new byte[cipher.GetBlockSize()]));

                var decStream = InitDecStream(new CipherStream(GetInputStream(), cipher, null));

                byte[] prefix = StreamUtilities.RequireBytes(decStream, cipher.GetBlockSize() + 2);

                /*
                 * The oracle attack on the "quick check" bytes is deemed a security risk for typical public key
                 * encryption usages, therefore we do not perform the check.
                 */
                //QuickCheck(prefix);

                return decStream;
            }
            catch (PgpException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new PgpException("Exception starting decryption", e);
            }
        }

        /// <summary>
        /// A version 6 PKESK packet can only be followed by a version 2 SEIPD packet, which says
        /// which cipher and AEAD mode were used and carries the salt the message key is derived
        /// from.
        /// </summary>
        private Stream GetDataStreamV6(PgpPrivateKey privKey)
        {
            var seipd2 = RequireSeipd2Packet();

            byte[] sessionKey = RecoverSessionKeyV6(privKey);

            try
            {
                return InitDecStream(new Seipd2InputStream(GetInputStream(), seipd2.CipherAlgorithm,
                    seipd2.AeadAlgorithm, seipd2.ChunkSize, sessionKey, seipd2.Salt));
            }
            catch (PgpException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new PgpException("Exception starting decryption", e);
            }
            finally
            {
                Arrays.ZeroMemory(sessionKey);
            }
        }

        private SymmetricEncIntegrityPacket RequireSeipd2Packet()
        {
            // RFC 9580 5.1.2: "A v6 PKESK packet MUST NOT precede a v1 SEIPD packet or a deprecated
            // SED packet".
            return Seipd2Packet
                ?? throw new PgpException("a v6 PKESK packet must be followed by a v2 SEIPD packet");
        }

        private byte[] RecoverSessionData(PgpPrivateKey privKey)
        {
            if (Rfc9580Utilities.IsNativeDiffieHellman(m_keyData.Algorithm))
                return RecoverSessionDataNativeDH(privKey);

            if (m_keyData.Algorithm != PublicKeyAlgorithmTag.ECDH)
                return RecoverAsymmetricBlock(privKey);

            return RecoverEcdhBlock(privKey);
        }

        /// <summary>
        /// The session key alone, for a version 6 packet. RFC 9580 5.1.2: "No symmetric key
        /// encryption algorithm identifier is passed to the public key algorithm for a v6 PKESK
        /// packet, as it is included in the v2 SEIPD packet." Everything else is unchanged, so the
        /// recovered block is the same one octet shorter -- and for X25519 and X448 it carries no
        /// checksum either.
        /// </summary>
        private byte[] RecoverSessionKeyV6(PgpPrivateKey privKey)
        {
            if (Rfc9580Utilities.IsNativeDiffieHellman(m_keyData.Algorithm))
                return UnwrapNativeDH(privKey, hasAlgorithmOctet: false, out _);

            byte[] block = m_keyData.Algorithm != PublicKeyAlgorithmTag.ECDH
                ? RecoverAsymmetricBlock(privKey)
                : RecoverEcdhBlock(privKey);

            // What is left is the session key and the two-octet checksum over it.
            if (block.Length < 3)
                throw new PgpException("encoded length out of range");

            byte[] sessionKey = Arrays.CopyOfRange(block, 0, block.Length - 2);

            int check = 0;
            foreach (byte b in sessionKey)
            {
                check += b;
            }

            if (Pack.BE_To_UInt16(block, block.Length - 2) != (ushort)check)
                throw new PgpKeyValidationException("key checksum failed");

            return sessionKey;
        }

        private byte[] RecoverAsymmetricBlock(PgpPrivateKey privKey)
        {
            byte[][] secKeyData = m_keyData.GetEncSessionKey();

            IBufferedCipher cipher = GetKeyCipher(m_keyData.Algorithm);

            try
            {
                cipher.Init(forEncryption: false, privKey.Key);
            }
            catch (InvalidKeyException e)
            {
                throw new PgpException("error setting asymmetric cipher", e);
            }

            if (m_keyData.Algorithm == PublicKeyAlgorithmTag.RsaEncrypt ||
                m_keyData.Algorithm == PublicKeyAlgorithmTag.RsaGeneral)
            {
                byte[] bi = secKeyData[0];

                cipher.ProcessBytes(bi, 2, bi.Length - 2);
            }
            else
            {
                ElGamalPrivateKeyParameters k = (ElGamalPrivateKeyParameters)privKey.Key;
                int size = (k.Parameters.P.BitLength + 7) / 8;

                ProcessEncodedMpi(cipher, size, secKeyData[0]);
                ProcessEncodedMpi(cipher, size, secKeyData[1]);
            }

            try
            {
                return cipher.DoFinal();
            }
            catch (Exception e)
            {
                throw new PgpException("exception decrypting secret key", e);
            }
        }

        private byte[] RecoverEcdhBlock(PgpPrivateKey privKey)
        {
            byte[][] secKeyData = m_keyData.GetEncSessionKey();

            ECDHPublicBcpgKey ecPubKey = (ECDHPublicBcpgKey)privKey.PublicKeyPacket.Key;
            byte[] enc = secKeyData[0];

            int pLen = (Pack.BE_To_UInt16(enc, 0) + 7) / 8;
            if ((2 + pLen + 1) > enc.Length)
                throw new PgpException("encoded length out of range");

            byte[] pEnc = new byte[pLen];
            Array.Copy(enc, 2, pEnc, 0, pLen);

            int keyLen = enc[pLen + 2];
            if ((2 + pLen + 1 + keyLen) > enc.Length)
                throw new PgpException("encoded length out of range");

            byte[] keyEnc = new byte[keyLen];
            Array.Copy(enc, 2 + pLen + 1, keyEnc, 0, keyEnc.Length);

            var curveOid = ecPubKey.CurveOid;
            byte[] secret;

            if (EdECObjectIdentifiers.id_X25519.Equals(curveOid) ||
                CryptlibObjectIdentifiers.curvey25519.Equals(curveOid))
            {
                // skip the 0x40 header byte.
                if (pEnc.Length != (1 + X25519PublicKeyParameters.KeySize) || 0x40 != pEnc[0])
                    throw new ArgumentException("Invalid X25519 public key");

                X25519PublicKeyParameters ephPub = new X25519PublicKeyParameters(pEnc, 1);

                X25519Agreement agreement = new X25519Agreement();
                agreement.Init(privKey.Key);

                secret = new byte[agreement.AgreementSize];
                agreement.CalculateAgreement(ephPub, secret, 0);
            }
            else if (EdECObjectIdentifiers.id_X448.Equals(curveOid))
            {
                // skip the 0x40 header byte.
                if (pEnc.Length != (1 + X448PublicKeyParameters.KeySize) || 0x40 != pEnc[0])
                    throw new ArgumentException("Invalid X448 public key");

                X448PublicKeyParameters ephPub = new X448PublicKeyParameters(pEnc, 1);

                X448Agreement agreement = new X448Agreement();
                agreement.Init(privKey.Key);

                secret = new byte[agreement.AgreementSize];
                agreement.CalculateAgreement(ephPub, secret, 0);
            }
            else
            {
                ECDomainParameters ecParameters = ((ECPrivateKeyParameters)privKey.Key).Parameters;

                ECPublicKeyParameters ephPub = new ECPublicKeyParameters(ecParameters.Curve.DecodePoint(pEnc),
                    ecParameters);

                ECDHBasicAgreement agreement = new ECDHBasicAgreement();
                agreement.Init(privKey.Key);
                BigInteger S = agreement.CalculateAgreement(ephPub);
                secret = BigIntegers.AsUnsignedByteArray(agreement.GetFieldSize(), S);
            }

            KeyParameter key = new KeyParameter(Rfc6637Utilities.CreateKey(privKey.PublicKeyPacket, secret));

            IWrapper wrapper = PgpUtilities.CreateWrapper(ecPubKey.SymmetricKeyAlgorithm);
            wrapper.Init(forWrapping: false, key);

            return PgpPad.UnpadSessionData(wrapper.Unwrap(keyEnc, 0, keyEnc.Length));
        }

        /// <summary>
        /// RFC 9580 5.1.6 and 5.1.7. The session key is wrapped on its own, with the symmetric
        /// algorithm identifier beside it in the clear and no checksum; the block returned here is
        /// rebuilt in the shape every other algorithm produces, so that the rest of this class does
        /// not have to know which one it was.
        /// </summary>
        private byte[] RecoverSessionDataNativeDH(PgpPrivateKey privKey)
        {
            byte[] sessionKey = UnwrapNativeDH(privKey, hasAlgorithmOctet: true, out byte sessionKeyAlgorithm);

            byte[] sessionData = new byte[1 + sessionKey.Length + 2];
            sessionData[0] = sessionKeyAlgorithm;
            Array.Copy(sessionKey, 0, sessionData, 1, sessionKey.Length);

            int check = 0;
            foreach (byte b in sessionKey)
            {
                check += b;
            }

            Pack.UInt16_To_BE((ushort)check, sessionData, sessionData.Length - 2);

            return sessionData;
        }

        /// <summary>
        /// Unwrap an X25519 or X448 session key. A version 3 packet puts the symmetric algorithm
        /// identifier inside the fields the one-octet length covers, immediately before the wrapped
        /// key; a version 6 packet leaves it out, so the length covers the wrapped key alone.
        /// </summary>
        private byte[] UnwrapNativeDH(PgpPrivateKey privKey, bool hasAlgorithmOctet,
            out byte sessionKeyAlgorithm)
        {
            byte[] enc = m_keyData.GetEncSessionKey()[0];

            var algorithm = m_keyData.Algorithm;
            int publicKeyLength = Rfc9580Utilities.PublicKeyLength(algorithm);

            // The ephemeral public key, a one-octet length, and the fields that length covers.
            if (enc.Length < publicKeyLength + 2)
                throw new PgpException("encoded length out of range");

            int fieldsLength = enc[publicKeyLength];
            int minimumFieldsLength = hasAlgorithmOctet ? 2 : 1;
            if (fieldsLength < minimumFieldsLength || publicKeyLength + 1 + fieldsLength > enc.Length)
                throw new PgpException("encoded length out of range");

            byte[] ephemeralPublicKey = Arrays.CopyOfRange(enc, 0, publicKeyLength);

            int wrappedOffset = publicKeyLength + 1;
            if (hasAlgorithmOctet)
            {
                sessionKeyAlgorithm = enc[wrappedOffset];
                wrappedOffset++;
            }
            else
            {
                sessionKeyAlgorithm = 0;
            }

            byte[] wrapped = Arrays.CopyOfRange(enc, wrappedOffset, publicKeyLength + 1 + fieldsLength);

            byte[] recipientPublicKey, secret;

            if (algorithm == PublicKeyAlgorithmTag.X25519)
            {
                if (!(privKey.PublicKeyPacket.Key is X25519PublicBcpgKey x25519Key))
                    throw new PgpException("session key is for X25519, but the key is not");

                var agreement = new X25519Agreement();
                agreement.Init(privKey.Key);
                secret = new byte[agreement.AgreementSize];
                agreement.CalculateAgreement(new X25519PublicKeyParameters(ephemeralPublicKey),
                    secret, 0);

                recipientPublicKey = x25519Key.GetKey();
            }
            else
            {
                if (!(privKey.PublicKeyPacket.Key is X448PublicBcpgKey x448Key))
                    throw new PgpException("session key is for X448, but the key is not");

                var agreement = new X448Agreement();
                agreement.Init(privKey.Key);
                secret = new byte[agreement.AgreementSize];
                agreement.CalculateAgreement(new X448PublicKeyParameters(ephemeralPublicKey),
                    secret, 0);

                recipientPublicKey = x448Key.GetKey();
            }

            var key = Rfc9580Utilities.CreateKey(algorithm, ephemeralPublicKey, recipientPublicKey,
                secret);

            IWrapper wrapper = PgpUtilities.CreateWrapper(Rfc9580Utilities.KeyWrapAlgorithm(algorithm));
            wrapper.Init(forWrapping: false, key);

            return wrapper.Unwrap(wrapped, 0, wrapped.Length);
        }

        private static bool ConfirmCheckSum(byte[] sessionInfo)
        {
            int check = 0;

            for (int i = 1; i < sessionInfo.Length - 2; ++i)
            {
                check += sessionInfo[i];
            }

            return Pack.BE_To_UInt16(sessionInfo, sessionInfo.Length - 2) == (ushort)check;
        }

        private static void ProcessEncodedMpi(IBufferedCipher cipher, int size, byte[] mpiEnc)
        {
            if (mpiEnc.Length - 2 > size)  // leading Zero? Shouldn't happen but...
            {
                cipher.ProcessBytes(mpiEnc, 3, mpiEnc.Length - 3);
            }
            else
            {
                byte[] tmp = new byte[size];
                Array.Copy(mpiEnc, 2, tmp, tmp.Length - (mpiEnc.Length - 2), mpiEnc.Length - 2);
                cipher.ProcessBytes(tmp, 0, tmp.Length);
            }
        }
    }
}
