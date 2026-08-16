using System;

using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Math.EC.Rfc7748;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Hpke
{
    /// <summary>The five Diffie-Hellman KEMs registered by RFC 9180 section 7.1.</summary>
    internal sealed class HpkeDHKem
        : HpkeKem
    {
        private readonly short m_kemId;
        private readonly HpkeHkdf m_hkdf;
        private readonly IAsymmetricCipherKeyPairGenerator m_kpGen;
        private readonly IRawAgreement m_rawAgreement;
        private readonly ECDomainParameters m_domainParams;
        private readonly byte m_bitmask;
        private readonly int m_Nsk;
        private readonly int m_Nsecret;
        private readonly int m_Nenc;

        internal HpkeDHKem(short kemId)
        {
            m_kemId = kemId;

            switch (kemId)
            {
            case HpkeSuite.kem_P256_SHA256:
                m_hkdf = new HpkeHkdf(HpkeSuite.kdf_HKDF_SHA256);
                m_domainParams = GetDomainParameters("P-256");
                m_rawAgreement = new ECDhcRawAgreement();
                m_bitmask = 0xff;
                m_Nsk = 32;
                m_Nsecret = 32;
                m_Nenc = 65;
                m_kpGen = new ECKeyPairGenerator();
                m_kpGen.Init(new ECKeyGenerationParameters(m_domainParams, GetSecureRandom()));
                break;
            case HpkeSuite.kem_P384_SHA384:
                m_hkdf = new HpkeHkdf(HpkeSuite.kdf_HKDF_SHA384);
                m_domainParams = GetDomainParameters("P-384");
                m_rawAgreement = new ECDhcRawAgreement();
                m_bitmask = 0xff;
                m_Nsk = 48;
                m_Nsecret = 48;
                m_Nenc = 97;
                m_kpGen = new ECKeyPairGenerator();
                m_kpGen.Init(new ECKeyGenerationParameters(m_domainParams, GetSecureRandom()));
                break;
            case HpkeSuite.kem_P521_SHA512:
                m_hkdf = new HpkeHkdf(HpkeSuite.kdf_HKDF_SHA512);
                m_domainParams = GetDomainParameters("P-521");
                m_rawAgreement = new ECDhcRawAgreement();
                m_bitmask = 0x01;
                m_Nsk = 66;
                m_Nsecret = 64;
                m_Nenc = 133;
                m_kpGen = new ECKeyPairGenerator();
                m_kpGen.Init(new ECKeyGenerationParameters(m_domainParams, GetSecureRandom()));
                break;
            case HpkeSuite.kem_X25519_SHA256:
                m_hkdf = new HpkeHkdf(HpkeSuite.kdf_HKDF_SHA256);
                m_rawAgreement = new X25519Agreement();
                m_Nsecret = 32;
                m_Nsk = 32;
                m_Nenc = 32;
                m_kpGen = new X25519KeyPairGenerator();
                m_kpGen.Init(new X25519KeyGenerationParameters(GetSecureRandom()));
                break;
            case HpkeSuite.kem_X448_SHA512:
                m_hkdf = new HpkeHkdf(HpkeSuite.kdf_HKDF_SHA512);
                m_rawAgreement = new X448Agreement();
                m_Nsecret = 64;
                m_Nsk = 56;
                m_Nenc = 56;
                m_kpGen = new X448KeyPairGenerator();
                m_kpGen.Init(new X448KeyGenerationParameters(GetSecureRandom()));
                break;
            default:
                throw new ArgumentException("invalid kem id", nameof(kemId));
            }
        }

        internal override int EncryptionSize => m_Nenc;

        internal override byte[] SerializePublicKey(AsymmetricKeyParameter key)
        {
            switch (m_kemId)
            {
            case HpkeSuite.kem_P256_SHA256:
            case HpkeSuite.kem_P384_SHA384:
            case HpkeSuite.kem_P521_SHA512:
                return ((ECPublicKeyParameters)key).Q.GetEncoded(false);
            case HpkeSuite.kem_X448_SHA512:
                return ((X448PublicKeyParameters)key).GetEncoded();
            case HpkeSuite.kem_X25519_SHA256:
                return ((X25519PublicKeyParameters)key).GetEncoded();
            default:
                throw new InvalidOperationException("invalid kem id");
            }
        }

        internal override byte[] SerializePrivateKey(AsymmetricKeyParameter key)
        {
            switch (m_kemId)
            {
            case HpkeSuite.kem_P256_SHA256:
            case HpkeSuite.kem_P384_SHA384:
            case HpkeSuite.kem_P521_SHA512:
                return BigIntegers.AsUnsignedByteArray(m_Nsk, ((ECPrivateKeyParameters)key).D);
            case HpkeSuite.kem_X448_SHA512:
            {
                byte[] encoded = ((X448PrivateKeyParameters)key).GetEncoded();
                X448.ClampPrivateKey(encoded);
                return encoded;
            }
            case HpkeSuite.kem_X25519_SHA256:
            {
                byte[] encoded = ((X25519PrivateKeyParameters)key).GetEncoded();
                X25519.ClampPrivateKey(encoded);
                return encoded;
            }
            default:
                throw new InvalidOperationException("invalid kem id");
            }
        }

        internal override AsymmetricKeyParameter DeserializePublicKey(byte[] pkEncoded)
        {
            if (pkEncoded == null)
                throw new ArgumentNullException(nameof(pkEncoded));
            if (pkEncoded.Length != m_Nenc)
                throw new ArgumentException("'pkEncoded' has invalid length", nameof(pkEncoded));

            switch (m_kemId)
            {
            case HpkeSuite.kem_P256_SHA256:
            case HpkeSuite.kem_P384_SHA384:
            case HpkeSuite.kem_P521_SHA512:
            {
                // 0x04 is the marker for an uncompressed encoding.
                if (pkEncoded[0] != 0x04)
                    throw new ArgumentException("'pkEncoded' has invalid format", nameof(pkEncoded));

                ECPoint g = m_domainParams.Curve.DecodePoint(pkEncoded);
                return new ECPublicKeyParameters(g, m_domainParams);
            }
            case HpkeSuite.kem_X448_SHA512:
                return new X448PublicKeyParameters(pkEncoded);
            case HpkeSuite.kem_X25519_SHA256:
                return new X25519PublicKeyParameters(pkEncoded);
            default:
                throw new InvalidOperationException("invalid kem id");
            }
        }

        internal override AsymmetricCipherKeyPair DeserializePrivateKey(byte[] skEncoded, byte[] pkEncoded)
        {
            if (skEncoded == null)
                throw new ArgumentNullException(nameof(skEncoded));
            if (skEncoded.Length != m_Nsk)
                throw new ArgumentException("'skEncoded' has invalid length", nameof(skEncoded));

            AsymmetricKeyParameter pubParam = null;
            if (pkEncoded != null)
            {
                pubParam = DeserializePublicKey(pkEncoded);
            }

            switch (m_kemId)
            {
            case HpkeSuite.kem_P256_SHA256:
            case HpkeSuite.kem_P384_SHA384:
            case HpkeSuite.kem_P521_SHA512:
            {
                BigInteger d = new BigInteger(1, skEncoded);
                var ec = new ECPrivateKeyParameters(d, m_domainParams);
                if (pubParam == null)
                {
                    ECPoint q = new FixedPointCombMultiplier().Multiply(m_domainParams.G, ec.D);
                    pubParam = new ECPublicKeyParameters(q, m_domainParams);
                }
                return new AsymmetricCipherKeyPair(pubParam, ec);
            }
            case HpkeSuite.kem_X448_SHA512:
            {
                var x448 = new X448PrivateKeyParameters(skEncoded);
                if (pubParam == null)
                {
                    pubParam = x448.GeneratePublicKey();
                }
                return new AsymmetricCipherKeyPair(pubParam, x448);
            }
            case HpkeSuite.kem_X25519_SHA256:
            {
                var x25519 = new X25519PrivateKeyParameters(skEncoded);
                if (pubParam == null)
                {
                    pubParam = x25519.GeneratePublicKey();
                }
                return new AsymmetricCipherKeyPair(pubParam, x25519);
            }
            default:
                throw new InvalidOperationException("invalid kem id");
            }
        }

        internal override AsymmetricCipherKeyPair GeneratePrivateKey() => m_kpGen.GenerateKeyPair();

        internal override AsymmetricCipherKeyPair DeriveKeyPair(byte[] ikm)
        {
            byte[] suiteID = SuiteId();

            switch (m_kemId)
            {
            case HpkeSuite.kem_P256_SHA256:
            case HpkeSuite.kem_P384_SHA384:
            case HpkeSuite.kem_P521_SHA512:
            {
                byte[] dkpPrk = m_hkdf.LabeledExtract(null, suiteID, "dkp_prk", ikm);
                byte[] counterArray = new byte[1];
                for (int counter = 0; counter < 256; ++counter)
                {
                    counterArray[0] = (byte)counter;
                    byte[] bytes = m_hkdf.LabeledExpand(dkpPrk, suiteID, "candidate", counterArray, m_Nsk);
                    bytes[0] = (byte)(bytes[0] & m_bitmask);

                    BigInteger d = new BigInteger(1, bytes);
                    if (ValidateSk(d))
                    {
                        ECPoint q = new FixedPointCombMultiplier().Multiply(m_domainParams.G, d);
                        return new AsymmetricCipherKeyPair(
                            new ECPublicKeyParameters(q, m_domainParams),
                            new ECPrivateKeyParameters(d, m_domainParams));
                    }
                }
                throw new InvalidOperationException("DeriveKeyPairError");
            }
            case HpkeSuite.kem_X448_SHA512:
            {
                byte[] dkpPrk = m_hkdf.LabeledExtract(null, suiteID, "dkp_prk", ikm);
                byte[] skBytes = m_hkdf.LabeledExpand(dkpPrk, suiteID, "sk", null, m_Nsk);
                var sk = new X448PrivateKeyParameters(skBytes);
                return new AsymmetricCipherKeyPair(sk.GeneratePublicKey(), sk);
            }
            case HpkeSuite.kem_X25519_SHA256:
            {
                byte[] dkpPrk = m_hkdf.LabeledExtract(null, suiteID, "dkp_prk", ikm);
                byte[] skBytes = m_hkdf.LabeledExpand(dkpPrk, suiteID, "sk", null, m_Nsk);
                var sk = new X25519PrivateKeyParameters(skBytes);
                return new AsymmetricCipherKeyPair(sk.GeneratePublicKey(), sk);
            }
            default:
                throw new InvalidOperationException("invalid kem id");
            }
        }

        internal override byte[][] Encap(AsymmetricKeyParameter pkR) => Encap(pkR, m_kpGen.GenerateKeyPair());

        internal override byte[][] Encap(AsymmetricKeyParameter pkR, AsymmetricCipherKeyPair kpE)
        {
            byte[] secret = CalculateRawAgreement(m_rawAgreement, kpE.Private, pkR);
            byte[] enc = SerializePublicKey(kpE.Public);
            byte[] pkRm = SerializePublicKey(pkR);
            byte[] kemContext = Arrays.Concatenate(enc, pkRm);

            return new byte[][] { ExtractAndExpand(secret, kemContext), enc };
        }

        internal override byte[] Decap(byte[] enc, AsymmetricCipherKeyPair kpR)
        {
            AsymmetricKeyParameter pkE = DeserializePublicKey(enc);
            byte[] secret = CalculateRawAgreement(m_rawAgreement, kpR.Private, pkE);
            byte[] pkRm = SerializePublicKey(kpR.Public);
            byte[] kemContext = Arrays.Concatenate(enc, pkRm);

            return ExtractAndExpand(secret, kemContext);
        }

        internal override byte[][] AuthEncap(AsymmetricKeyParameter pkR, AsymmetricCipherKeyPair kpS)
        {
            AsymmetricCipherKeyPair kpE = m_kpGen.GenerateKeyPair();

            m_rawAgreement.Init(kpE.Private);
            int agreementSize = m_rawAgreement.AgreementSize;
            byte[] secret = new byte[agreementSize * 2];
            m_rawAgreement.CalculateAgreement(pkR, secret, 0);

            m_rawAgreement.Init(kpS.Private);
            if (agreementSize != m_rawAgreement.AgreementSize)
                throw new InvalidOperationException();

            m_rawAgreement.CalculateAgreement(pkR, secret, agreementSize);

            byte[] enc = SerializePublicKey(kpE.Public);
            byte[] pkRm = SerializePublicKey(pkR);
            byte[] pkSm = SerializePublicKey(kpS.Public);
            byte[] kemContext = Arrays.ConcatenateAll(enc, pkRm, pkSm);

            return new byte[][] { ExtractAndExpand(secret, kemContext), enc };
        }

        internal override byte[] AuthDecap(byte[] enc, AsymmetricCipherKeyPair kpR, AsymmetricKeyParameter pkS)
        {
            AsymmetricKeyParameter pkE = DeserializePublicKey(enc);

            m_rawAgreement.Init(kpR.Private);
            int agreementSize = m_rawAgreement.AgreementSize;
            byte[] secret = new byte[agreementSize * 2];
            m_rawAgreement.CalculateAgreement(pkE, secret, 0);
            m_rawAgreement.CalculateAgreement(pkS, secret, agreementSize);

            byte[] pkRm = SerializePublicKey(kpR.Public);
            byte[] pkSm = SerializePublicKey(pkS);
            byte[] kemContext = Arrays.ConcatenateAll(enc, pkRm, pkSm);

            return ExtractAndExpand(secret, kemContext);
        }

        private byte[] SuiteId()
        {
            byte[] kemIdBytes = new byte[2];
            Pack.UInt16_To_BE((ushort)m_kemId, kemIdBytes);

            return Arrays.Concatenate(Strings.ToByteArray("KEM"), kemIdBytes);
        }

        private byte[] ExtractAndExpand(byte[] dh, byte[] kemContext)
        {
            byte[] suiteID = SuiteId();
            byte[] eaePrk = m_hkdf.LabeledExtract(null, suiteID, "eae_prk", dh);

            return m_hkdf.LabeledExpand(eaePrk, suiteID, "shared_secret", kemContext, m_Nsecret);
        }

        private bool ValidateSk(BigInteger d)
        {
            BigInteger n = m_domainParams.N;
            int minWeight = n.BitLength >> 2;

            if (d.CompareTo(BigInteger.One) < 0 || d.CompareTo(n) >= 0)
                return false;

            return WNafUtilities.GetNafWeight(d) >= minWeight;
        }

        private static byte[] CalculateRawAgreement(IRawAgreement rawAgreement, AsymmetricKeyParameter privateKey,
            AsymmetricKeyParameter publicKey)
        {
            rawAgreement.Init(privateKey);
            byte[] z = new byte[rawAgreement.AgreementSize];
            rawAgreement.CalculateAgreement(publicKey, z, 0);

            return z;
        }

        private static ECDomainParameters GetDomainParameters(string curveName) =>
            new ECDomainParameters(CustomNamedCurves.GetByName(curveName));

        private static SecureRandom GetSecureRandom() => CryptoServicesRegistrar.GetSecureRandom();
    }
}
