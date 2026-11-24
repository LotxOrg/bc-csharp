using System;
using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace Org.BouncyCastle.Tls.Tests
{
    /// <summary>
    /// What <see cref="AbstractTlsServer.NotifyHandshakeBeginning"/> has to clear before the next handshake on a reused
    /// server.
    /// </summary>
    /// <remarks>
    /// <see cref="AbstractTlsServer.ProcessClientExtensions(IDictionary{int, byte[]})"/> assigns "status_request_v2"
    /// and "trusted_ca_keys" only when the ClientHello carried extensions at all, so a field left standing from the
    /// previous handshake is a field the next one inherits. That matters because the server decides whether to echo
    /// from these fields: echoing an extension the client did not offer has it abort with unsupported_extension (RFC
    /// 5246 sec. 7.4.1.4). "status_request" was already cleared here; its two neighbours were not.
    /// </remarks>
    [TestFixture]
    public class AbstractTlsServerResetTest
    {
        [Test]
        public void StatusRequestExtensionsAreClearedBetweenHandshakes()
        {
            MockServer server = new MockServer();

            server.ProcessClientExtensions(CreateStatusRequestExtensions());

            Assert.NotNull(server.CertificateStatusRequest, "the test should have offered status_request");
            Assert.NotNull(server.StatusRequestV2, "the test should have offered status_request_v2");

            server.NotifyHandshakeBeginning();

            Assert.Null(server.CertificateStatusRequest, "status_request should not survive into the next handshake");
            Assert.Null(server.StatusRequestV2, "status_request_v2 should not survive into the next handshake");
        }

        [Test]
        public void TrustedCAKeysIsClearedBetweenHandshakes()
        {
            MockServer server = new MockServer();

            var clientExtensions = new Dictionary<int, byte[]>();
            TlsExtensionsUtilities.AddTrustedCAKeysExtensionClient(clientExtensions, new List<TrustedAuthority>());

            server.ProcessClientExtensions(clientExtensions);

            Assert.NotNull(server.TrustedCAKeys, "the test should have offered trusted_ca_keys");

            server.NotifyHandshakeBeginning();

            Assert.Null(server.TrustedCAKeys, "trusted_ca_keys should not survive into the next handshake");
        }

        /// <summary>
        /// The case the reset exists for: a second ClientHello with no extensions at all leaves
        /// <see cref="TlsServer.ProcessClientExtensions(IDictionary{int, byte[]})"/> with nothing to assign, so
        /// anything not cleared is still the first handshake's.
        /// </summary>
        [Test]
        public void ExtensionlessClientHelloInheritsNothing()
        {
            MockServer server = new MockServer();

            server.ProcessClientExtensions(CreateStatusRequestExtensions());

            server.NotifyHandshakeBeginning();
            server.ProcessClientExtensions(null);

            Assert.Null(server.StatusRequestV2, "an extensionless ClientHello must not inherit status_request_v2");
            Assert.Null(server.CertificateStatusRequest,
                "an extensionless ClientHello must not inherit status_request");
            Assert.Null(server.TrustedCAKeys, "an extensionless ClientHello must not inherit trusted_ca_keys");
        }

        private static Dictionary<int, byte[]> CreateStatusRequestExtensions()
        {
            OcspStatusRequest ocspStatusRequest = new OcspStatusRequest(null, null);

            var clientExtensions = new Dictionary<int, byte[]>();
            TlsExtensionsUtilities.AddStatusRequestExtension(clientExtensions,
                new CertificateStatusRequest(CertificateStatusType.ocsp, ocspStatusRequest));

            var statusRequestV2 = TlsUtilities.VectorOfOne(
                new CertificateStatusRequestItemV2(CertificateStatusType.ocsp_multi, ocspStatusRequest));
            TlsExtensionsUtilities.AddStatusRequestV2Extension(clientExtensions, statusRequestV2);

            return clientExtensions;
        }

        private class MockServer
            : AbstractTlsServer
        {
            internal MockServer()
                : base(new BcTlsCrypto())
            {
            }

            public override TlsCredentials GetCredentials() => throw new NotSupportedException();

            protected override int[] GetSupportedCipherSuites() => new int[]{ CipherSuite.TLS_AES_128_GCM_SHA256 };

            internal CertificateStatusRequest CertificateStatusRequest => m_certificateStatusRequest;

            internal IList<CertificateStatusRequestItemV2> StatusRequestV2 => m_statusRequestV2;

            internal IList<TrustedAuthority> TrustedCAKeys => m_trustedCAKeys;
        }
    }
}
