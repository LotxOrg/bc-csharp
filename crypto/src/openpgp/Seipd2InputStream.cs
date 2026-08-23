using System;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>
    /// Reads the body of a version 2 SEIPD packet, verifying each chunk before any of it is handed
    /// on and the final tag before the stream reports its end.
    /// </summary>
    /// <remarks>
    /// Nothing here ever returns plaintext that has not been authenticated. A chunk is decrypted
    /// whole, so a failed tag throws before a single octet of it escapes, and the tag that closes
    /// the packet covers the total length, so a ciphertext cut short is refused rather than read as
    /// a shorter message.
    /// <para>
    /// The packet does not say how many chunks it holds, and the last chunk may be shorter than the
    /// rest, so the reader keeps one tag's worth of lookahead: while a full chunk and something
    /// beyond it are in hand, that chunk is complete; once the underlying stream ends, whatever
    /// remains is the last chunk followed by the final tag.
    /// </para>
    /// </remarks>
    internal sealed class Seipd2InputStream
        : BaseInputStream
    {
        private readonly Stream m_in;
        private readonly SymmetricKeyAlgorithmTag m_cipherAlgorithm;
        private readonly AeadAlgorithmTag m_aeadAlgorithm;
        private readonly byte[] m_aaData;
        private readonly KeyParameter m_messageKey;
        private readonly byte[] m_iv;
        private readonly int m_tagLength;
        private readonly int m_chunkLength;

        private readonly byte[] m_buf;
        private int m_bufLength = 0;

        private byte[] m_plaintext = null;
        private int m_plaintextPos = 0;
        private int m_plaintextLength = 0;

        private long m_chunkIndex = 0;
        private long m_totalPlaintextLength = 0;
        private bool m_finished = false;

        internal Seipd2InputStream(Stream inStr, SymmetricKeyAlgorithmTag cipherAlgorithm,
            AeadAlgorithmTag aeadAlgorithm, int chunkSizeOctet, byte[] sessionKey, byte[] salt)
        {
            m_in = inStr ?? throw new ArgumentNullException(nameof(inStr));
            m_cipherAlgorithm = cipherAlgorithm;
            m_aeadAlgorithm = aeadAlgorithm;
            m_aaData = SymmetricEncIntegrityPacket.CreateAAData(SymmetricEncIntegrityPacket.Version2,
                cipherAlgorithm, aeadAlgorithm, chunkSizeOctet);

            Seipd2Utilities.DeriveMessageKeyAndIV(sessionKey, salt, m_aaData, cipherAlgorithm, aeadAlgorithm,
                out m_messageKey, out m_iv);

            m_tagLength = AeadUtilities.GetAuthTagLength(aeadAlgorithm);
            m_chunkLength = Seipd2Utilities.ChunkLength(chunkSizeOctet);

            m_buf = new byte[m_chunkLength + 2 * m_tagLength];
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            Streams.ValidateBufferArguments(buffer, offset, count);

            if (count < 1)
                return 0;

            if (!EnsurePlaintext())
                return 0;

            int take = System.Math.Min(count, m_plaintextLength - m_plaintextPos);
            Array.Copy(m_plaintext, m_plaintextPos, buffer, offset, take);
            m_plaintextPos += take;
            return take;
        }

        public override int ReadByte()
        {
            if (!EnsurePlaintext())
                return -1;

            return m_plaintext[m_plaintextPos++];
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <remarks>
        /// Overridden because the base class reads a span an octet at a time, and this is the
        /// overload <see cref="Stream.CopyTo(Stream)"/> uses.
        /// </remarks>
        public override int Read(Span<byte> buffer)
        {
            if (buffer.Length < 1)
                return 0;

            if (!EnsurePlaintext())
                return 0;

            int take = System.Math.Min(buffer.Length, m_plaintextLength - m_plaintextPos);
            m_plaintext.AsSpan(m_plaintextPos, take).CopyTo(buffer);
            m_plaintextPos += take;
            return take;
        }
#endif

        /// <summary>
        /// Make sure an unread octet of verified plaintext is waiting, decrypting the next chunk if
        /// the last one has run out. False once the packet has ended and its final tag has been
        /// checked.
        /// </summary>
        private bool EnsurePlaintext()
        {
            while (m_plaintext == null || m_plaintextPos >= m_plaintextLength)
            {
                if (m_finished)
                    return false;

                ReadChunk();
            }

            return true;
        }

        private void ReadChunk()
        {
            FillBuffer();

            if (m_bufLength < m_tagLength)
                throw new PgpException("truncated v2 SEIPD packet: no final tag");

            // A full buffer means at least one octet beyond a whole chunk is in hand, so that chunk
            // is complete and cannot be the last. Anything short of a full buffer means the
            // underlying stream has ended, and what is left is the last chunk, if any, followed by
            // the final tag.
            bool atEnd = m_bufLength < m_buf.Length;

            int chunkDataLength = atEnd ? m_bufLength - m_tagLength : m_chunkLength + m_tagLength;

            if (atEnd && chunkDataLength > 0 && chunkDataLength < m_tagLength)
                throw new PgpException("truncated v2 SEIPD packet: incomplete chunk");

            if (chunkDataLength > 0)
            {
                DecryptChunk(chunkDataLength);
                Consume(chunkDataLength);
            }
            else
            {
                m_plaintext = null;
                m_plaintextPos = 0;
                m_plaintextLength = 0;
            }

            if (atEnd)
            {
                VerifyFinalTag();
            }
        }

        private void FillBuffer()
        {
            while (m_bufLength < m_buf.Length)
            {
                int read = m_in.Read(m_buf, m_bufLength, m_buf.Length - m_bufLength);
                if (read < 1)
                    break;

                m_bufLength += read;
            }
        }

        private void DecryptChunk(int chunkDataLength)
        {
            byte[] nonce = Seipd2Utilities.CreateNonce(m_iv, m_chunkIndex);

            IAeadCipher cipher = Seipd2Utilities.CreateAeadCipher(m_cipherAlgorithm, m_aeadAlgorithm,
                m_messageKey, nonce, m_aaData, forEncryption: false);

            byte[] output = new byte[cipher.GetOutputSize(chunkDataLength)];

            int outputLength;
            try
            {
                outputLength = cipher.ProcessBytes(m_buf, 0, chunkDataLength, output, 0);
                outputLength += cipher.DoFinal(output, outputLength);
            }
            catch (InvalidCipherTextException e)
            {
                Arrays.ZeroMemory(output);
                throw new PgpDataValidationException("v2 SEIPD chunk " + m_chunkIndex + " failed authentication", e);
            }

            m_plaintext = output;
            m_plaintextPos = 0;
            m_plaintextLength = outputLength;

            m_totalPlaintextLength += outputLength;
            m_chunkIndex++;
        }

        private void Consume(int length)
        {
            Array.Copy(m_buf, length, m_buf, 0, m_bufLength - length);
            m_bufLength -= length;
        }

        private void VerifyFinalTag()
        {
            byte[] nonce = Seipd2Utilities.CreateNonce(m_iv, m_chunkIndex);
            byte[] finalAAData = Seipd2Utilities.CreateFinalAAData(m_aaData, m_totalPlaintextLength);

            IAeadCipher cipher = Seipd2Utilities.CreateAeadCipher(m_cipherAlgorithm, m_aeadAlgorithm,
                m_messageKey, nonce, finalAAData, forEncryption: false);

            byte[] output = new byte[cipher.GetOutputSize(m_tagLength)];

            try
            {
                int outputLength = cipher.ProcessBytes(m_buf, 0, m_tagLength, output, 0);
                cipher.DoFinal(output, outputLength);
            }
            catch (InvalidCipherTextException e)
            {
                throw new PgpDataValidationException(
                    "v2 SEIPD final tag failed authentication; the ciphertext may have been truncated", e);
            }

            m_bufLength = 0;
            m_finished = true;

            Arrays.ZeroMemory(m_iv);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                Arrays.ZeroMemory(m_buf);

                if (m_plaintext != null)
                {
                    Arrays.ZeroMemory(m_plaintext);
                }
            }

            base.Dispose(disposing);
        }
    }
}
