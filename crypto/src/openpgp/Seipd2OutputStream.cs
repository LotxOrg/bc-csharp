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
    /// Writes the body of a version 2 SEIPD packet: the plaintext divided into chunks, each
    /// encrypted and authenticated on its own, and then a tag over the total length.
    /// </summary>
    /// <remarks>
    /// The packet header, up to and including the salt, is written by the caller before this stream
    /// is created; it is also what the additional data and the derived key are computed from, so
    /// the two cannot disagree.
    /// </remarks>
    internal sealed class Seipd2OutputStream
        : BaseOutputStream
    {
        private readonly Stream m_out;
        private readonly SymmetricKeyAlgorithmTag m_cipherAlgorithm;
        private readonly AeadAlgorithmTag m_aeadAlgorithm;
        private readonly byte[] m_aaData;
        private readonly KeyParameter m_messageKey;
        private readonly byte[] m_iv;
        private readonly byte[] m_chunk;

        private int m_chunkPos = 0;
        private long m_chunkIndex = 0;
        private long m_totalPlaintextLength = 0;
        private bool m_closed = false;

        internal Seipd2OutputStream(Stream outStr, SymmetricKeyAlgorithmTag cipherAlgorithm,
            AeadAlgorithmTag aeadAlgorithm, int chunkSizeOctet, byte[] sessionKey, byte[] salt)
        {
            m_out = outStr ?? throw new ArgumentNullException(nameof(outStr));
            m_cipherAlgorithm = cipherAlgorithm;
            m_aeadAlgorithm = aeadAlgorithm;
            m_aaData = SymmetricEncIntegrityPacket.CreateAAData(SymmetricEncIntegrityPacket.Version2,
                cipherAlgorithm, aeadAlgorithm, chunkSizeOctet);

            Seipd2Utilities.DeriveMessageKeyAndIV(sessionKey, salt, m_aaData, cipherAlgorithm, aeadAlgorithm,
                out m_messageKey, out m_iv);

            m_chunk = new byte[Seipd2Utilities.ChunkLength(chunkSizeOctet)];
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            Streams.ValidateBufferArguments(buffer, offset, count);

            if (m_closed)
                throw new ObjectDisposedException(nameof(Seipd2OutputStream));

            while (count > 0)
            {
                int available = m_chunk.Length - m_chunkPos;
                int take = System.Math.Min(available, count);

                Array.Copy(buffer, offset, m_chunk, m_chunkPos, take);
                m_chunkPos += take;
                offset += take;
                count -= take;

                if (m_chunkPos == m_chunk.Length)
                {
                    WriteChunk();
                }
            }
        }

        public override void WriteByte(byte value)
        {
            if (m_closed)
                throw new ObjectDisposedException(nameof(Seipd2OutputStream));

            m_chunk[m_chunkPos++] = value;

            if (m_chunkPos == m_chunk.Length)
            {
                WriteChunk();
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <remarks>
        /// Overridden because the base class writes a span an octet at a time, and this is the
        /// overload <see cref="Stream.CopyTo(Stream)"/> uses.
        /// </remarks>
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            if (m_closed)
                throw new ObjectDisposedException(nameof(Seipd2OutputStream));

            while (!buffer.IsEmpty)
            {
                int available = m_chunk.Length - m_chunkPos;
                int take = System.Math.Min(available, buffer.Length);

                buffer[..take].CopyTo(m_chunk.AsSpan(m_chunkPos));
                m_chunkPos += take;
                buffer = buffer[take..];

                if (m_chunkPos == m_chunk.Length)
                {
                    WriteChunk();
                }
            }
        }
#endif

        protected override void Dispose(bool disposing)
        {
            if (disposing && !m_closed)
            {
                m_closed = true;

                try
                {
                    // A chunk is only written when it holds something. An empty plaintext therefore
                    // produces no chunks at all, and the final tag alone attests to its length.
                    if (m_chunkPos > 0)
                    {
                        WriteChunk();
                    }

                    WriteFinalTag();
                }
                finally
                {
                    Arrays.ZeroMemory(m_chunk);
                    Arrays.ZeroMemory(m_iv);
                }
            }

            base.Dispose(disposing);
        }

        private void WriteChunk()
        {
            byte[] nonce = Seipd2Utilities.CreateNonce(m_iv, m_chunkIndex);

            IAeadCipher cipher = Seipd2Utilities.CreateAeadCipher(m_cipherAlgorithm, m_aeadAlgorithm,
                m_messageKey, nonce, m_aaData, forEncryption: true);

            byte[] output = new byte[cipher.GetOutputSize(m_chunkPos)];
            int outputLength = cipher.ProcessBytes(m_chunk, 0, m_chunkPos, output, 0);
            outputLength += cipher.DoFinal(output, outputLength);

            m_out.Write(output, 0, outputLength);

            m_totalPlaintextLength += m_chunkPos;
            m_chunkPos = 0;
            m_chunkIndex++;
        }

        private void WriteFinalTag()
        {
            byte[] nonce = Seipd2Utilities.CreateNonce(m_iv, m_chunkIndex);
            byte[] finalAAData = Seipd2Utilities.CreateFinalAAData(m_aaData, m_totalPlaintextLength);

            IAeadCipher cipher = Seipd2Utilities.CreateAeadCipher(m_cipherAlgorithm, m_aeadAlgorithm,
                m_messageKey, nonce, finalAAData, forEncryption: true);

            byte[] tag = new byte[cipher.GetOutputSize(0)];
            int tagLength = cipher.DoFinal(tag, 0);

            m_out.Write(tag, 0, tagLength);
        }
    }
}
