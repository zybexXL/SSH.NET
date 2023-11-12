using System;
using Renci.SshNet.Security.Cryptography.Ciphers;

namespace Renci.SshNet.Security.Cryptography
{
    /// <summary>
    /// Base class for block cipher implementations.
    /// </summary>
    public abstract class BlockCipher : SymmetricCipher
    {
        private readonly CipherMode _mode;

        private readonly CipherPadding _padding;

        /// <summary>
        /// Gets the size of the block in bytes.
        /// </summary>
        /// <value>
        /// The size of the block in bytes.
        /// </value>
        private readonly byte _blockSize;

        /// <summary>
        /// Gets the minimum data size.
        /// </summary>
        /// <value>
        /// The minimum data size.
        /// </value>
        public override byte MinimumSize
        {
            get { return BlockSize; }
        }

        /// <summary>
        /// Gets the size of the block.
        /// </summary>
        /// <value>
        /// The size of the block.
        /// </value>
        public byte BlockSize
        {
            get
            {
                return _blockSize;
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="BlockCipher"/> class.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="blockSize">Size of the block.</param>
        /// <param name="mode">Cipher mode.</param>
        /// <param name="padding">Cipher padding.</param>
        /// <exception cref="ArgumentNullException"><paramref name="key"/> is <see langword="null"/>.</exception>
        protected BlockCipher(byte[] key, byte blockSize, CipherMode mode, CipherPadding padding)
            : base(key)
        {
            _blockSize = blockSize;
            _mode = mode;
            _padding = padding;

            _mode?.Init(this);
        }

        /// <summary>
        /// Encrypts the specified data.
        /// </summary>
        /// <param name="input">The data.</param>
        /// <param name="offset">The zero-based offset in <paramref name="input"/> at which to begin encrypting.</param>
        /// <param name="length">The number of bytes to encrypt from <paramref name="input"/>.</param>
        /// <returns>
        /// The encrypted data.
        /// </returns>
        public override byte[] Encrypt(byte[] input, int offset, int length)
        {
            if (_padding is not null)
            {
                // padding always changes the array size, even if it's already block-aligned
                var paddingLength = _blockSize - (length % _blockSize);
                input = _padding.Pad(input, offset, length, paddingLength);
                length += paddingLength;
                offset = 0;
            }

            var output = new byte[length];
            var writtenBytes = 0;

            for (var i = offset; i < length; i += _blockSize)
            {
                var count = Math.Min(_blockSize, length - i);
                if (_mode is null)
                {
                    writtenBytes += EncryptBlock(input, i, count, output, i - offset);
                }
                else
                {
                    writtenBytes += _mode.EncryptBlock(input, i, count, output, i - offset);
                }
            }

            if (writtenBytes < length)
            {
                throw new InvalidOperationException("Encryption error.");
            }

            return output;
        }

        /// <summary>
        /// Decrypts the specified data.
        /// </summary>
        /// <param name="input">The data.</param>
        /// <returns>
        /// The decrypted data.
        /// </returns>
        public override byte[] Decrypt(byte[] input)
        {
            return Decrypt(input, 0, input.Length);
        }

        /// <summary>
        /// Decrypts the specified input.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <param name="offset">The zero-based offset in <paramref name="input"/> at which to begin decrypting.</param>
        /// <param name="length">The number of bytes to decrypt from <paramref name="input"/>.</param>
        /// <returns>
        /// The decrypted data.
        /// </returns>
        public override byte[] Decrypt(byte[] input, int offset, int length)
        {
            var output = new byte[length];
            var writtenBytes = 0;
            for (var i = offset; i < length; i += _blockSize)
            {
                var count = Math.Min(_blockSize, length - i);
                if (_mode is null)
                {
                    writtenBytes += DecryptBlock(input, i, count, output, i - offset);
                }
                else
                {
                    writtenBytes += _mode.DecryptBlock(input, i, count, output, i - offset);
                }
            }

            if (writtenBytes < length)
            {
                throw new InvalidOperationException("Encryption error.");
            }

            // remove Padding (if padding enabled)
            _padding?.Unpad(ref output);

            return output;
        }
    }
}
