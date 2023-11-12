using System;

namespace Renci.SshNet.Security.Cryptography.Ciphers.Paddings
{
    /// <summary>
    /// Implements PKCS7 cipher padding.
    /// </summary>
    public class PKCS7Padding : CipherPadding
    {
        /// <summary>
        /// Pads the specified input to match the block size.
        /// </summary>
        /// <param name="blockSize">The size of the block.</param>
        /// <param name="input">The input.</param>
        /// <param name="offset">The zero-based offset in <paramref name="input"/> at which the data to pad starts.</param>
        /// <param name="length">The number of bytes in <paramref name="input"/> to take into account.</param>
        /// <returns>
        /// The padded data array.
        /// </returns>
        public override byte[] Pad(int blockSize, byte[] input, int offset, int length)
        {
            var numOfPaddedBytes = blockSize - (length % blockSize);
            return Pad(input, offset, length, numOfPaddedBytes);
        }

        /// <summary>
        /// Pads the specified input with a given number of bytes.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <param name="offset">The zero-based offset in <paramref name="input"/> at which the data to pad starts.</param>
        /// <param name="length">The number of bytes in <paramref name="input"/> to take into account.</param>
        /// <param name="paddinglength">The number of bytes to pad the input with.</param>
        /// <returns>
        /// The padded data array.
        /// </returns>
        public override byte[] Pad(byte[] input, int offset, int length, int paddinglength)
        {
            var output = new byte[length + paddinglength];
            Buffer.BlockCopy(input, offset, output, 0, length);

            for (var i = 0; i < paddinglength; i++)
            {
                output[length + i] = (byte) paddinglength;
            }

            return output;
        }

        /// <summary>
        /// Removes padding by resizing the array.
        /// </summary>
        /// <param name="data">The output of a Cipher operation.</param>
        public override void Unpad(ref byte[] data)
        {
            var paddinglength = data[data.Length - 1];
            var newSize = data.Length - paddinglength;
            if (paddinglength > 0 && newSize > 0)
            {
                Array.Resize(ref data, newSize);
            }
        }

        /// <summary>
        /// Removes padding.
        /// </summary>
        /// <param name="data">The output of a Cipher operation.</param>
        /// <returns>The unpadded data array.</returns>
        public override byte[] Unpad(byte[] data)
        {
            var paddinglength = data[data.Length - 1];
            var newSize = data.Length - paddinglength;
            if (paddinglength > 0 && newSize > 0)
            {
                var output = new byte[newSize];
                Buffer.BlockCopy(data, 0, output, 0, newSize);
                return output;
            }

            return data;
        }
    }
}
