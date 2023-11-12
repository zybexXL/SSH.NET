namespace Renci.SshNet.Security.Cryptography.Ciphers.Paddings
{
    /// <summary>
    /// Implements PKCS5 cipher padding (same as PKCS7).
    /// </summary>
    public class PKCS5Padding : PKCS7Padding
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="PKCS5Padding"/> class.
        /// </summary>
        public PKCS5Padding()
            : base()
        {
        }
    }
}
