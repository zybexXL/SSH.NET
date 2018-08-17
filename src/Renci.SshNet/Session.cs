using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Renci.SshNet.Channels;
using Renci.SshNet.Common;
using Renci.SshNet.Compression;
using Renci.SshNet.Messages;
using Renci.SshNet.Messages.Authentication;
using Renci.SshNet.Messages.Connection;
using Renci.SshNet.Messages.Transport;
using Renci.SshNet.Security;
using System.Globalization;
using System.Linq;
using Renci.SshNet.Abstractions;
using Renci.SshNet.Security.Cryptography;

namespace Renci.SshNet
{
    /// <summary>
    /// Provides functionality to connect and interact with SSH server.
    /// </summary>
    public class Session : ISession
    {
        private const byte Null = 0x00;
        internal const byte CarriageReturn = 0x0d;
        internal const byte LineFeed = 0x0a;

        /// <summary>
        /// Specifies an infinite waiting period.
        /// </summary>
        /// <remarks>
        /// The value of this field is <c>-1</c> millisecond.
        /// </remarks>
        internal static readonly TimeSpan InfiniteTimeSpan = new TimeSpan(0, 0, 0, 0, -1);

        /// <summary>
        /// Specifies an infinite waiting period.
        /// </summary>
        /// <remarks>
        /// The value of this field is <c>-1</c>.
        /// </remarks>
        internal static readonly int Infinite = -1;

        /// <summary>
        /// Holds the initial local window size for the channels.
        /// </summary>
        /// <value>
        /// 2147483647 (2^31 - 1) bytes.
        /// </value>
        /// <remarks>
        /// We currently do not define a maximum (remote) window size.
        /// </remarks>
        private const int InitialLocalWindowSize = 0x7FFFFFFF;

        /// <summary>
        /// Holds the maximum size of channel data packets that we receive.
        /// </summary>
        /// <value>
        /// 64 KB.
        /// </value>
        /// <remarks>
        /// <para>
        /// This is the maximum size (in bytes) we support for the data (payload) of a
        /// <c>SSH_MSG_CHANNEL_DATA</c> message we receive.
        /// </para>
        /// <para>
        /// We currently do not enforce this limit.
        /// </para>
        /// </remarks>
        private const int LocalChannelDataPacketSize = 1024*64;

        /// <summary>
        /// Specifies maximum packet size defined by the protocol.
        /// </summary>
        /// <value>
        /// 68536 (64 KB + 3000 bytes).
        /// </value>
        internal const int MaximumSshPacketSize = LocalChannelDataPacketSize + 3000;

#if FEATURE_REGEX_COMPILE
        internal static readonly Regex ServerVersionRe = new Regex("^SSH-(?<protoversion>[^-]+)-(?<softwareversion>.+)( SP.+)?$", RegexOptions.Compiled);
#else
        internal static readonly Regex ServerVersionRe = new Regex("^SSH-(?<protoversion>[^-]+)-(?<softwareversion>.+)( SP.+)?$");
#endif

        /// <summary>
        /// Controls how many authentication attempts can take place at the same time.
        /// </summary>
        /// <remarks>
        /// Some server may restrict number to prevent authentication attacks
        /// </remarks>
        private static readonly SemaphoreLight AuthenticationConnection = new SemaphoreLight(3);

        /// <summary>
        /// Holds metada about session messages
        /// </summary>
        private SshMessageFactory _sshMessageFactory;

        /// <summary>
        /// Holds a <see cref="WaitHandle"/> that is signaled when the message listener loop has completed.
        /// </summary>
        private EventWaitHandle _messageListenerCompleted;

        /// <summary>
        /// WaitHandle to signal that last service request was accepted
        /// </summary>
        private EventWaitHandle _serviceAccepted = new AutoResetEvent(false);

        /// <summary>
        /// WaitHandle to signal that exception was thrown by another thread.
        /// </summary>
        private EventWaitHandle _exceptionWaitHandle = new ManualResetEvent(false);

        /// <summary>
        /// WaitHandle to signal that key exchange was completed.
        /// </summary>
        private EventWaitHandle _keyExchangeCompletedWaitHandle = new ManualResetEvent(false);

        /// <summary>
        /// WaitHandle to signal that key exchange is in progress.
        /// </summary>
        private bool _keyExchangeInProgress;

        /// <summary>
        /// Exception that need to be thrown by waiting thread
        /// </summary>
        private Exception _exception;

        /// <summary>
        /// Specifies whether connection is authenticated
        /// </summary>
        private bool _isAuthenticated;

        /// <summary>
        /// Specifies whether user issued Disconnect command or not
        /// </summary>
        private bool _isDisconnecting;

        private IKeyExchange _keyExchange;

        internal HashAlgorithm ServerMac { get; private set; }

        internal HashAlgorithm ClientMac { get; private set; }

        internal Cipher ClientCipher { get; private set; }

        internal Cipher ServerCipher { get; private set; }

        internal Compressor ServerDecompression { get; private set; }

        internal Compressor ClientCompression { get; private set; }

        private SemaphoreLight _sessionSemaphore;

        /// <summary>
        /// Holds the factory to use for creating new services.
        /// </summary>
        private readonly IServiceFactory _serviceFactory;

        /// <summary>
        /// Holds connection socket.
        /// </summary>
        private Socket _socket;

        private AsyncMessageListener _messageListener;

        /// <summary>
        /// Gets the session semaphore that controls session channels.
        /// </summary>
        /// <value>
        /// The session semaphore.
        /// </value>
        public SemaphoreLight SessionSemaphore
        {
            get
            {
                if (_sessionSemaphore == null)
                {
                    lock (this)
                    {
                        if (_sessionSemaphore == null)
                        {
                            _sessionSemaphore = new SemaphoreLight(ConnectionInfo.MaxSessions);
                        }
                    }
                }

                return _sessionSemaphore;
            }
        }

        private bool _isDisconnectMessageSent;

        private uint _nextChannelNumber;

        /// <summary>
        /// Gets the next channel number.
        /// </summary>
        /// <value>
        /// The next channel number.
        /// </value>
        private uint NextChannelNumber
        {
            get
            {
                uint result;

                lock (this)
                {
                    result = _nextChannelNumber++;
                }

                return result;
            }
        }

        /// <summary>
        /// Gets a value indicating whether the session is connected.
        /// </summary>
        /// <value>
        /// <c>true</c> if the session is connected; otherwise, <c>false</c>.
        /// </value>
        /// <remarks>
        /// This methods returns <c>true</c> in all but the following cases:
        /// <list type="bullet">
        ///     <item>
        ///         <description>The <see cref="Session"/> is disposed.</description>
        ///     </item>
        ///     <item>
        ///         <description>The <c>SSH_MSG_DISCONNECT</c> message - which is used to disconnect from the server - has been sent.</description>
        ///     </item>
        ///     <item>
        ///         <description>The client has not been authenticated successfully.</description>
        ///     </item>
        ///     <item>
        ///         <description>The listener thread - which is used to receive messages from the server - has stopped.</description>
        ///     </item>
        ///     <item>
        ///         <description>The socket used to communicate with the server is no longer connected.</description>
        ///     </item>
        /// </list>
        /// </remarks>
        public bool IsConnected
        {
            get
            {
                if (_disposed || _isDisconnectMessageSent || !_isAuthenticated)
                    return false;
                if (_messageListenerCompleted == null || _messageListenerCompleted.WaitOne(0))
                    return false;

                return _messageListener != null && _messageListener.IsConnected;
            }
        }

        /// <summary>
        /// Gets the session id.
        /// </summary>
        /// <value>
        /// The session id, or <c>null</c> if the client has not been authenticated.
        /// </value>
        public byte[] SessionId { get; private set; }

        private Message _clientInitMessage;

        /// <summary>
        /// Gets the client init message.
        /// </summary>
        /// <value>The client init message.</value>
        public Message ClientInitMessage
        {
            get
            {
                if (_clientInitMessage == null)
                {
                    _clientInitMessage = new KeyExchangeInitMessage
                        {
                            KeyExchangeAlgorithms = ConnectionInfo.KeyExchangeAlgorithms.Keys.ToArray(),
                            ServerHostKeyAlgorithms = ConnectionInfo.HostKeyAlgorithms.Keys.ToArray(),
                            EncryptionAlgorithmsClientToServer = ConnectionInfo.Encryptions.Keys.ToArray(),
                            EncryptionAlgorithmsServerToClient = ConnectionInfo.Encryptions.Keys.ToArray(),
                            MacAlgorithmsClientToServer = ConnectionInfo.HmacAlgorithms.Keys.ToArray(),
                            MacAlgorithmsServerToClient = ConnectionInfo.HmacAlgorithms.Keys.ToArray(),
                            CompressionAlgorithmsClientToServer = ConnectionInfo.CompressionAlgorithms.Keys.ToArray(),
                            CompressionAlgorithmsServerToClient = ConnectionInfo.CompressionAlgorithms.Keys.ToArray(),
                            LanguagesClientToServer = new[] {string.Empty},
                            LanguagesServerToClient = new[] {string.Empty},
                            FirstKexPacketFollows = false,
                            Reserved = 0
                        };
                }
                return _clientInitMessage;
            }
        }

        /// <summary>
        /// Gets or sets the server version string.
        /// </summary>
        /// <value>The server version.</value>
        public string ServerVersion
        {
            get { return ConnectionInfo.ServerVersion; }
        }

        /// <summary>
        /// Gets or sets the client version string.
        /// </summary>
        /// <value>The client version.</value>
        public string ClientVersion { get; private set; }

        /// <summary>
        /// Gets or sets the connection info.
        /// </summary>
        /// <value>The connection info.</value>
        public ConnectionInfo ConnectionInfo { get; private set; }

        /// <summary>
        /// Occurs when an error occurred.
        /// </summary>
        public event EventHandler<ExceptionEventArgs> ErrorOccured;

        /// <summary>
        /// Occurs when session has been disconnected from the server.
        /// </summary>
        public event EventHandler<EventArgs> Disconnected;

        /// <summary>
        /// Occurs when host key received.
        /// </summary>
        public event EventHandler<HostKeyEventArgs> HostKeyReceived;

        /// <summary>
        /// Occurs when <see cref="BannerMessage"/> message is received from the server.
        /// </summary>
        public event EventHandler<MessageEventArgs<BannerMessage>> UserAuthenticationBannerReceived;

        /// <summary>
        /// Occurs when <see cref="InformationRequestMessage"/> message is received from the server.
        /// </summary>
        internal event EventHandler<MessageEventArgs<InformationRequestMessage>> UserAuthenticationInformationRequestReceived;

        /// <summary>
        /// Occurs when <see cref="PasswordChangeRequiredMessage"/> message is received from the server.
        /// </summary>
        internal event EventHandler<MessageEventArgs<PasswordChangeRequiredMessage>> UserAuthenticationPasswordChangeRequiredReceived;

        /// <summary>
        /// Occurs when <see cref="PublicKeyMessage"/> message is received from the server.
        /// </summary>
        internal event EventHandler<MessageEventArgs<PublicKeyMessage>> UserAuthenticationPublicKeyReceived;

        /// <summary>
        /// Occurs when <see cref="KeyExchangeDhGroupExchangeGroup"/> message is received from the server.
        /// </summary>
        internal event EventHandler<MessageEventArgs<KeyExchangeDhGroupExchangeGroup>> KeyExchangeDhGroupExchangeGroupReceived;

        /// <summary>
        /// Occurs when <see cref="KeyExchangeDhGroupExchangeReply"/> message is received from the server.
        /// </summary>
        internal event EventHandler<MessageEventArgs<KeyExchangeDhGroupExchangeReply>> KeyExchangeDhGroupExchangeReplyReceived;

        #region Message events

        /// <summary>
        /// Occurs when <see cref="DisconnectMessage"/> message received
        /// </summary>
        internal event EventHandler<MessageEventArgs<DisconnectMessage>> DisconnectReceived;

        /// <summary>
        /// Occurs when <see cref="IgnoreMessage"/> message received
        /// </summary>
        internal event EventHandler<MessageEventArgs<IgnoreMessage>> IgnoreReceived;

        /// <summary>
        /// Occurs when <see cref="UnimplementedMessage"/> message received
        /// </summary>
        internal event EventHandler<MessageEventArgs<UnimplementedMessage>> UnimplementedReceived;

        /// <summary>
        /// Occurs when <see cref="DebugMessage"/> message received
        /// </summary>
        internal event EventHandler<MessageEventArgs<DebugMessage>> DebugReceived;

        /// <summary>
        /// Occurs when <see cref="ServiceRequestMessage"/> message received
        /// </summary>
        internal event EventHandler<MessageEventArgs<ServiceRequestMessage>> ServiceRequestReceived;

        /// <summary>
        /// Occurs when <see cref="ServiceAcceptMessage"/> message received
        /// </summary>
        internal event EventHandler<MessageEventArgs<ServiceAcceptMessage>> ServiceAcceptReceived;

        /// <summary>
        /// Occurs when <see cref="KeyExchangeInitMessage"/> message received
        /// </summary>
        internal event EventHandler<MessageEventArgs<KeyExchangeInitMessage>> KeyExchangeInitReceived;

        /// <summary>
        /// Occurs when a <see cref="KeyExchangeDhReplyMessage"/> message is received from the SSH server.
        /// </summary>
        internal event EventHandler<MessageEventArgs<KeyExchangeDhReplyMessage>> KeyExchangeDhReplyMessageReceived;

        /// <summary>
        /// Occurs when <see cref="NewKeysMessage"/> message received
        /// </summary>
        internal event EventHandler<MessageEventArgs<NewKeysMessage>> NewKeysReceived;

        /// <summary>
        /// Occurs when <see cref="RequestMessage"/> message received
        /// </summary>
        internal event EventHandler<MessageEventArgs<RequestMessage>> UserAuthenticationRequestReceived;

        /// <summary>
        /// Occurs when <see cref="FailureMessage"/> message received
        /// </summary>
        internal event EventHandler<MessageEventArgs<FailureMessage>> UserAuthenticationFailureReceived;

        /// <summary>
        /// Occurs when <see cref="SuccessMessage"/> message received
        /// </summary>
        internal event EventHandler<MessageEventArgs<SuccessMessage>> UserAuthenticationSuccessReceived;

        /// <summary>
        /// Occurs when <see cref="GlobalRequestMessage"/> message received
        /// </summary>
        internal event EventHandler<MessageEventArgs<GlobalRequestMessage>> GlobalRequestReceived;

        /// <summary>
        /// Occurs when <see cref="RequestSuccessMessage"/> message received
        /// </summary>
        public event EventHandler<MessageEventArgs<RequestSuccessMessage>> RequestSuccessReceived;

        /// <summary>
        /// Occurs when <see cref="RequestFailureMessage"/> message received
        /// </summary>
        public event EventHandler<MessageEventArgs<RequestFailureMessage>> RequestFailureReceived;

        /// <summary>
        /// Occurs when <see cref="ChannelOpenMessage"/> message received
        /// </summary>
        public event EventHandler<MessageEventArgs<ChannelOpenMessage>> ChannelOpenReceived;

        /// <summary>
        /// Occurs when <see cref="ChannelOpenConfirmationMessage"/> message received
        /// </summary>
        public event EventHandler<MessageEventArgs<ChannelOpenConfirmationMessage>> ChannelOpenConfirmationReceived;

        /// <summary>
        /// Occurs when <see cref="ChannelOpenFailureMessage"/> message received
        /// </summary>
        public event EventHandler<MessageEventArgs<ChannelOpenFailureMessage>> ChannelOpenFailureReceived;

        /// <summary>
        /// Occurs when <see cref="ChannelWindowAdjustMessage"/> message received
        /// </summary>
        public event EventHandler<MessageEventArgs<ChannelWindowAdjustMessage>> ChannelWindowAdjustReceived;

        /// <summary>
        /// Occurs when <see cref="ChannelDataMessage"/> message received
        /// </summary>
        public event EventHandler<MessageEventArgs<ChannelDataMessage>> ChannelDataReceived;

        /// <summary>
        /// Occurs when <see cref="ChannelExtendedDataMessage"/> message received
        /// </summary>
        public event EventHandler<MessageEventArgs<ChannelExtendedDataMessage>> ChannelExtendedDataReceived;

        /// <summary>
        /// Occurs when <see cref="ChannelEofMessage"/> message received
        /// </summary>
        public event EventHandler<MessageEventArgs<ChannelEofMessage>> ChannelEofReceived;

        /// <summary>
        /// Occurs when <see cref="ChannelCloseMessage"/> message received
        /// </summary>
        public event EventHandler<MessageEventArgs<ChannelCloseMessage>> ChannelCloseReceived;

        /// <summary>
        /// Occurs when <see cref="ChannelRequestMessage"/> message received
        /// </summary>
        public event EventHandler<MessageEventArgs<ChannelRequestMessage>> ChannelRequestReceived;

        /// <summary>
        /// Occurs when <see cref="ChannelSuccessMessage"/> message received
        /// </summary>
        public event EventHandler<MessageEventArgs<ChannelSuccessMessage>> ChannelSuccessReceived;

        /// <summary>
        /// Occurs when <see cref="ChannelFailureMessage"/> message received
        /// </summary>
        public event EventHandler<MessageEventArgs<ChannelFailureMessage>> ChannelFailureReceived;

        #endregion

        /// <summary>
        /// Initializes a new instance of the <see cref="Session"/> class.
        /// </summary>
        /// <param name="connectionInfo">The connection info.</param>
        /// <param name="serviceFactory">The factory to use for creating new services.</param>
        /// <exception cref="ArgumentNullException"><paramref name="connectionInfo"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentNullException"><paramref name="serviceFactory"/> is <c>null</c>.</exception>
        internal Session(ConnectionInfo connectionInfo, IServiceFactory serviceFactory)
        {
            if (connectionInfo == null)
                throw new ArgumentNullException("connectionInfo");
            if (serviceFactory == null)
                throw new ArgumentNullException("serviceFactory");

            ClientVersion = "SSH-2.0-Renci.SshNet.SshClient.0.0.1";
            ConnectionInfo = connectionInfo;
            _serviceFactory = serviceFactory;
            _messageListenerCompleted = new ManualResetEvent(true);
        }

        /// <summary>
        /// Connects to the server.
        /// </summary>
        /// <exception cref="SocketException">Socket connection to the SSH server or proxy server could not be established, or an error occurred while resolving the hostname.</exception>
        /// <exception cref="SshConnectionException">SSH session could not be established.</exception>
        /// <exception cref="SshAuthenticationException">Authentication of SSH session failed.</exception>
        /// <exception cref="ProxyException">Failed to establish proxy connection.</exception>
        public void Connect()
        {
            if (IsConnected)
                return;

            try
            {
                AuthenticationConnection.Wait();

                if (IsConnected)
                    return;

                lock (this)
                {
                    //  If connected don't connect again
                    if (IsConnected)
                        return;

                    // reset connection specific information
                    Reset();

                    //  Build list of available messages while connecting
                    _sshMessageFactory = new SshMessageFactory();

                    switch (ConnectionInfo.ProxyType)
                    {
                        case ProxyTypes.None:
                            SocketConnect(ConnectionInfo.Host, ConnectionInfo.Port);
                            break;
                        case ProxyTypes.Socks4:
                            SocketConnect(ConnectionInfo.ProxyHost, ConnectionInfo.ProxyPort);
                            ConnectSocks4();
                            break;
                        case ProxyTypes.Socks5:
                            SocketConnect(ConnectionInfo.ProxyHost, ConnectionInfo.ProxyPort);
                            ConnectSocks5();
                            break;
                        case ProxyTypes.Http:
                            SocketConnect(ConnectionInfo.ProxyHost, ConnectionInfo.ProxyPort);
                            ConnectHttp();
                            break;
                    }

                    // TODO: only mark as started when we now for sure the listener is started

                    // mark the message listener threads as started
                    _messageListenerCompleted.Reset();

                    _messageListener = new AsyncMessageListener(this, _socket, LoadMessage);
                    _messageListener.Start();
                    _messageListener.Closed += (sender, args) =>  _messageListenerCompleted.Set();
                    _messageListener.Error += (sender, args) =>
                        {
                            _messageListenerCompleted.Set();

                            DiagnosticAbstraction.Log(string.Format("[{0}] Raised exception: {1}", ToHex(SessionId), args.Exception));

                            var connectionException = args.Exception as SshConnectionException;

                            if (_isDisconnecting)
                            {
                                //  a connection exception which is raised while isDisconnecting is normal and
                                //  should be ignored
                                if (connectionException != null)
                                    return;

                                // any timeout while disconnecting can be caused by loss of connectivity
                                // altogether and should be ignored
                                var socketException = args.Exception as SocketException;
                                if (socketException != null && socketException.SocketErrorCode == SocketError.TimedOut)
                                    return;
                            }

                            // "save" exception and set exception wait handle to ensure any waits are interrupted
                            _exception = args.Exception;
                            _exceptionWaitHandle.Set();

                            var errorOccured = ErrorOccured;
                            if (errorOccured != null)
                                errorOccured(this, new ExceptionEventArgs(args.Exception));

                            if (connectionException != null)
                            {
                                DiagnosticAbstraction.Log(string.Format("[{0}] Disconnecting after exception: {1}", ToHex(SessionId), args.Exception));
                                Disconnect(connectionException.DisconnectReason, args.Exception.ToString());
                            }
                        };
                    _messageListener.ServerIdentified += (sender, args) =>
                        {
                            ConnectionInfo.ServerVersion = args.ServerIdentification;

                            DiagnosticAbstraction.Log(string.Format("Server version '{0}' on '{1}'.", args.ProtocolVersion, args.SoftwareName));

                            if (args.ProtocolVersion != "2.0" && args.ProtocolVersion != "1.99")
                            {
                                _exception = new SshConnectionException(string.Format(CultureInfo.CurrentCulture, "Server version '{0}' is not supported.", args.ProtocolVersion), DisconnectReason.ProtocolVersionNotSupported);
                                _exceptionWaitHandle.Set();
                                return;
                            }

                            // Register Transport response messages
                            RegisterMessage("SSH_MSG_DISCONNECT");
                            RegisterMessage("SSH_MSG_IGNORE");
                            RegisterMessage("SSH_MSG_UNIMPLEMENTED");
                            RegisterMessage("SSH_MSG_DEBUG");
                            RegisterMessage("SSH_MSG_SERVICE_ACCEPT");
                            RegisterMessage("SSH_MSG_KEXINIT");
                            RegisterMessage("SSH_MSG_NEWKEYS");

                            //  Some server implementations might sent this message first, prior establishing encryption algorithm
                            RegisterMessage("SSH_MSG_USERAUTH_BANNER");

                            _messageListener.SendClientIdentification(ClientVersion);
                        };

                    //  Wait for key exchange to be completed
                    WaitOnHandle(_keyExchangeCompletedWaitHandle);

                    //  If sessionId is not set then its not connected
                    if (SessionId == null)
                    {
                        Disconnect();
                        return;
                    }

                    //  Request user authorization service
                    SendMessage(new ServiceRequestMessage(ServiceName.UserAuthentication));

                    //  Wait for service to be accepted
                    WaitOnHandle(_serviceAccepted);

                    if (string.IsNullOrEmpty(ConnectionInfo.Username))
                    {
                        throw new SshException("Username is not specified.");
                    }

                    // Some servers send a global request immediately after successful authentication
                    // Avoid race condition by already enabling SSH_MSG_GLOBAL_REQUEST before authentication
                    RegisterMessage("SSH_MSG_GLOBAL_REQUEST");

                    ConnectionInfo.Authenticate(this, _serviceFactory);
                    _isAuthenticated = true;

                    //  Register Connection messages
                    RegisterMessage("SSH_MSG_REQUEST_SUCCESS");
                    RegisterMessage("SSH_MSG_REQUEST_FAILURE");
                    RegisterMessage("SSH_MSG_CHANNEL_OPEN_CONFIRMATION");
                    RegisterMessage("SSH_MSG_CHANNEL_OPEN_FAILURE");
                    RegisterMessage("SSH_MSG_CHANNEL_WINDOW_ADJUST");
                    RegisterMessage("SSH_MSG_CHANNEL_EXTENDED_DATA");
                    RegisterMessage("SSH_MSG_CHANNEL_REQUEST");
                    RegisterMessage("SSH_MSG_CHANNEL_SUCCESS");
                    RegisterMessage("SSH_MSG_CHANNEL_FAILURE");
                    RegisterMessage("SSH_MSG_CHANNEL_DATA");
                    RegisterMessage("SSH_MSG_CHANNEL_EOF");
                    RegisterMessage("SSH_MSG_CHANNEL_CLOSE");
                }
            }
            finally
            {
                AuthenticationConnection.Release();
            }
        }

        /// <summary>
        /// Disconnects from the server.
        /// </summary>
        /// <remarks>
        /// This sends a <b>SSH_MSG_DISCONNECT</b> message to the server, waits for the
        /// server to close the socket on its end and subsequently closes the client socket.
        /// </remarks>
        public void Disconnect()
        {
            DiagnosticAbstraction.Log(string.Format("[{0}] Disconnecting session.", ToHex(SessionId)));

            // send SSH_MSG_DISCONNECT message, clear socket read buffer and dispose it
            Disconnect(DisconnectReason.ByApplication, "Connection terminated by the client.");

            // at this point, we are sure that the listener thread will stop as we've
            // disconnected the socket, so lets wait until the message listener thread
            // has completed
            if (_messageListenerCompleted != null)
            {
                _messageListenerCompleted.WaitOne();
            }
        }

        private void Disconnect(DisconnectReason reason, string message)
        {
            // transition to disconnecting state to avoid throwing exceptions while cleaning up, and to
            // ensure any exceptions that are raised do not overwrite the exception that is set
            _isDisconnecting = true;

            // send disconnect message to the server if the connection is still open
            // and the disconnect message has not yet been sent
            //
            // note that this should also cause the listener loop to be interrupted as
            // the server should respond by closing the socket
            if (IsConnected)
            {
                TrySendDisconnect(reason, message);

                if (_messageListenerCompleted.WaitOne(300))
                {
                    return;
                }
            }

            // disconnect socket, and dispose it
            if (_messageListener != null)
            {
                Console.WriteLine("DISPOSE");
                _messageListener.Dispose();
            }
        }

        /// <summary>
        /// Waits for the specified handle or the exception handle for the receive thread
        /// to signal within the connection timeout.
        /// </summary>
        /// <param name="waitHandle">The wait handle.</param>
        /// <exception cref="SshConnectionException">A received package was invalid or failed the message integrity check.</exception>
        /// <exception cref="SshOperationTimeoutException">None of the handles are signaled in time and the session is not disconnecting.</exception>
        /// <exception cref="SocketException">A socket error was signaled while receiving messages from the server.</exception>
        /// <remarks>
        /// When neither handles are signaled in time and the session is not closing, then the
        /// session is disconnected.
        /// </remarks>
        void ISession.WaitOnHandle(WaitHandle waitHandle)
        {
            WaitOnHandle(waitHandle, ConnectionInfo.Timeout);
        }

        /// <summary>
        /// Waits for the specified handle or the exception handle for the receive thread
        /// to signal within the specified timeout.
        /// </summary>
        /// <param name="waitHandle">The wait handle.</param>
        /// <param name="timeout">The time to wait for any of the handles to become signaled.</param>
        /// <exception cref="SshConnectionException">A received package was invalid or failed the message integrity check.</exception>
        /// <exception cref="SshOperationTimeoutException">None of the handles are signaled in time and the session is not disconnecting.</exception>
        /// <exception cref="SocketException">A socket error was signaled while receiving messages from the server.</exception>
        /// <remarks>
        /// When neither handles are signaled in time and the session is not closing, then the
        /// session is disconnected.
        /// </remarks>
        void ISession.WaitOnHandle(WaitHandle waitHandle, TimeSpan timeout)
        {
            WaitOnHandle(waitHandle, timeout);
        }

        /// <summary>
        /// Waits for the specified handle or the exception handle for the receive thread
        /// to signal within the connection timeout.
        /// </summary>
        /// <param name="waitHandle">The wait handle.</param>
        /// <exception cref="SshConnectionException">A received package was invalid or failed the message integrity check.</exception>
        /// <exception cref="SshOperationTimeoutException">None of the handles are signaled in time and the session is not disconnecting.</exception>
        /// <exception cref="SocketException">A socket error was signaled while receiving messages from the server.</exception>
        /// <remarks>
        /// When neither handles are signaled in time and the session is not closing, then the
        /// session is disconnected.
        /// </remarks>
        internal void WaitOnHandle(WaitHandle waitHandle)
        {
            WaitOnHandle(waitHandle, ConnectionInfo.Timeout);
        }

        /// <summary>
        /// Waits for the specified <seec ref="WaitHandle"/> to receive a signal, using a <see cref="TimeSpan"/>
        /// to specify the time interval.
        /// </summary>
        /// <param name="waitHandle">The <see cref="WaitHandle"/> that should be signaled.</param>
        /// <param name="timeout">A <see cref="TimeSpan"/> that represents the number of milliseconds to wait, or a <see cref="TimeSpan"/> that represents <c>-1</c> milliseconds to wait indefinitely.</param>
        /// <returns>
        /// A <see cref="WaitResult"/>.
        /// </returns>
        WaitResult ISession.TryWait(WaitHandle waitHandle, TimeSpan timeout)
        {
            Exception exception;
            return TryWait(waitHandle, timeout, out exception);
        }

        /// <summary>
        /// Waits for the specified <seec ref="WaitHandle"/> to receive a signal, using a <see cref="TimeSpan"/>
        /// to specify the time interval.
        /// </summary>
        /// <param name="waitHandle">The <see cref="WaitHandle"/> that should be signaled.</param>
        /// <param name="timeout">A <see cref="TimeSpan"/> that represents the number of milliseconds to wait, or a <see cref="TimeSpan"/> that represents <c>-1</c> milliseconds to wait indefinitely.</param>
        /// <param name="exception">When this method returns <see cref="WaitResult.Failed"/>, contains the <see cref="Exception"/>.</param>
        /// <returns>
        /// A <see cref="WaitResult"/>.
        /// </returns>
        WaitResult ISession.TryWait(WaitHandle waitHandle, TimeSpan timeout, out Exception exception)
        {
            return TryWait(waitHandle, timeout, out exception);
        }

        /// <summary>
        /// Waits for the specified <seec ref="WaitHandle"/> to receive a signal, using a <see cref="TimeSpan"/>
        /// to specify the time interval.
        /// </summary>
        /// <param name="waitHandle">The <see cref="WaitHandle"/> that should be signaled.</param>
        /// <param name="timeout">A <see cref="TimeSpan"/> that represents the number of milliseconds to wait, or a <see cref="TimeSpan"/> that represents <c>-1</c> milliseconds to wait indefinitely.</param>
        /// <param name="exception">When this method returns <see cref="WaitResult.Failed"/>, contains the <see cref="Exception"/>.</param>
        /// <returns>
        /// A <see cref="WaitResult"/>.
        /// </returns>
        private WaitResult TryWait(WaitHandle waitHandle, TimeSpan timeout, out Exception exception)
        {
            if (waitHandle == null)
                throw new ArgumentNullException("waitHandle");

            var waitHandles = new[]
                {
                    _exceptionWaitHandle,
                    _messageListenerCompleted,
                    waitHandle
                };

            switch (WaitHandle.WaitAny(waitHandles, timeout))
            {
                case 0:
                    if (_exception is SshConnectionException)
                    {
                        exception = null;
                        return WaitResult.Disconnected;
                    }
                    exception = _exception;
                    return WaitResult.Failed;
                case 1:
                    exception = null;
                    return WaitResult.Disconnected;
                case 2:
                    exception = null;
                    return WaitResult.Success;
                case WaitHandle.WaitTimeout:
                    exception = null;
                    return WaitResult.TimedOut;
                default:
                    throw new InvalidOperationException("Unexpected result.");
            }
        }

        /// <summary>
        /// Waits for the specified handle or the exception handle for the receive thread
        /// to signal within the specified timeout.
        /// </summary>
        /// <param name="waitHandle">The wait handle.</param>
        /// <param name="timeout">The time to wait for any of the handles to become signaled.</param>
        /// <exception cref="SshConnectionException">A received package was invalid or failed the message integrity check.</exception>
        /// <exception cref="SshOperationTimeoutException">None of the handles are signaled in time and the session is not disconnecting.</exception>
        /// <exception cref="SocketException">A socket error was signaled while receiving messages from the server.</exception>
        internal void WaitOnHandle(WaitHandle waitHandle, TimeSpan timeout)
        {
            if (waitHandle == null)
                throw new ArgumentNullException("waitHandle");

            var waitHandles = new[]
                {
                    _exceptionWaitHandle,
                    _messageListenerCompleted,
                    waitHandle
                };

            switch (WaitHandle.WaitAny(waitHandles, timeout))
            {
                case 0:
                    throw _exception;
                case 1:
                    throw new SshConnectionException("Client not connected.");
                case WaitHandle.WaitTimeout:
                    // when the session is disconnecting, a timeout is likely when no
                    // network connectivity is available; depending on the configured
                    // timeout either the WaitAny times out first or a SocketException
                    // detailing a timeout thrown hereby completing the listener thread
                    // (which makes us end up in case 1). Either way, we do not want to
                    // report an exception to the client when we're disconnecting anyway
                    if (!_isDisconnecting)
                    {
                        throw new SshOperationTimeoutException("Session operation has timed out");
                    }
                    break;
            }
        }

        /// <summary>
        /// Sends a message to the server.
        /// </summary>
        /// <param name="message">The message to send.</param>
        /// <exception cref="SshConnectionException">The client is not connected.</exception>
        /// <exception cref="SshOperationTimeoutException">The operation timed out.</exception>
        /// <exception cref="InvalidOperationException">The size of the packet exceeds the maximum size defined by the protocol.</exception>
        internal void SendMessage(Message message)
        {
            if (!_socket.CanWrite())
                throw new SshConnectionException("Client not connected.");

            if (_keyExchangeInProgress && !(message is IKeyExchangedAllowed))
            {
                //  Wait for key exchange to be completed
                WaitOnHandle(_keyExchangeCompletedWaitHandle);
            }

            _messageListener.SendMessage(message);
        }

        /// <summary>
        /// Sends a message to the server.
        /// </summary>
        /// <param name="message">The message to send.</param>
        /// <returns>
        /// <c>true</c> if the message was sent to the server; otherwise, <c>false</c>.
        /// </returns>
        /// <exception cref="InvalidOperationException">The size of the packet exceeds the maximum size defined by the protocol.</exception>
        /// <remarks>
        /// This methods returns <c>false</c> when the attempt to send the message results in a
        /// <see cref="SocketException"/> or a <see cref="SshException"/>.
        /// </remarks>
        private bool TrySendMessage(Message message)
        {
            try
            {
                SendMessage(message);
                return true;
            }
            catch (SshException ex)
            {
                DiagnosticAbstraction.Log(string.Format("Failure sending message '{0}' to server: '{1}' => {2}", message.GetType().Name, message, ex));
                return false;
            }
            catch (SocketException ex)
            {
                DiagnosticAbstraction.Log(string.Format("Failure sending message '{0}' to server: '{1}' => {2}", message.GetType().Name, message, ex));
                return false;
            }
        }

        private void TrySendDisconnect(DisconnectReason reasonCode, string message)
        {
            var disconnectMessage = new DisconnectMessage(reasonCode, message);

            // send the disconnect message, but ignore the outcome
            TrySendMessage(disconnectMessage);

            // mark disconnect message sent regardless of whether the send sctually succeeded
            _isDisconnectMessageSent = true;
        }

        #region Handle received message events

        /// <summary>
        /// Called when <see cref="DisconnectMessage"/> received.
        /// </summary>
        /// <param name="message"><see cref="DisconnectMessage"/> message.</param>
        internal void OnDisconnectReceived(DisconnectMessage message)
        {
            DiagnosticAbstraction.Log(string.Format("[{0}] Disconnect received: {1} {2}.", ToHex(SessionId), message.ReasonCode, message.Description));

            // transition to disconnecting state to avoid throwing exceptions while cleaning up, and to
            // ensure any exceptions that are raised do not overwrite the SshConnectionException that we
            // set below
            _isDisconnecting = true;

            _exception = new SshConnectionException(string.Format(CultureInfo.InvariantCulture, "The connection was closed by the server: {0} ({1}).", message.Description, message.ReasonCode), message.ReasonCode);
            _exceptionWaitHandle.Set();

            var disconnectReceived = DisconnectReceived;
            if (disconnectReceived != null)
                disconnectReceived(this, new MessageEventArgs<DisconnectMessage>(message));

            var disconnected = Disconnected;
            if (disconnected != null)
                disconnected(this, new EventArgs());

            // disconnect socket, and dispose it
            _messageListener.Dispose();
        }

        /// <summary>
        /// Called when <see cref="IgnoreMessage"/> received.
        /// </summary>
        /// <param name="message"><see cref="IgnoreMessage"/> message.</param>
        internal void OnIgnoreReceived(IgnoreMessage message)
        {
            var handlers = IgnoreReceived;
            if (handlers != null)
                handlers(this, new MessageEventArgs<IgnoreMessage>(message));
        }

        /// <summary>
        /// Called when <see cref="UnimplementedMessage"/> message received.
        /// </summary>
        /// <param name="message"><see cref="UnimplementedMessage"/> message.</param>
        internal void OnUnimplementedReceived(UnimplementedMessage message)
        {
            var handlers = UnimplementedReceived;
            if (handlers != null)
                handlers(this, new MessageEventArgs<UnimplementedMessage>(message));
        }

        /// <summary>
        /// Called when <see cref="DebugMessage"/> message received.
        /// </summary>
        /// <param name="message"><see cref="DebugMessage"/> message.</param>
        internal void OnDebugReceived(DebugMessage message)
        {
            var handlers = DebugReceived;
            if (handlers != null)
                handlers(this, new MessageEventArgs<DebugMessage>(message));
        }

        /// <summary>
        /// Called when <see cref="ServiceRequestMessage"/> message received.
        /// </summary>
        /// <param name="message"><see cref="ServiceRequestMessage"/> message.</param>
        internal void OnServiceRequestReceived(ServiceRequestMessage message)
        {
            var handlers = ServiceRequestReceived;
            if (handlers != null)
                handlers(this, new MessageEventArgs<ServiceRequestMessage>(message));
        }

        /// <summary>
        /// Called when <see cref="ServiceAcceptMessage"/> message received.
        /// </summary>
        /// <param name="message"><see cref="ServiceAcceptMessage"/> message.</param>
        internal void OnServiceAcceptReceived(ServiceAcceptMessage message)
        {
            var handlers = ServiceAcceptReceived;
            if (handlers != null)
                handlers(this, new MessageEventArgs<ServiceAcceptMessage>(message));

            _serviceAccepted.Set();
        }

        internal void OnKeyExchangeDhGroupExchangeGroupReceived(KeyExchangeDhGroupExchangeGroup message)
        {
            var handlers = KeyExchangeDhGroupExchangeGroupReceived;
            if (handlers != null)
                handlers(this, new MessageEventArgs<KeyExchangeDhGroupExchangeGroup>(message));
        }

        internal void OnKeyExchangeDhGroupExchangeReplyReceived(KeyExchangeDhGroupExchangeReply message)
        {
            var handlers = KeyExchangeDhGroupExchangeReplyReceived;
            if (handlers != null)
                handlers(this, new MessageEventArgs<KeyExchangeDhGroupExchangeReply>(message));
        }

        /// <summary>
        /// Called when <see cref="KeyExchangeInitMessage"/> message received.
        /// </summary>
        /// <param name="message"><see cref="KeyExchangeInitMessage"/> message.</param>
        internal void OnKeyExchangeInitReceived(KeyExchangeInitMessage message)
        {
            _keyExchangeInProgress = true;

            _keyExchangeCompletedWaitHandle.Reset();

            // Disable messages that are not key exchange related
            _sshMessageFactory.DisableNonKeyExchangeMessages();

            _keyExchange = _serviceFactory.CreateKeyExchange(ConnectionInfo.KeyExchangeAlgorithms,
                                                             message.KeyExchangeAlgorithms);

            ConnectionInfo.CurrentKeyExchangeAlgorithm = _keyExchange.Name;

            _keyExchange.HostKeyReceived += KeyExchange_HostKeyReceived;

            //  Start the algorithm implementation
            _keyExchange.Start(this, message);

            var keyExchangeInitReceived = KeyExchangeInitReceived;
            if (keyExchangeInitReceived != null)
                keyExchangeInitReceived(this, new MessageEventArgs<KeyExchangeInitMessage>(message));
        }

        internal void OnKeyExchangeDhReplyMessageReceived(KeyExchangeDhReplyMessage message)
        {
            var handlers = KeyExchangeDhReplyMessageReceived;
            if (handlers != null)
                handlers(this, new MessageEventArgs<KeyExchangeDhReplyMessage>(message));
        }

        /// <summary>
        /// Called when <see cref="NewKeysMessage"/> message received.
        /// </summary>
        /// <param name="message"><see cref="NewKeysMessage"/> message.</param>
        internal void OnNewKeysReceived(NewKeysMessage message)
        {
            //  Update sessionId
            if (SessionId == null)
            {
                SessionId = _keyExchange.ExchangeHash;
            }

            //  Dispose of old ciphers and hash algorithms
            if (ServerMac != null)
            {
                ServerMac.Dispose();
                ServerMac = null;
            }

            if (ClientMac != null)
            {
                ClientMac.Dispose();
                ClientMac = null;
            }

            //  Update negotiated algorithms
            ServerCipher = _keyExchange.CreateServerCipher();
            ServerMac = _keyExchange.CreateServerHash();
            ServerDecompression = _keyExchange.CreateDecompressor();

            ClientCipher = _keyExchange.CreateClientCipher();
            ClientMac = _keyExchange.CreateClientHash();
            ClientCompression = _keyExchange.CreateCompressor();

            //  Dispose of old KeyExchange object as it is no longer needed.
            if (_keyExchange != null)
            {
                _keyExchange.HostKeyReceived -= KeyExchange_HostKeyReceived;
                _keyExchange.Dispose();
                _keyExchange = null;
            }

            // Enable activated messages that are not key exchange related
            _sshMessageFactory.EnableActivatedMessages();

            var newKeysReceived = NewKeysReceived;
            if (newKeysReceived != null)
                newKeysReceived(this, new MessageEventArgs<NewKeysMessage>(message));

            //  Signal that key exchange completed
            _keyExchangeCompletedWaitHandle.Set();

            _keyExchangeInProgress = false;
        }

        /// <summary>
        /// Called when client is disconnecting from the server.
        /// </summary>
        void ISession.OnDisconnecting()
        {
            _isDisconnecting = true;
        }

        /// <summary>
        /// Called when <see cref="RequestMessage"/> message received.
        /// </summary>
        /// <param name="message"><see cref="RequestMessage"/> message.</param>
        internal void OnUserAuthenticationRequestReceived(RequestMessage message)
        {
            var handlers = UserAuthenticationRequestReceived;
            if (handlers != null)
                handlers(this, new MessageEventArgs<RequestMessage>(message));
        }

        /// <summary>
        /// Called when <see cref="FailureMessage"/> message received.
        /// </summary>
        /// <param name="message"><see cref="FailureMessage"/> message.</param>
        internal void OnUserAuthenticationFailureReceived(FailureMessage message)
        {
            var handlers = UserAuthenticationFailureReceived;
            if (handlers != null)
                handlers(this, new MessageEventArgs<FailureMessage>(message));
        }

        /// <summary>
        /// Called when <see cref="SuccessMessage"/> message received.
        /// </summary>
        /// <param name="message"><see cref="SuccessMessage"/> message.</param>
        internal void OnUserAuthenticationSuccessReceived(SuccessMessage message)
        {
            var handlers = UserAuthenticationSuccessReceived;
            if (handlers != null)
                handlers(this, new MessageEventArgs<SuccessMessage>(message));
        }

        /// <summary>
        /// Called when <see cref="BannerMessage"/> message received.
        /// </summary>
        /// <param name="message"><see cref="BannerMessage"/> message.</param>
        internal void OnUserAuthenticationBannerReceived(BannerMessage message)
        {
            var handlers = UserAuthenticationBannerReceived;
            if (handlers != null)
                handlers(this, new MessageEventArgs<BannerMessage>(message));
        }


        /// <summary>
        /// Called when <see cref="InformationRequestMessage"/> message received.
        /// </summary>
        /// <param name="message"><see cref="InformationRequestMessage"/> message.</param>
        internal void OnUserAuthenticationInformationRequestReceived(InformationRequestMessage message)
        {
            var handlers = UserAuthenticationInformationRequestReceived;
            if (handlers != null)
                handlers(this, new MessageEventArgs<InformationRequestMessage>(message));
        }

        internal void OnUserAuthenticationPasswordChangeRequiredReceived(PasswordChangeRequiredMessage message)
        {
            var handlers = UserAuthenticationPasswordChangeRequiredReceived;
            if (handlers != null)
                handlers(this, new MessageEventArgs<PasswordChangeRequiredMessage>(message));
        }

        internal void OnUserAuthenticationPublicKeyReceived(PublicKeyMessage message)
        {
            var handlers = UserAuthenticationPublicKeyReceived;
            if (handlers != null)
                handlers(this, new MessageEventArgs<PublicKeyMessage>(message));
        }

        /// <summary>
        /// Called when <see cref="GlobalRequestMessage"/> message received.
        /// </summary>
        /// <param name="message"><see cref="GlobalRequestMessage"/> message.</param>
        internal void OnGlobalRequestReceived(GlobalRequestMessage message)
        {
            var handlers = GlobalRequestReceived;
            if (handlers != null)
                handlers(this, new MessageEventArgs<GlobalRequestMessage>(message));
        }

        /// <summary>
        /// Called when <see cref="RequestSuccessMessage"/> message received.
        /// </summary>
        /// <param name="message"><see cref="RequestSuccessMessage"/> message.</param>
        internal void OnRequestSuccessReceived(RequestSuccessMessage message)
        {
            var handlers = RequestSuccessReceived;
            if (handlers != null)
                handlers(this, new MessageEventArgs<RequestSuccessMessage>(message));
        }

        /// <summary>
        /// Called when <see cref="RequestFailureMessage"/> message received.
        /// </summary>
        /// <param name="message"><see cref="RequestFailureMessage"/> message.</param>
        internal void OnRequestFailureReceived(RequestFailureMessage message)
        {
            var handlers = RequestFailureReceived;
            if (handlers != null)
                handlers(this, new MessageEventArgs<RequestFailureMessage>(message));
        }

        /// <summary>
        /// Called when <see cref="ChannelOpenMessage"/> message received.
        /// </summary>
        /// <param name="message"><see cref="ChannelOpenMessage"/> message.</param>
        internal void OnChannelOpenReceived(ChannelOpenMessage message)
        {
            var handlers = ChannelOpenReceived;
            if (handlers != null)
                handlers(this, new MessageEventArgs<ChannelOpenMessage>(message));
        }

        /// <summary>
        /// Called when <see cref="ChannelOpenConfirmationMessage"/> message received.
        /// </summary>
        /// <param name="message"><see cref="ChannelOpenConfirmationMessage"/> message.</param>
        internal void OnChannelOpenConfirmationReceived(ChannelOpenConfirmationMessage message)
        {
            var handlers = ChannelOpenConfirmationReceived;
            if (handlers != null)
                handlers(this, new MessageEventArgs<ChannelOpenConfirmationMessage>(message));
        }

        /// <summary>
        /// Called when <see cref="ChannelOpenFailureMessage"/> message received.
        /// </summary>
        /// <param name="message"><see cref="ChannelOpenFailureMessage"/> message.</param>
        internal void OnChannelOpenFailureReceived(ChannelOpenFailureMessage message)
        {
            var handlers = ChannelOpenFailureReceived;
            if (handlers != null)
                handlers(this, new MessageEventArgs<ChannelOpenFailureMessage>(message));
        }

        /// <summary>
        /// Called when <see cref="ChannelWindowAdjustMessage"/> message received.
        /// </summary>
        /// <param name="message"><see cref="ChannelWindowAdjustMessage"/> message.</param>
        internal void OnChannelWindowAdjustReceived(ChannelWindowAdjustMessage message)
        {
            var handlers = ChannelWindowAdjustReceived;
            if (handlers != null)
                handlers(this, new MessageEventArgs<ChannelWindowAdjustMessage>(message));
        }

        /// <summary>
        /// Called when <see cref="ChannelDataMessage"/> message received.
        /// </summary>
        /// <param name="message"><see cref="ChannelDataMessage"/> message.</param>
        internal void OnChannelDataReceived(ChannelDataMessage message)
        {
            var handlers = ChannelDataReceived;
            if (handlers != null)
                handlers(this, new MessageEventArgs<ChannelDataMessage>(message));
        }

        /// <summary>
        /// Called when <see cref="ChannelExtendedDataMessage"/> message received.
        /// </summary>
        /// <param name="message"><see cref="ChannelExtendedDataMessage"/> message.</param>
        internal void OnChannelExtendedDataReceived(ChannelExtendedDataMessage message)
        {
            var handlers = ChannelExtendedDataReceived;
            if (handlers != null)
                handlers(this, new MessageEventArgs<ChannelExtendedDataMessage>(message));
        }

        /// <summary>
        /// Called when <see cref="ChannelCloseMessage"/> message received.
        /// </summary>
        /// <param name="message"><see cref="ChannelCloseMessage"/> message.</param>
        internal void OnChannelEofReceived(ChannelEofMessage message)
        {
            var handlers = ChannelEofReceived;
            if (handlers != null)
                handlers(this, new MessageEventArgs<ChannelEofMessage>(message));
        }

        /// <summary>
        /// Called when <see cref="ChannelCloseMessage"/> message received.
        /// </summary>
        /// <param name="message"><see cref="ChannelCloseMessage"/> message.</param>
        internal void OnChannelCloseReceived(ChannelCloseMessage message)
        {
            var handlers = ChannelCloseReceived;
            if (handlers != null)
                handlers(this, new MessageEventArgs<ChannelCloseMessage>(message));
        }

        /// <summary>
        /// Called when <see cref="ChannelRequestMessage"/> message received.
        /// </summary>
        /// <param name="message"><see cref="ChannelRequestMessage"/> message.</param>
        internal void OnChannelRequestReceived(ChannelRequestMessage message)
        {
            var handlers = ChannelRequestReceived;
            if (handlers != null)
                handlers(this, new MessageEventArgs<ChannelRequestMessage>(message));
        }

        /// <summary>
        /// Called when <see cref="ChannelSuccessMessage"/> message received.
        /// </summary>
        /// <param name="message"><see cref="ChannelSuccessMessage"/> message.</param>
        internal void OnChannelSuccessReceived(ChannelSuccessMessage message)
        {
            var handlers = ChannelSuccessReceived;
            if (handlers != null)
                handlers(this, new MessageEventArgs<ChannelSuccessMessage>(message));
        }

        /// <summary>
        /// Called when <see cref="ChannelFailureMessage"/> message received.
        /// </summary>
        /// <param name="message"><see cref="ChannelFailureMessage"/> message.</param>
        internal void OnChannelFailureReceived(ChannelFailureMessage message)
        {
            var handlers = ChannelFailureReceived;
            if (handlers != null)
                handlers(this, new MessageEventArgs<ChannelFailureMessage>(message));
        }

        #endregion

        private void KeyExchange_HostKeyReceived(object sender, HostKeyEventArgs e)
        {
            var handlers = HostKeyReceived;
            if (handlers != null)
                handlers(this, e);
        }

        #region Message loading functions

        /// <summary>
        /// Registers SSH message with the session.
        /// </summary>
        /// <param name="messageName">The name of the message to register with the session.</param>
        public void RegisterMessage(string messageName)
        {
            _sshMessageFactory.EnableAndActivateMessage(messageName);
        }

        /// <summary>
        /// Unregister SSH message from the session.
        /// </summary>
        /// <param name="messageName">The name of the message to unregister with the session.</param>
        public void UnRegisterMessage(string messageName)
        {
            _sshMessageFactory.DisableAndDeactivateMessage(messageName);
        }

        /// <summary>
        /// Loads a message from a given buffer.
        /// </summary>
        /// <param name="data">An array of bytes from which to construct the message.</param>
        /// <param name="offset">The zero-based byte offset in <paramref name="data"/> at which to begin reading.</param>
        /// <param name="count">The number of bytes to load.</param>
        /// <returns>
        /// A message constructed from <paramref name="data"/>.
        /// </returns>
        /// <exception cref="SshException">The type of the message is not supported.</exception>
        private Message LoadMessage(byte[] data, int offset, int count)
        {
            var messageType = data[offset];


            var message = _sshMessageFactory.Create(messageType);

            // TODO REMOVE
            if (messageType == 20)
            {
                DiagnosticAbstraction.Log(string.Format("[{0}] {1} (Offset={2}; Count={3}).", ToHex(SessionId), message.GetType().Name, offset, count));
                DiagnosticAbstraction.Log(data.AsString());
            }

            message.Load(data, offset + 1, count - 1);


            DiagnosticAbstraction.Log(string.Format("[{0}] Received message '{1}' from server: '{2}'.", ToHex(SessionId), message.GetType().Name, message));

            return message;
        }

        #endregion

        /// <summary>
        /// Establishes a socket connection to the specified host and port.
        /// </summary>
        /// <param name="host">The host name of the server to connect to.</param>
        /// <param name="port">The port to connect to.</param>
        /// <exception cref="SshOperationTimeoutException">The connection failed to establish within the configured <see cref="Renci.SshNet.ConnectionInfo.Timeout"/>.</exception>
        /// <exception cref="SocketException">An error occurred trying to establish the connection.</exception>
        private void SocketConnect(string host, int port)
        {
            var ipAddress = DnsAbstraction.GetHostAddresses(host)[0];
            var ep = new IPEndPoint(ipAddress, port);

            DiagnosticAbstraction.Log(string.Format("Initiating connection to '{0}:{1}'.", host, port));

            _socket = SocketAbstraction.Connect(ep, ConnectionInfo.Timeout);

            const int socketBufferSize = 2 * MaximumSshPacketSize;
            _socket.SendBufferSize = socketBufferSize;
            _socket.ReceiveBufferSize = socketBufferSize;
        }

        /// <summary>
        /// Performs a blocking read on the socket until <paramref name="length"/> bytes are received.
        /// </summary>
        /// <param name="buffer">An array of type <see cref="byte"/> that is the storage location for the received data.</param>
        /// <param name="offset">The position in <paramref name="buffer"/> parameter to store the received data.</param>
        /// <param name="length">The number of bytes to read.</param>
        /// <returns>
        /// The number of bytes read.
        /// </returns>
        /// <exception cref="SshConnectionException">The socket is closed.</exception>
        /// <exception cref="SshOperationTimeoutException">The read has timed-out.</exception>
        /// <exception cref="SocketException">The read failed.</exception>
        private int SocketRead(byte[] buffer, int offset, int length)
        {
            var bytesRead = SocketAbstraction.Read(_socket, buffer, offset, length, InfiniteTimeSpan);
            if (bytesRead == 0)
            {
                // when we're in the disconnecting state (either triggered by client or server), then the
                // SshConnectionException will interrupt the message listener loop (if not already interrupted)
                // and the exception itself will be ignored (in RaiseError)
                throw new SshConnectionException("An established connection was aborted by the server.",
                                                 DisconnectReason.ConnectionLost);
            }
            return bytesRead;
        }

        /// <summary>
        /// Performs a blocking read on the socket until a line is read.
        /// </summary>
        /// <param name="timeout">A <see cref="TimeSpan"/> that represents the time to wait until a line is read.</param>
        /// <exception cref="SshOperationTimeoutException">The read has timed-out.</exception>
        /// <exception cref="SocketException">An error occurred when trying to access the socket.</exception>
        /// <returns>
        /// The line read from the socket, or <c>null</c> when the remote server has shutdown and all data has been received.
        /// </returns>
        private string SocketReadLine(TimeSpan timeout)
        {
            var encoding = SshData.Ascii;
            var buffer = new List<byte>();
            var data = new byte[1];

            // read data one byte at a time to find end of line and leave any unhandled information in the buffer
            // to be processed by subsequent invocations
            do
            {
                var bytesRead = SocketAbstraction.Read(_socket, data, 0, data.Length, timeout);
                if (bytesRead == 0)
                    // the remote server shut down the socket
                    break;

                buffer.Add(data[0]);
            }
            while (!(buffer.Count > 0 && (buffer[buffer.Count - 1] == LineFeed || buffer[buffer.Count - 1] == Null)));

            if (buffer.Count == 0)
                return null;
            if (buffer.Count == 1 && buffer[buffer.Count - 1] == 0x00)
                // return an empty version string if the buffer consists of only a 0x00 character
                return string.Empty;
            if (buffer.Count > 1 && buffer[buffer.Count - 2] == CarriageReturn)
                // strip trailing CRLF
                return encoding.GetString(buffer.ToArray(), 0, buffer.Count - 2);
            if (buffer.Count > 1 && buffer[buffer.Count - 1] == LineFeed)
                // strip trailing LF
                return encoding.GetString(buffer.ToArray(), 0, buffer.Count - 1);
            return encoding.GetString(buffer.ToArray(), 0, buffer.Count);
        }

        private byte SocketReadByte()
        {
            var buffer = new byte[1];
            SocketRead(buffer, 0, 1);
            return buffer[0];
        }

        private void ConnectSocks4()
        {
            var connectionRequest = CreateSocks4ConnectionRequest(ConnectionInfo.Host, (ushort) ConnectionInfo.Port, ConnectionInfo.ProxyUsername);
            SocketAbstraction.Send(_socket, connectionRequest);

            //  Read null byte
            if (SocketReadByte() != 0)
            {
                throw new ProxyException("SOCKS4: Null is expected.");
            }

            //  Read response code
            var code = SocketReadByte();

            switch (code)
            {
                case 0x5a:
                    break;
                case 0x5b:
                    throw new ProxyException("SOCKS4: Connection rejected.");
                case 0x5c:
                    throw new ProxyException("SOCKS4: Client is not running identd or not reachable from the server.");
                case 0x5d:
                    throw new ProxyException("SOCKS4: Client's identd could not confirm the user ID string in the request.");
                default:
                    throw new ProxyException("SOCKS4: Not valid response.");
            }

            var dummyBuffer = new byte[6]; // field 3 (2 bytes) and field 4 (4) should be ignored
            SocketRead(dummyBuffer, 0, 6);
        }

        private void ConnectSocks5()
        {
            var greeting = new byte[]
                {
                    // SOCKS version number
                    0x05,
                    // Number of supported authentication methods
                    0x02,
                    // No authentication
                    0x00,
                    // Username/Password authentication
                    0x02
                };
            SocketAbstraction.Send(_socket, greeting);

            var socksVersion = SocketReadByte();
            if (socksVersion != 0x05)
                throw new ProxyException(string.Format("SOCKS Version '{0}' is not supported.", socksVersion));

            var authenticationMethod = SocketReadByte();
            switch (authenticationMethod)
            {
                case 0x00:
                    break;
                case 0x02:
                    // Create username/password authentication request
                    var authenticationRequest = CreateSocks5UserNameAndPasswordAuthenticationRequest(ConnectionInfo.ProxyUsername, ConnectionInfo.ProxyPassword);
                    // Send authentication request
                    SocketAbstraction.Send(_socket, authenticationRequest);
                    // Read authentication result
                    var authenticationResult = SocketAbstraction.Read(_socket, 2, ConnectionInfo.Timeout);

                    if (authenticationResult[0] != 0x01)
                        throw new ProxyException("SOCKS5: Server authentication version is not valid.");
                    if (authenticationResult[1] != 0x00)
                        throw new ProxyException("SOCKS5: Username/Password authentication failed.");
                    break;
                case 0xFF:
                    throw new ProxyException("SOCKS5: No acceptable authentication methods were offered.");
            }

            var connectionRequest = CreateSocks5ConnectionRequest(ConnectionInfo.Host, (ushort) ConnectionInfo.Port);
            SocketAbstraction.Send(_socket, connectionRequest);

            //  Read Server SOCKS5 version
            if (SocketReadByte() != 5)
            {
                throw new ProxyException("SOCKS5: Version 5 is expected.");
            }

            //  Read response code
            var status = SocketReadByte();

            switch (status)
            {
                case 0x00:
                    break;
                case 0x01:
                    throw new ProxyException("SOCKS5: General failure.");
                case 0x02:
                    throw new ProxyException("SOCKS5: Connection not allowed by ruleset.");
                case 0x03:
                    throw new ProxyException("SOCKS5: Network unreachable.");
                case 0x04:
                    throw new ProxyException("SOCKS5: Host unreachable.");
                case 0x05:
                    throw new ProxyException("SOCKS5: Connection refused by destination host.");
                case 0x06:
                    throw new ProxyException("SOCKS5: TTL expired.");
                case 0x07:
                    throw new ProxyException("SOCKS5: Command not supported or protocol error.");
                case 0x08:
                    throw new ProxyException("SOCKS5: Address type not supported.");
                default:
                    throw new ProxyException("SOCKS5: Not valid response.");
            }

            //  Read reserved byte
            if (SocketReadByte() != 0)
            {
                throw new ProxyException("SOCKS5: 0 byte is expected.");
            }

            var addressType = SocketReadByte();
            switch (addressType)
            {
                case 0x01:
                    var ipv4 = new byte[4];
                    SocketRead(ipv4, 0, 4);
                    break;
                case 0x04:
                    var ipv6 = new byte[16];
                    SocketRead(ipv6, 0, 16);
                    break;
                default:
                    throw new ProxyException(string.Format("Address type '{0}' is not supported.", addressType));
            }

            var port = new byte[2];

            //  Read 2 bytes to be ignored
            SocketRead(port, 0, 2);
        }

        /// <summary>
        /// https://tools.ietf.org/html/rfc1929
        /// </summary>
        private static byte[] CreateSocks5UserNameAndPasswordAuthenticationRequest(string username, string password)
        {
            if (username.Length > byte.MaxValue)
                throw new ProxyException("Proxy username is too long.");
            if (password.Length > byte.MaxValue)
                throw new ProxyException("Proxy password is too long.");

            var authenticationRequest = new byte
                [
                    // Version of the negotiation
                    1 +
                    // Length of the username
                    1 +
                    // Username
                    username.Length +
                    // Length of the password
                    1 +
                    // Password
                    password.Length
                ];

            var index = 0;

            // Version of the negiotiation
            authenticationRequest[index++] = 0x01;

            // Length of the username
            authenticationRequest[index++] = (byte) username.Length;

            // Username
            SshData.Ascii.GetBytes(username, 0, username.Length, authenticationRequest, index);
            index += username.Length;

            // Length of the password
            authenticationRequest[index++] = (byte) password.Length;

            // Password
            SshData.Ascii.GetBytes(password, 0, password.Length, authenticationRequest, index);

            return authenticationRequest;
        }

        private static byte[] CreateSocks4ConnectionRequest(string hostname, ushort port, string username)
        {
            var addressBytes = GetSocks4DestinationAddress(hostname);

            var connectionRequest = new byte
                [
                    // SOCKS version number
                    1 +
                    // Command code
                    1 +
                    // Port number
                    2 +
                    // IP address
                    addressBytes.Length +
                    // Username
                    username.Length +
                    // Null terminator
                    1
                ];

            var index = 0;

            // SOCKS version number
            connectionRequest[index++] = 0x04;

            // Command code
            connectionRequest[index++] = 0x01; // establish a TCP/IP stream connection

            // Port number
            Pack.UInt16ToBigEndian(port, connectionRequest, index);
            index += 2;

            // Address
            Buffer.BlockCopy(addressBytes, 0, connectionRequest, index, addressBytes.Length);
            index += addressBytes.Length;

            connectionRequest[index] = 0x00;

            return connectionRequest;
        }

        private static byte[] CreateSocks5ConnectionRequest(string hostname, ushort port)
        {
            byte addressType;
            var addressBytes = GetSocks5DestinationAddress(hostname, out addressType);

            var connectionRequest = new byte
                [
                    // SOCKS version number
                    1 +
                    // Command code
                    1 +
                    // Reserved
                    1 +
                    // Address type
                    1 +
                    // Address
                    addressBytes.Length +
                    // Port number
                    2
                ];

            var index = 0;

            // SOCKS version number
            connectionRequest[index++] = 0x05;

            // Command code
            connectionRequest[index++] = 0x01; // establish a TCP/IP stream connection

            // Reserved
            connectionRequest[index++] = 0x00;

            // Address type
            connectionRequest[index++] = addressType;
            
            // Address
            Buffer.BlockCopy(addressBytes, 0, connectionRequest, index, addressBytes.Length);
            index += addressBytes.Length;

            // Port number
            Pack.UInt16ToBigEndian(port, connectionRequest, index);

            return connectionRequest;
        }

        private static byte[] GetSocks4DestinationAddress(string hostname)
        {
            var addresses = DnsAbstraction.GetHostAddresses(hostname);

            for (var i = 0; i < addresses.Length; i++)
            {
                var address = addresses[i];
                if (address.AddressFamily == AddressFamily.InterNetwork)
                    return address.GetAddressBytes();
            }

            throw new ProxyException(string.Format("SOCKS4 only supports IPv4. No such address found for '{0}'.", hostname));
        }

        private static byte[] GetSocks5DestinationAddress(string hostname, out byte addressType)
        {
            var ip = DnsAbstraction.GetHostAddresses(hostname)[0];

            byte[] address;

            switch (ip.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    addressType = 0x01; // IPv4
                    address = ip.GetAddressBytes();
                    break;
                case AddressFamily.InterNetworkV6:
                    addressType = 0x04; // IPv6
                    address = ip.GetAddressBytes();
                    break;
                default:
                    throw new ProxyException(string.Format("SOCKS5: IP address '{0}' is not supported.", ip));
            }

            return address;
        }

        private void ConnectHttp()
        {
            var httpResponseRe = new Regex(@"HTTP/(?<version>\d[.]\d) (?<statusCode>\d{3}) (?<reasonPhrase>.+)$");
            var httpHeaderRe = new Regex(@"(?<fieldName>[^\[\]()<>@,;:\""/?={} \t]+):(?<fieldValue>.+)?");

            SocketAbstraction.Send(_socket, SshData.Ascii.GetBytes(string.Format("CONNECT {0}:{1} HTTP/1.0\r\n", ConnectionInfo.Host, ConnectionInfo.Port)));

            //  Sent proxy authorization is specified
            if (!string.IsNullOrEmpty(ConnectionInfo.ProxyUsername))
            {
                var authorization = string.Format("Proxy-Authorization: Basic {0}\r\n",
                                                  Convert.ToBase64String(SshData.Ascii.GetBytes(string.Format("{0}:{1}", ConnectionInfo.ProxyUsername, ConnectionInfo.ProxyPassword)))
                                                  );
                SocketAbstraction.Send(_socket, SshData.Ascii.GetBytes(authorization));
            }

            SocketAbstraction.Send(_socket, SshData.Ascii.GetBytes("\r\n"));

            HttpStatusCode? statusCode = null;
            var contentLength = 0;

            while (true)
            {
                var response = SocketReadLine(ConnectionInfo.Timeout);
                if (response == null)
                    // server shut down socket
                    break;

                if (statusCode == null)
                {
                    var statusMatch = httpResponseRe.Match(response);
                    if (statusMatch.Success)
                    {
                        var httpStatusCode = statusMatch.Result("${statusCode}");
                        statusCode = (HttpStatusCode) int.Parse(httpStatusCode);
                        if (statusCode != HttpStatusCode.OK)
                        {
                            var reasonPhrase = statusMatch.Result("${reasonPhrase}");
                            throw new ProxyException(string.Format("HTTP: Status code {0}, \"{1}\"", httpStatusCode,
                                reasonPhrase));
                        }
                    }

                    continue;
                }

                // continue on parsing message headers coming from the server
                var headerMatch = httpHeaderRe.Match(response);
                if (headerMatch.Success)
                {
                    var fieldName = headerMatch.Result("${fieldName}");
                    if (fieldName.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
                    {
                        contentLength = int.Parse(headerMatch.Result("${fieldValue}"));
                    }
                    continue;
                }

                // check if we've reached the CRLF which separates request line and headers from the message body
                if (response.Length == 0)
                {
                    //  read response body if specified
                    if (contentLength > 0)
                    {
                        var contentBody = new byte[contentLength];
                        SocketRead(contentBody, 0, contentLength);
                    }
                    break;
                }
            }

            if (statusCode == null)
                throw new ProxyException("HTTP response does not contain status line.");
        }

        /// <summary>
        /// Resets connection-specific information to ensure state of a previous connection
        /// does not affect new connections.
        /// </summary>
        private void Reset()
        {
            if (_exceptionWaitHandle != null)
                _exceptionWaitHandle.Reset();
            if (_keyExchangeCompletedWaitHandle != null)
                _keyExchangeCompletedWaitHandle.Reset();
            if (_messageListenerCompleted != null)
                _messageListenerCompleted.Set();

            SessionId = null;
            _isDisconnectMessageSent = false;
            _isDisconnecting = false;
            _isAuthenticated = false;
            _exception = null;
            _keyExchangeInProgress = false;
        }

        private static SshConnectionException CreateConnectionAbortedByServerException()
        {
            return new SshConnectionException("An established connection was aborted by the server.",
                                              DisconnectReason.ConnectionLost);
        }

        #region IDisposable implementation

        private bool _disposed;

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Releases unmanaged and - optionally - managed resources
        /// </summary>
        /// <param name="disposing"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                DiagnosticAbstraction.Log(string.Format("[{0}] Disposing session.", Session.ToHex(SessionId)));

                Disconnect();

                var serviceAccepted = _serviceAccepted;
                if (serviceAccepted != null)
                {
                    serviceAccepted.Dispose();
                    _serviceAccepted = null;
                }

                var exceptionWaitHandle = _exceptionWaitHandle;
                if (exceptionWaitHandle != null)
                {
                    exceptionWaitHandle.Dispose();
                    _exceptionWaitHandle = null;
                }

                var keyExchangeCompletedWaitHandle = _keyExchangeCompletedWaitHandle;
                if (keyExchangeCompletedWaitHandle != null)
                {
                    keyExchangeCompletedWaitHandle.Dispose();
                    _keyExchangeCompletedWaitHandle = null;
                }

                var serverMac = ServerMac;
                if (serverMac != null)
                {
                    serverMac.Dispose();
                    ServerMac = null;
                }

                var clientMac = ClientMac;
                if (clientMac != null)
                {
                    clientMac.Dispose();
                    ClientMac = null;
                }

                var keyExchange = _keyExchange;
                if (keyExchange != null)
                {
                    keyExchange.HostKeyReceived -= KeyExchange_HostKeyReceived;
                    keyExchange.Dispose();
                    _keyExchange = null;
                }

                var messageListenerCompleted = _messageListenerCompleted;
                if (messageListenerCompleted != null)
                {
                    messageListenerCompleted.Dispose();
                    _messageListenerCompleted = null;
                }

                _disposed = true;
            }
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="Session"/> is reclaimed by garbage collection.
        /// </summary>
        ~Session()
        {
            Dispose(false);
        }

        #endregion IDisposable implementation

        #region ISession implementation

        /// <summary>
        /// Gets or sets the connection info.
        /// </summary>
        /// <value>The connection info.</value>
        IConnectionInfo ISession.ConnectionInfo
        {
            get { return ConnectionInfo; }
        }

        WaitHandle ISession.MessageListenerCompleted
        {
            get { return _messageListenerCompleted; }
        }

        /// <summary>
        /// Create a new SSH session channel.
        /// </summary>
        /// <returns>
        /// A new SSH session channel.
        /// </returns>
        IChannelSession ISession.CreateChannelSession()
        {
            return new ChannelSession(this, NextChannelNumber, InitialLocalWindowSize, LocalChannelDataPacketSize);
        }

        /// <summary>
        /// Create a new channel for a locally forwarded TCP/IP port.
        /// </summary>
        /// <returns>
        /// A new channel for a locally forwarded TCP/IP port.
        /// </returns>
        IChannelDirectTcpip ISession.CreateChannelDirectTcpip()
        {
            return new ChannelDirectTcpip(this, NextChannelNumber, InitialLocalWindowSize, LocalChannelDataPacketSize);
        }

        /// <summary>
        /// Creates a "forwarded-tcpip" SSH channel.
        /// </summary>
        /// <returns>
        /// A new "forwarded-tcpip" SSH channel.
        /// </returns>
        IChannelForwardedTcpip ISession.CreateChannelForwardedTcpip(uint remoteChannelNumber,
                                                                    uint remoteWindowSize,
                                                                    uint remoteChannelDataPacketSize)
        {
            return new ChannelForwardedTcpip(this,
                                             NextChannelNumber,
                                             InitialLocalWindowSize,
                                             LocalChannelDataPacketSize,
                                             remoteChannelNumber,
                                             remoteWindowSize,
                                             remoteChannelDataPacketSize);
        }

        /// <summary>
        /// Sends a message to the server.
        /// </summary>
        /// <param name="message">The message to send.</param>
        /// <exception cref="SshConnectionException">The client is not connected.</exception>
        /// <exception cref="SshOperationTimeoutException">The operation timed out.</exception>
        /// <exception cref="InvalidOperationException">The size of the packet exceeds the maximum size defined by the protocol.</exception>
        void ISession.SendMessage(Message message)
        {
            SendMessage(message);
        }

        /// <summary>
        /// Sends a message to the server.
        /// </summary>
        /// <param name="message">The message to send.</param>
        /// <returns>
        /// <c>true</c> if the message was sent to the server; otherwise, <c>false</c>.
        /// </returns>
        /// <exception cref="InvalidOperationException">The size of the packet exceeds the maximum size defined by the protocol.</exception>
        /// <remarks>
        /// This methods returns <c>false</c> when the attempt to send the message results in a
        /// <see cref="SocketException"/> or a <see cref="SshException"/>.
        /// </remarks>
        bool ISession.TrySendMessage(Message message)
        {
            return TrySendMessage(message);
        }

        #endregion ISession implementation

        internal static string ToHex(byte[] bytes)
        {
            if (bytes == null)
                return null;

            return ToHex(bytes, 0);
        }

        internal static string ToHex(byte[] bytes, int offset)
        {
            var byteCount = bytes.Length - offset;

            var builder = new StringBuilder(bytes.Length * 2);

            for (var i = offset; i < byteCount; i++)
            {
                var b = bytes[i];
                builder.Append(b.ToString("X2"));
            }

            return builder.ToString();
        }
    }

    /// <summary>
    /// Represents the result of a wait operations.
    /// </summary>
    internal enum WaitResult
    {
        /// <summary>
        /// The <see cref="WaitHandle"/> was signaled within the specified interval.
        /// </summary>
        Success = 1,

        /// <summary>
        /// The <see cref="WaitHandle"/> was not signaled within the specified interval.
        /// </summary>
        TimedOut = 2,

        /// <summary>
        /// The session is in a disconnected state.
        /// </summary>
        Disconnected = 3,

        /// <summary>
        /// The session is in a failed state.
        /// </summary>
        Failed = 4
    }

    internal class ServerIdentifiedEventArgs : EventArgs
    {
        public string SoftwareName { get; private set; }
        public string ServerIdentification { get; private set; }
        public string ProtocolVersion { get; private set; }

        public ServerIdentifiedEventArgs(string serverIdentification, string protocolVersion, string softwareName)
        {
            SoftwareName = softwareName;
            ServerIdentification = serverIdentification;
            ProtocolVersion = protocolVersion;
        }
    }

    internal class AsyncMessageListener : IDisposable
    {
        private readonly Session _session;
        private readonly Socket _socket;
        private readonly LoadMessageDelegate _loadMessageDelegate;
        private readonly SocketAsyncEventArgs _readSocketAsyncEventArgs;
        private readonly SocketAsyncEventArgs _writeSocketAsyncEventArgs;

        /// <summary>
        /// Specifies outbound packet number
        /// </summary>
        private volatile uint _outboundPacketSequence;

        /// <summary>
        /// Specifies incoming packet number
        /// </summary>
        private uint _inboundPacketSequence;

        /// <summary>
        /// Holds an object that is used to ensure only a single thread can dispose
        /// <see cref="_socket"/> at any given time.
        /// </summary>
        /// <remarks>
        /// This is also used to ensure that <see cref="_socket"/> will not be disposed
        /// while performing a given operation or set of operations on <see cref="_socket"/>.
        /// </remarks>
        private readonly object _disposeLock;

        /// <summary>
        /// Holds an object that is used to ensure only a single thread can write to
        /// <see cref="_socket"/> at any given time.
        /// </summary>
        /// <remarks>
        /// This is also used to ensure that <see cref="_outboundPacketSequence"/> is
        /// incremented atomatically.
        /// </remarks>
        private readonly object _socketWriteLock;

        private readonly object _transitionLock;

        private ListenerState _state;
        private byte _blockSize;
        private uint _packetLength;
        private byte[] _firstBlock;
        private int _receiveReadOffset;
        private readonly CountdownEvent _processingCompleted;
        private readonly AutoResetEvent _sendPacketCompleted;
        private readonly TimeSpan _timeout;

        public event EventHandler<ServerIdentifiedEventArgs> ServerIdentified;
        public event EventHandler<EventArgs> Closed;
        public event EventHandler<ExceptionEventArgs> Error;

        public bool IsConnected
        {
            get
            {
                return _state == ListenerState.Connected ||
                       _state == ListenerState.FirstBlockRead ||
                       _state == ListenerState.Ready;
            }
        }

        public AsyncMessageListener(Session session, Socket socket, LoadMessageDelegate loadMessageDelegate)
        {
            var buffer = CreateSocketReceiveBuffer();

            _session = session;
            _socket = socket;
            _loadMessageDelegate = loadMessageDelegate;
            _processingCompleted = new CountdownEvent(1);
            _sendPacketCompleted = new AutoResetEvent(false);
            _timeout = session.ConnectionInfo.Timeout;

            _socketWriteLock = new object();
            _transitionLock = new object();
            _disposeLock = new object();

            _readSocketAsyncEventArgs = new SocketAsyncEventArgs();
            _readSocketAsyncEventArgs.SetBuffer(buffer, 0, buffer.Length);
            _readSocketAsyncEventArgs.Completed += SocketOperationCompleted;

            _writeSocketAsyncEventArgs = new SocketAsyncEventArgs();
            _writeSocketAsyncEventArgs.Completed += SocketOperationCompleted;
        }

        private static byte[] CreateSocketReceiveBuffer()
        {
            return new byte[Session.MaximumSshPacketSize + 3000];
            //return new byte[10000];
        }

        private bool ReadServerIdentification(int count)
        {
            int bytesRead;

            // Get server version from the server, and ignore any text lines which are sent before
            var serverVersion = GetLine(_readSocketAsyncEventArgs, _receiveReadOffset, count, out bytesRead);
            if (serverVersion == null)
            {
                return false;
            }

            var versionMatch = Session.ServerVersionRe.Match(serverVersion);
            if (!versionMatch.Success)
            {
                return false;
            }

            // Get server SSH version
            var protocolVersion = versionMatch.Result("${protoversion}");
            var softwareName = versionMatch.Result("${softwareversion}");

            if (ServerIdentified != null)
            {
                ServerIdentified(this, new ServerIdentifiedEventArgs(serverVersion, protocolVersion, softwareName));
            }

            _receiveReadOffset += bytesRead;
            return true;
        }

        public void SendClientIdentification(string clientVersion)
        {
            var clientIdentification = Encoding.UTF8.GetBytes(string.Format(CultureInfo.InvariantCulture, "{0}\x0D\x0A", clientVersion));
            lock (_socketWriteLock)
            {
                SendPacketAsync(clientIdentification, 0, clientIdentification.Length);
                if (!_sendPacketCompleted.WaitOne(_timeout))
                {
                    // TODO
                }
            }
        }

        private static string GetLine(SocketAsyncEventArgs sae, int offset, int count, out int bytesRead)
        {
            var bytesInLine = 0;

            bytesRead = 0;
            while (bytesRead < count)
            {
                var b = sae.Buffer[offset + bytesRead++];
                if (b != Session.LineFeed)
                {
                    bytesInLine++;
                    continue;
                }

                if (bytesInLine == 0)
                {
                    // Skip LF
                    offset++;
                    continue;
                }

                string line;
                if (sae.Buffer[offset + bytesRead - 2] == Session.CarriageReturn)
                {
                    line = SshData.Ascii.GetString(sae.Buffer, offset, bytesInLine - 1);
                }
                else
                {
                    line = SshData.Ascii.GetString(sae.Buffer, offset, bytesInLine);
                }

                return line;
            }

            return null;
        }

        private bool ReadFirstBlock(int count, Cipher serverCipher)
        {
            // Determine the size of the first block, which is 8 or cipher block size (whichever is larger) bytes
            _blockSize = serverCipher == null ? (byte) 8 : Math.Max((byte) 8, serverCipher.MinimumSize);

            if (count < _blockSize)
            {
                return false;
            }

            //  Read first block - which starts with the packet length
            if (serverCipher != null)
            {
                _firstBlock = serverCipher.Decrypt(_readSocketAsyncEventArgs.Buffer, _receiveReadOffset, _blockSize);
            }
            else
            {
                _firstBlock = new byte[_blockSize];
                Buffer.BlockCopy(_readSocketAsyncEventArgs.Buffer, _receiveReadOffset, _firstBlock, 0, _blockSize);
            }

            _packetLength = Pack.BigEndianToUInt32(_firstBlock);

            // Test packet minimum and maximum boundaries
            if (_packetLength < Math.Max((byte) 16, _blockSize) - 4 || _packetLength > Session.MaximumSshPacketSize - 4)
                // TODO: publish error event, and attempt to transition to ERROR
                throw new SshConnectionException(
                    string.Format(CultureInfo.CurrentCulture, "Bad packet length: {0}.", _packetLength),
                    DisconnectReason.ProtocolError);

            DiagnosticAbstraction.Log(string.Format("[{0}] Received packet; Length={1}; Blocksize={2}", Session.ToHex(_session.SessionId), _packetLength, _blockSize));

            _receiveReadOffset += _blockSize;

            return true;
        }

        private Message ReadMessage(int count, HashAlgorithm serverMac, Cipher serverCipher, Compressor serverDecompression)
        {
            // the length of the packet sequence field in bytes
            const int inboundPacketSequenceLength = 4;
            // The length of the "packet length" field in bytes
            const int packetLengthFieldLength = 4;
            // The length of the "padding length" field in bytes
            const int paddingLengthFieldLength = 1;

            var serverMacLength = serverMac != null ? serverMac.HashSize / 8 : 0;

            // Determine the number of bytes left to read; We've already read "blockSize" bytes, but the
            // "packet length" field itself - which is 4 bytes - is not included in the length of the packet
            var bytesToRead = (int) (_packetLength - (_blockSize - packetLengthFieldLength)) + serverMacLength;

            DiagnosticAbstraction.Log(string.Format("[{0}] Reading message (Bytes={1}; Offset={2}; Count={3}).", Session.ToHex(_session.SessionId), bytesToRead, _receiveReadOffset, count));

            if (count < bytesToRead)
            {
                return null;
            }

            // Construct buffer for holding the payload and the inbound packet sequence as we need both in order
            // to generate the hash.
            // 
            // The total length of the "data" buffer is an addition of:
            // - inboundPacketSequenceLength (4 bytes)
            // - packetLength
            // - serverMacLength
            // 
            // We include the inbound packet sequence to allow us to have the the full SSH packet in a single
            // byte[] for the purpose of calculating the client hash. Room for the server MAC is foreseen
            // to read the packet including server MAC in a single pass (except for the initial block).
            var data = new byte[bytesToRead + _blockSize + inboundPacketSequenceLength];
            Pack.UInt32ToBigEndian(_inboundPacketSequence, data);
            Buffer.BlockCopy(_firstBlock, 0, data, inboundPacketSequenceLength, _firstBlock.Length);
            Buffer.BlockCopy(_readSocketAsyncEventArgs.Buffer, _receiveReadOffset, data, _blockSize + inboundPacketSequenceLength, bytesToRead);

            if (serverCipher != null)
            {
                var numberOfBytesToDecrypt = data.Length - (_blockSize + inboundPacketSequenceLength + serverMacLength);
                if (numberOfBytesToDecrypt > 0)
                {
                    var decryptedData = serverCipher.Decrypt(data, _blockSize + inboundPacketSequenceLength, numberOfBytesToDecrypt);
                    Buffer.BlockCopy(decryptedData, 0, data, _blockSize + inboundPacketSequenceLength, decryptedData.Length);
                }
            }

            _receiveReadOffset += bytesToRead;

            var paddingLength = data[inboundPacketSequenceLength + packetLengthFieldLength];
            var messagePayloadLength = (int) _packetLength - paddingLength - paddingLengthFieldLength;
            var messagePayloadOffset = inboundPacketSequenceLength + packetLengthFieldLength + paddingLengthFieldLength;

            // validate message against MAC
            if (serverMac != null)
            {
                var clientHash = serverMac.ComputeHash(data, 0, data.Length - serverMacLength);
                var serverHash = data.Take(data.Length - serverMacLength, serverMacLength);

                // TODO add IsEqualTo overload that takes left+right index and number of bytes to compare;
                // TODO that way we can eliminate the extra allocation of the Take above
                if (!serverHash.IsEqualTo(clientHash))
                {
                    // TODO: publish error event, and attempt to transition to ERROR
                    throw new SshConnectionException("MAC error", DisconnectReason.MacError);
                }
            }

            if (serverDecompression != null)
            {
                data = serverDecompression.Decompress(data, messagePayloadOffset, messagePayloadLength);

                // data now only contains the decompressed payload, and as such the offset is reset to zero
                messagePayloadOffset = 0;
                // the length of the payload is now the complete decompressed content
                messagePayloadLength = data.Length;
            }

            _inboundPacketSequence++;

            return _loadMessageDelegate(data, messagePayloadOffset, messagePayloadLength);
        }

        private void SocketOperationCompleted(object sender, SocketAsyncEventArgs e)
        {
            switch (e.LastOperation)
            {
                case SocketAsyncOperation.Receive:
                    ProcessReceive(e);
                    break;
                case SocketAsyncOperation.Send:
                    ProcessSend(e);
                    break;
                case SocketAsyncOperation.Disconnect:
                    ProcessDisconnect(e);
                    break;
            }
        }

        private void ProcessSend(SocketAsyncEventArgs e)
        {
            _sendPacketCompleted.Set();

            if (e.SocketError != SocketError.Success)
            {
                StartDisconnect(e);
            }
        }

        private void ProcessReceive(SocketAsyncEventArgs e)
        {
            if (e.BytesTransferred == 0 || e.SocketError != SocketError.Success)
            {
                if (e.BytesTransferred == 0)
                {
                    DiagnosticAbstraction.Log(string.Format("[{0}] Socket closed by server.", Session.ToHex(_session.SessionId)));
                }
                else
                {
                    DiagnosticAbstraction.Log(string.Format("[{0}] Socket error '{1}'.", Session.ToHex(_session.SessionId), e.SocketError));
                }

                Transition(ListenerState.Closed);
                StartDisconnect(e);
                return;
            }

            if (!_socket.Connected)
            {
                DiagnosticAbstraction.Log(string.Format("[{0}] Socket not connected. Ignoring received data (Offset={1}; BytesTransferrer={2}).", Session.ToHex(_session.SessionId), e.Offset, e.BytesTransferred));
                return;
            }

            DiagnosticAbstraction.Log(string.Format("[{0}] Received data; Offset={1}; BytesTransferrer={2}", Session.ToHex(_session.SessionId), e.Offset, e.BytesTransferred));

            _processingCompleted.AddCount();
            try
            {
                ProcessReceivedData((e.Offset - _receiveReadOffset) + e.BytesTransferred, _readSocketAsyncEventArgs.Offset + _readSocketAsyncEventArgs.BytesTransferred);
            }
            finally
            {
                _processingCompleted.Signal();
            }
        }

        public void Stop()
        {
            DiagnosticAbstraction.Log(string.Format("[{0}] Stopping listener.", Session.ToHex(_session.SessionId)));

            lock (_transitionLock)
            {
                if (_state == ListenerState.Disposed)
                {
                    throw new ObjectDisposedException(GetType().Name);
                }

                if (!Transition(ListenerState.Stopped))
                {
                    return;
                }
            }

            lock (_disposeLock)
            {
                if (_state == ListenerState.Stopped)
                {
                    DoStop();
                }
            }
        }

        private void ProcessReceivedData(int count, int totalBytesReceived)
        {
            DiagnosticAbstraction.Log(string.Format("[{0}] Processing data (Offset={1}; Count={2}, State={3}).", Session.ToHex(_session.SessionId), _receiveReadOffset, count, _state));

            if (_state == ListenerState.Connected)
            {
                if (ReadServerIdentification(count))
                {
                    Transition(ListenerState.Ready);
                    if (_receiveReadOffset < totalBytesReceived)
                    {
                        ProcessReceivedData(totalBytesReceived - _receiveReadOffset, totalBytesReceived);
                        return;
                    }
                    if (_receiveReadOffset == totalBytesReceived)
                    {
                        _receiveReadOffset = 0;
                        _readSocketAsyncEventArgs.SetBuffer(0, _readSocketAsyncEventArgs.Buffer.Length);
                    }
                }
                else
                {
                    _readSocketAsyncEventArgs.SetBuffer(totalBytesReceived, _readSocketAsyncEventArgs.Buffer.Length - totalBytesReceived);
                }
            }
            else if (_state == ListenerState.Ready)
            {
                if (ReadFirstBlock(count, _session.ServerCipher))
                {
                    Transition(ListenerState.FirstBlockRead);
                    if (_receiveReadOffset < totalBytesReceived)
                    {
                        ProcessReceivedData(totalBytesReceived - _receiveReadOffset, totalBytesReceived);
                        return;
                    }
                    if (_receiveReadOffset == totalBytesReceived)
                    {
                        _receiveReadOffset = 0;
                        _readSocketAsyncEventArgs.SetBuffer(0, _readSocketAsyncEventArgs.Buffer.Length);
                    }
                }
                else
                {
                    _readSocketAsyncEventArgs.SetBuffer(totalBytesReceived, _readSocketAsyncEventArgs.Buffer.Length - totalBytesReceived);
                }
            }
            else if (_state == ListenerState.FirstBlockRead)
            {
                var message = ReadMessage(count, _session.ServerMac, _session.ServerCipher, _session.ServerDecompression);
                if (message != null)
                {
                    message.Process(_session);
                    Transition(ListenerState.Ready);
                    if (_receiveReadOffset < totalBytesReceived)
                    {
                        ProcessReceivedData(totalBytesReceived - _receiveReadOffset, totalBytesReceived);
                        return;
                    }
                    if (_receiveReadOffset == totalBytesReceived)
                    {
                        _receiveReadOffset = 0;
                        _readSocketAsyncEventArgs.SetBuffer(0, _readSocketAsyncEventArgs.Buffer.Length);
                    }
                }
                else
                {
                    _readSocketAsyncEventArgs.SetBuffer(totalBytesReceived, _readSocketAsyncEventArgs.Buffer.Length - totalBytesReceived);
                }
            }
            else if (_state == ListenerState.Stopped)
            {
                DiagnosticAbstraction.Log(string.Format("[{0}] Listener stopping. Ignoring data (Offset={1}; Count={2}).", Session.ToHex(_session.SessionId), _receiveReadOffset, count));
                return;
            }
            else if (_state == ListenerState.Disposed)
            {
                DiagnosticAbstraction.Log(string.Format("[{0}] Listener disposed. Ignoring data (Offset={1}; Count={2}).", Session.ToHex(_session.SessionId), _receiveReadOffset, count));
                return;
            }
            else
            {
                DiagnosticAbstraction.Log(string.Format("[{0}] Unexpected listener state '{1}'. Ignoring data (Offset={2}; Count={3}).", Session.ToHex(_session.SessionId), _state, _receiveReadOffset, count));
            }

            StartReceive();
        }

        private void DoStop()
        {
            if (_processingCompleted.IsSet)
            {
                return;
            }

            _processingCompleted.Signal();
            _processingCompleted.Wait(Session.InfiniteTimeSpan);
            RaiseClosedEvent();
        }

        private bool Transition(ListenerState newState)
        {
            lock (_transitionLock)
            {
                var currentState = _state;

                if (currentState == ListenerState.FirstBlockRead)
                {
                    if (newState == ListenerState.Ready)
                    {
                        _state = newState;
                    }
                    else if (newState == ListenerState.FirstBlockRead)
                    {
                        _state = newState;
                    }
                    else if (newState == ListenerState.Stopped)
                    {
                        _state = newState;
                    }
                    else if (newState == ListenerState.Closed)
                    {
                        _state = newState;
                        RaiseClosedEvent();
                    }
                    else if (newState == ListenerState.Disposed)
                    {
                        _state = newState;
                    }
                    else
                    {
                        _state = ListenerState.Error;
                        RaiseErrorEvent(CreateTransitionNodeAllowedException(currentState, newState));
                        return false;
                    }
                }
                else if (currentState == ListenerState.Ready)
                {
                    if (newState == ListenerState.Ready)
                    {
                    }
                    else if (newState == ListenerState.FirstBlockRead)
                    {
                        _state = newState;
                    }
                    else if (newState == ListenerState.Stopped)
                    {
                        _state = newState;
                    }
                    else if (newState == ListenerState.Closed)
                    {
                        _state = newState;
                        RaiseClosedEvent();
                    }
                    else if (newState == ListenerState.Disposed)
                    {
                        _state = newState;
                    }
                    else
                    {
                        _state = ListenerState.Error;
                        RaiseErrorEvent(CreateTransitionNodeAllowedException(currentState, newState));
                        return false;
                    }
                }
                else if (currentState == ListenerState.Connected)
                {
                    if (newState == ListenerState.Ready)
                    {
                        _state = newState;
                    }
                    else if (newState == ListenerState.Stopped)
                    {
                        _state = newState;
                    }
                    else if (newState == ListenerState.Closed)
                    {
                        _state = newState;
                        RaiseClosedEvent();
                    }
                    else
                    {
                        _state = ListenerState.Error;
                        RaiseErrorEvent(CreateTransitionNodeAllowedException(currentState, newState));
                        return false;
                    }
                }
                else if (currentState == ListenerState.Stopped)
                {
                    if (newState == ListenerState.Stopped)
                    {
                    }
                    else if (newState == ListenerState.Disposed)
                    {
                        _state = newState;
                    }
                    else if (newState == ListenerState.Closed)
                    {
                        _state = newState;
                        // no need to raise Closed event, since this will be done as part of the DoStop method
                        //RaiseClosedEvent();
                    }
                    else
                    {
                        _state = ListenerState.Error;
                        RaiseErrorEvent(CreateTransitionNodeAllowedException(currentState, newState));
                        return false;
                    }
                }
                else if (currentState == ListenerState.Closed)
                {
                    if (newState == ListenerState.Stopped)
                    {
                        _state = newState;
                    }
                    else if (newState == ListenerState.Disposed)
                    {
                        _state = newState;
                    }
                    else if (newState == ListenerState.Closed)
                    {
                    }
                    else
                    {
                        _state = ListenerState.Error;
                        RaiseErrorEvent(CreateTransitionNodeAllowedException(currentState, newState));
                        return false;
                    }
                }
                else if (currentState == ListenerState.Disposed)
                {
                    if (newState == ListenerState.Closed)
                    {
                        // no need to raise Closed event, since this will be done as part of the DoStop method
                        //RaiseClosedEvent();

                    }
                    else if (newState == ListenerState.Disposed)
                    {
                        return false;
                    }
                    else
                    {
                        RaiseErrorEvent(CreateTransitionNodeAllowedException(currentState, newState));
                        return false;
                    }
                }
                else
                {
                    _state = ListenerState.Error;
                    RaiseErrorEvent(CreateTransitionNodeAllowedException(currentState, newState));
                    return false;
                }

                return true;
            }
        }

        private static SshException CreateTransitionNodeAllowedException(ListenerState currentState, ListenerState newState)
        {
            return new SshException(string.Format(CultureInfo.InvariantCulture, "Transition from '{0}' to '{1} is not allowed.", currentState.ToString(), newState.ToString()));
        }

        private void RaiseClosedEvent()
        {
            var closed = Closed;
            if (closed != null)
            {
                closed(this, new EventArgs());
            }
        }

        private void RaiseErrorEvent(Exception cause)
        {
            var error = Error;
            if (error != null)
            {
                error(this, new ExceptionEventArgs(cause));
            }
        }

        public void Start()
        {
            if (_state == ListenerState.Disposed)
            {
                throw new ObjectDisposedException(GetType().Name);
            }

            _state = ListenerState.Connected;
            StartReceive();
        }

        private void StartReceive()
        {
            DiagnosticAbstraction.Log(string.Format("[{0}] Start receiving; Offset={1}; Count={2}.", Session.ToHex(_session.SessionId), _readSocketAsyncEventArgs.Offset, _readSocketAsyncEventArgs.Count));

            try
            {
                if (!_socket.ReceiveAsync(_readSocketAsyncEventArgs))
                {
                    SocketOperationCompleted(this, _readSocketAsyncEventArgs);
                }
            }
            catch (ObjectDisposedException)
            {
                // TODO: publish error event, and attempt to transition to ERROR
                DiagnosticAbstraction.Log(string.Format("[{0}] Socket disposed. Stopped receiving.", Session.ToHex(_session.SessionId)));
            }
        }

        private static SshConnectionException CreateConnectionAbortedByServerException()
        {
            return new SshConnectionException("An established connection was aborted by the server.",
                                              DisconnectReason.ConnectionLost);
        }

        internal delegate Message LoadMessageDelegate(byte[] data, int offset, int count);

        private void StartDisconnect(SocketAsyncEventArgs e)
        {
            if (_socket.Connected)
            {
                try
                {
                    DiagnosticAbstraction.Log(string.Format("[{0}] Shutting down socket.", Session.ToHex(_session.SessionId)));

                    // interrupt any pending reads; should be done outside of socket read lock as we
                    // actually want shutdown the socket to make sure blocking reads are interrupted
                    //
                    // this may result in a SocketException (eg. An existing connection was forcibly
                    // closed by the remote host) which we'll log and ignore as it means the socket
                    // was already shut down
                    _socket.Shutdown(SocketShutdown.Both);
                }
                catch (SocketException ex)
                {
                    // TODO: log as warning
                    DiagnosticAbstraction.Log("Failure shutting down socket: " + ex);
                }
            }

            if (!_socket.DisconnectAsync(e))
            {
                ProcessDisconnect(e);
            }
        }

        /// <summary>
        /// Shuts down and disposes the socket.
        /// </summary>
        private void SocketDisconnectAndDispose()
        {
            if (_socket.Connected)
            {
                try
                {
                    DiagnosticAbstraction.Log(string.Format("[{0}] Shutting down socket.", Session.ToHex(_session.SessionId)));

                    // interrupt any pending reads; should be done outside of socket read lock as we
                    // actually want shutdown the socket to make sure blocking reads are interrupted
                    //
                    // this may result in a SocketException (eg. An existing connection was forcibly
                    // closed by the remote host) which we'll log and ignore as it means the socket
                    // was already shut down
                    _socket.Shutdown(SocketShutdown.Both);
                }
                catch (SocketException ex)
                {
                    // TODO: log as warning
                    DiagnosticAbstraction.Log("Failure shutting down socket: " + ex);
                }
            }

            DiagnosticAbstraction.Log(string.Format("[{0}] Disposing socket.", Session.ToHex(_session.SessionId)));
            _socket.Dispose();
            DiagnosticAbstraction.Log(string.Format("[{0}] Disposed socket.", Session.ToHex(_session.SessionId)));
        }

        private void ProcessDisconnect(SocketAsyncEventArgs e)
        {
            if (e.SocketError != SocketError.Success)
            {
                DiagnosticAbstraction.Log("Failure disconnecting socket: " + e.SocketError);
            }

            DiagnosticAbstraction.Log(string.Format("[{0}] Closing socket.", Session.ToHex(_session.SessionId)));
            _socket.Dispose();
            DiagnosticAbstraction.Log(string.Format("[{0}] Closed socket.", Session.ToHex(_session.SessionId)));
        }

        public void SendMessage(Message message)
        {
            DiagnosticAbstraction.Log(string.Format("[{0}] Sending message '{1}' to server: '{2}'.", Session.ToHex(_session.SessionId), message.GetType().Name, message));

            var clientCipher = _session.ClientCipher;
            var serverCipher = _session.ServerCipher;
            var clientMac  = _session.ClientMac;

            var paddingMultiplier = clientCipher == null ? (byte) 8 : Math.Max((byte) 8, serverCipher.MinimumSize);
            var packetData = message.GetPacket(paddingMultiplier, _session.ClientCompression);

            // take a write lock to ensure the outbound packet sequence number is incremented
            // atomically, and only after the packet has actually been sent
            lock (_socketWriteLock)
            {
                byte[] hash = null;
                var packetDataOffset = 4; // first four bytes are reserved for outbound packet sequence

                if (clientMac != null)
                {
                    // write outbound packet sequence to start of packet data
                    Pack.UInt32ToBigEndian(_outboundPacketSequence, packetData);
                    //  calculate packet hash
                    hash = clientMac.ComputeHash(packetData);
                }

                // Encrypt packet data
                if (clientCipher != null)
                {
                    packetData = clientCipher.Encrypt(packetData, packetDataOffset, (packetData.Length - packetDataOffset));
                    packetDataOffset = 0;
                }

                if (packetData.Length > Session.MaximumSshPacketSize)
                {
                    // TODO: publish error event, and transition to ERROR state

                    throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, "Packet is too big. Maximum packet size is {0} bytes.", Session.MaximumSshPacketSize));
                }

                var packetLength = packetData.Length - packetDataOffset;
                if (hash == null)
                {
                    SendPacketAsync(packetData, packetDataOffset, packetLength);
                    if (!_sendPacketCompleted.WaitOne(_timeout))
                    {
                        // TODO: publish error event, and transition to ERROR state
                    }
                }
                else
                {
                    SendPacketAsync(packetData, packetDataOffset, packetLength);
                    if (!_sendPacketCompleted.WaitOne(_timeout))
                    {
                        // TODO: publish error event, and transition to ERROR state
                    }
                    SendPacketAsync(hash, 0, hash.Length);
                    if (!_sendPacketCompleted.WaitOne(_timeout))
                    {
                        // TODO: publish error event, and transition to ERROR state
                    }
                }

                // increment the packet sequence number only after we're sure the packet has
                // been sent; even though it's only used for the MAC, it needs to be incremented
                // for each package sent.
                // 
                // the server will use it to verify the data integrity, and as such the order in
                // which messages are sent must follow the outbound packet sequence number
                _outboundPacketSequence++;
            }
        }

        /// <summary>
        /// Sends an SSH packet to the server.
        /// </summary>
        /// <param name="packet">A byte array containing the packet to send.</param>
        /// <param name="offset">The offset of the packet.</param>
        /// <param name="length">The length of the packet.</param>
        /// <exception cref="SshConnectionException">Client is not connected to the server.</exception>
        /// <remarks>
        /// <para>
        /// The send is performed in a dispose lock to avoid <see cref="NullReferenceException"/>
        /// and/or <see cref="ObjectDisposedException"/> when sending the packet.
        /// </para>
        /// <para>
        /// This method is only to be used when the connection is established, as the locking
        /// overhead is not required while establising the connection.
        /// </para>
        /// </remarks>
        private void SendPacketAsync(byte[] packet, int offset, int length)
        {
            lock (_disposeLock)
            {
                if (!_socket.Connected)
                {
                    // TODO: publish error event, and transition to ERROR state
                    throw new SshConnectionException("Client not connected.");
                }

                _writeSocketAsyncEventArgs.SetBuffer(packet, offset, length);
                if (!_socket.SendAsync(_writeSocketAsyncEventArgs))
                {
                    SocketOperationCompleted(this, _writeSocketAsyncEventArgs);
                }
            }
        }

        protected void Dispose(bool disposing)
        {
            if (disposing)
            {
                lock (_disposeLock)
                {
                    if (Transition(ListenerState.Disposed))
                    {
                        DoStop();

                        SocketDisconnectAndDispose();

                        _readSocketAsyncEventArgs.Dispose();
                        _writeSocketAsyncEventArgs.Dispose();

                        _processingCompleted.Dispose();
                        _sendPacketCompleted.Dispose();
                    }
                }
            }
        }

        public void Dispose()
        {
            DiagnosticAbstraction.Log(string.Format("[{0}] Disposing listener.", Session.ToHex(_session.SessionId)));

            Dispose(true);
            GC.SuppressFinalize(this);
        }

        public enum ListenerState
        {
            Initial = 1,
            Connected = 2,
            Ready = 3,
            FirstBlockRead = 4,
            Stopped = 5,
            Error = 6,
            Closed = 7,
            Disposed = 8
        }

        /*
        public class ListenerState
        {
            public static readonly ListenerState Initial = new ListenerState(1, "Initial");
            public static readonly ListenerState Connected = new ListenerState(2, "Connected");
            public static readonly ListenerState Ready = new ListenerState(3, "Ready");
            public static readonly ListenerState FirstBlockRead = new ListenerState(4, "FirstBlockRead");
            public static readonly ListenerState Stopped = new ListenerState(5, "Stopped");
            public static readonly ListenerState Error = new ListenerState(6, "Error");
            public static readonly ListenerState Closed = new ListenerState(7, "Closed");
            public static readonly ListenerState Disposed = new ListenerState(8, "Disposed");

            private readonly int _value;
            private readonly string _name;

            private ListenerState(int value, string name)
            {
                _value = value;
                _name = name;
            }

            public override bool Equals(object other)
            {
                var otherState = other as ListenerState;
                if (otherState == null)
                    return false;

                return _value == otherState._value;
            }

            public override int GetHashCode()
            {
                return _value;
            }

            public static bool operator ==(ListenerState x, ListenerState y)
            {
                if (ReferenceEquals(x, null))
                    return ReferenceEquals(y, null);
                if (ReferenceEquals(y, null))
                    return false;

                return x._value == y._value;
            }

            public static bool operator !=(ListenerState x, ListenerState y)
            {
                return !(x == y);
            }

            public override string ToString()
            {
                return _name;
            }
        }
        */
    }

    internal interface ISocketConnector
    {
        Socket Connect();
    }

    internal class RawSocketConnector : SocketConnectorBase
    {
        private readonly string _host;
        private readonly int _port;
        private readonly TimeSpan _timeout;

        public RawSocketConnector(string host, int port, TimeSpan timeout)
        {
            _host = host;
            _port = port;
            _timeout = timeout;
        }

        public override Socket Connect()
        {
            return ConnectSocket(_host, _port, _timeout);
        }
    }

    internal abstract class SocketConnectorBase : ISocketConnector
    {
        public abstract Socket Connect();

        protected static Socket ConnectSocket(string host, int port, TimeSpan timeout)
        {
            var ipAddress = DnsAbstraction.GetHostAddresses(host)[0];
            var ep = new IPEndPoint(ipAddress, port);

            DiagnosticAbstraction.Log(string.Format("Initiating connection to '{0}:{1}'.", host, port));

            var socket = SocketAbstraction.Connect(ep, timeout);

            const int socketBufferSize = 2 * Session.MaximumSshPacketSize;
            socket.SendBufferSize = socketBufferSize;
            socket.ReceiveBufferSize = socketBufferSize;

            return socket;
        }
    }

    internal class SocketReadBuffer
    {
        private readonly byte[] _buffer;

        public SocketReadBuffer(byte[] buffer)
        {
            _buffer = buffer;
        }

        public byte[] Buffer
        {
            get { return _buffer; }
        }

        public void Reset()
        {
            Position = 0;
            Size = 0;
        }

        public int Size { get; private set; }

        public int Position { get; private set; }

        public void Advance(int length)
        {
            Position += length;
        }
    }
}