
//
// Copyright (c) Michael Eddington
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Threading;
using System.Net.Sockets;

using System.Net.Security;
using System.Collections;
using System.Security.Cryptography.X509Certificates;
using System.Diagnostics;
using System.Security.Authentication;


using Peach.Core.Dom;

using NLog;
using System.Net;
using Peach.Core.IO;

namespace Peach.Core.Publishers
{
	public abstract class TlsPublisher : BufferedStreamPublisher
	{
		public ushort Port { get; set; }

		protected SslStream _tls = null;
		protected TcpClient _tcp = null;
		protected EndPoint _localEp = null;
		protected EndPoint _remoteEp = null;

		public TlsPublisher(Dictionary<string, Variant> args)
			: base(args)
		{
		}

		protected override void StartClient()
		{
			System.Diagnostics.Debug.Assert(_tls != null);
			System.Diagnostics.Debug.Assert(_tcp != null);
			System.Diagnostics.Debug.Assert(_client == null);
			System.Diagnostics.Debug.Assert(_localEp == null);
			System.Diagnostics.Debug.Assert(_remoteEp == null);

			try
			{
				_client = new MemoryStream();
				_localEp = _tcp.Client.LocalEndPoint;
				_remoteEp = _tcp.Client.RemoteEndPoint;
				_clientName = _remoteEp.ToString();
			}
			catch (Exception ex)
			{
				Logger.Error("open: Error, Unable to start tcp client reader. {0}.", ex.Message);
				throw new SoftException(ex);
			}

			base.StartClient();
		}

		protected override void ClientClose()
		{
			_tls.Close();
			_tcp.Close();
			_tls = null;
			_tcp = null;
			_remoteEp = null;
			_localEp = null;
		}

		protected override IAsyncResult ClientBeginRead(byte[] buffer, int offset, int count, AsyncCallback callback, object state)
		{
			return _tcp.Client.BeginReceive(buffer, offset, count, SocketFlags.None, callback, state);
		}

		protected override int ClientEndRead(IAsyncResult asyncResult)
		{
			return _tcp.Client.EndReceive(asyncResult);
		}

		protected override void ClientShutdown()
		{
			_tcp.Client.Shutdown(SocketShutdown.Send);
		}

		protected override IAsyncResult ClientBeginWrite(byte[] buffer, int offset, int count, AsyncCallback callback, object state)
		{
			return _tcp.Client.BeginSend(buffer, offset, count, SocketFlags.None, callback, state);
		}

		protected override int ClientEndWrite(IAsyncResult asyncResult)
		{
			return _tcp.Client.EndSend(asyncResult);
		}
	}

	[Publisher("Tls", true)]
	[Publisher("TlsClient")]
	[Publisher("tcp.Tls")]
	[Parameter("Host", typeof(string), "Hostname or IP address of remote host")]
	[Parameter("Port", typeof(ushort), "Local port to listen on")]
	[Parameter("Timeout", typeof(int), "How many milliseconds to wait when receiving data (default 3000)", "3000")]
	[Parameter("SendTimeout", typeof(int), "How many milliseconds to wait when sending data (default infinite)", "0")]
	[Parameter("ConnectTimeout", typeof(int), "Max milliseconds to wait for connection (default 10000)", "10000")]
	public class TlsClientPublisher : TlsPublisher
	{
		private static NLog.Logger logger = LogManager.GetCurrentClassLogger();
		protected override NLog.Logger Logger { get { return logger; } }

		public string Host { get; set; }
		public int ConnectTimeout { get; set; }

		public TlsClientPublisher(Dictionary<string, Variant> args)
			: base(args)
		{
		}

        // The following method is invoked by the RemoteCertificateValidationDelegate.
        public bool ValidateServerCertificate(
              object sender,
              X509Certificate certificate,
              X509Chain chain,
              SslPolicyErrors sslPolicyErrors) {
            // No errors with the certificate all is well
            if (sslPolicyErrors == SslPolicyErrors.None) {
                return true;
            }

            // There are errors with the certificate
            Logger.Error("tls: Certificate error: {0}.", sslPolicyErrors);
            // Do not allow this client to communicate with unauthenticated servers.
            return false;
        }

		protected override void OnOpen() {
			base.OnOpen();

			var timeout = ConnectTimeout;
			var sw = new Stopwatch();

			for (int i = 1; _tcp == null; i *= 2) {
				try {
					// Must build a new client object after every failed attempt to connect.
					// For some reason, just calling BeginConnect again does not work on mono.
					_tcp = new TcpClient();

					sw.Restart();

					var ar = _tcp.BeginConnect(Host, Port, null, null);
					if (!ar.AsyncWaitHandle.WaitOne(TimeSpan.FromMilliseconds(timeout))) {
						throw new TimeoutException();
                    }
					_tcp.EndConnect(ar);

					// Create an SSL stream that will close the client's stream.
					_tls = new SslStream(
						_tcp.GetStream(),
						false,
						new RemoteCertificateValidationCallback(ValidateServerCertificate),
						null
                    );

					// The server name must match the name on the server certificate.
					try {
						_tls.AuthenticateAsClient(Host);
					} catch (AuthenticationException ex) {
                        if (_tcp != null) {
                            _tcp.Close();
                            _tcp = null;
                        }
                        if (_tls != null) {
                            _tls.Close();
                            _tls = null;
                        }

						Logger.Error("tls: Error, Upable to authenticate host {0}.", Host);
						throw new SoftException(ex);
					}
				}
				catch (Exception ex) {
					sw.Stop();

					if (_tcp != null) {
						_tcp.Close();
						_tcp = null;
					}
                    if (_tls != null) {
                        _tls.Close();
                        _tls = null;
                    }

					timeout -= (int)sw.ElapsedMilliseconds;

					if (timeout > 0) {
						int waitTime = Math.Min(timeout, i);
						timeout -= waitTime;

						Logger.Warn("open: Warn, Unable to connect to remote host {0} on port {1}.  Trying again in {2}ms...", Host, Port, waitTime);
						Thread.Sleep(waitTime);
					} else {
						Logger.Error("open: Error, Unable to connect to remote host {0} on port {1}.", Host, Port);
						throw new SoftException(ex);
					}
				}
			}

			StartClient();
		}
	}
}
