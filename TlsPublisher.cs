
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
			return _tls.BeginRead(buffer, offset, count, callback, state);
		}

		protected override int ClientEndRead(IAsyncResult asyncResult)
		{
			return _tls.EndRead(asyncResult);
		}

		protected override void ClientShutdown()
		{
			_tls.Close();
		}

		protected override IAsyncResult ClientBeginWrite(byte[] buffer, int offset, int count, AsyncCallback callback, object state)
		{
			return _tls.BeginWrite(buffer, offset, count, callback, state);
		}

		protected override int ClientEndWrite(IAsyncResult asyncResult)
		{
			_tls.EndWrite(asyncResult);
            return 1;
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

		public TlsClientPublisher(Dictionary<string, Variant> args) : base(args) {
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
            // return false;
            return true;
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

                    try {
                        // Create an SSL stream that will close the client's stream.
                        _tls = new SslStream(
                            _tcp.GetStream(),
                            false,
                            new RemoteCertificateValidationCallback(ValidateServerCertificate),
                            null
                        );
					} catch (Exception ex) {
						Logger.Error("tls: Error, On creation of SslStream {0}.", ex.ToString());
						throw new SoftException(ex);
					}

					// The server name must match the name on the server certificate.
					try {
						_tls.AuthenticateAsClient(Host);
					} catch (AuthenticationException ex) {
						Logger.Error("tls: Error, Unable to authenticate host {0}.", Host);
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

	[Publisher("TlsListener", true)]
	[Publisher("tcp.TlsListener")]
	[Parameter("Interface", typeof(IPAddress), "IP of interface to bind to")]
	[Parameter("Port", typeof(ushort), "Local port to listen on")]
	[Parameter("Timeout", typeof(int), "How many milliseconds to wait when receiving data (default 3000)", "3000")]
	[Parameter("SendTimeout", typeof(int), "How many milliseconds to wait when sending data (default infinite)", "0")]
	[Parameter("AcceptTimeout", typeof(int), "How many milliseconds to wait for a connection (default 3000)", "3000")]
	[Parameter("CertificateFile", typeof(string), "PEM certificate to use")]
	public class TlsListenerPublisher : TlsPublisher
	{
		private static NLog.Logger logger = LogManager.GetCurrentClassLogger();
		protected override NLog.Logger Logger { get { return logger; } }

		public IPAddress Interface { get; set; }
		public int AcceptTimeout { get; set; }

		protected string CertificateFile { get; set; }
        protected X509Certificate2 _certificate = null;

		protected TcpListener _listener = null;

		public TlsListenerPublisher(Dictionary<string, Variant> args)
			: base(args)
		{
		}

		protected override void OnOpen()
		{
			System.Diagnostics.Debug.Assert(_listener == null);
			System.Diagnostics.Debug.Assert(_certificate == null);

            try
            {
                _certificate = new X509Certificate2(CertificateFile);
			}
			catch (Exception ex)
			{
				throw new PeachException("Error, unable to read server PEM " +
					CertificateFile + ": " + ex.Message, ex);
			}

			try
			{
				_listener = new TcpListener(Interface, Port);
				_listener.Start();
			}
			catch (Exception ex)
			{
				throw new PeachException("Error, unable to bind to interface " +
					Interface + " on port " + Port + ": " + ex.Message, ex);
			}

			base.OnOpen();
		}

		protected override void OnClose()
		{
			if (_listener != null)
			{
				_listener.Stop();
				_listener = null;
			}

			base.OnClose();
		}

		protected override void OnAccept()
		{
			// Ensure any open stream is closed...
			base.OnClose();

			try
			{
				var ar = _listener.BeginAcceptTcpClient(null, null);
				if (!ar.AsyncWaitHandle.WaitOne(TimeSpan.FromMilliseconds(AcceptTimeout)))
					throw new TimeoutException();
				_tcp = _listener.EndAcceptTcpClient(ar);
                _tls = new SslStream(_tcp.GetStream(), false);
                _tls.AuthenticateAsServer(_certificate, false, SslProtocols.Tls, true);
			}
			catch (Exception ex)
			{
				throw new SoftException(ex);
			}

			// Start receiving on the client
			StartClient();
		}
	}
}
