// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using IPv8.Keyvault;
using IPv8.Messaging.Interfaces;

namespace IPv8.Messaging.Anonymization
{
    /// <summary>
    /// Add Diffie-Hellman key establishment logic to ECCrypto (crypto.py::TunnelCrypto).
    /// </summary>
    public sealed class TunnelCrypto
    {
        private PrivateKey _key;

        /// <summary>Make this crypto fit for key establishment based on the given private key.</summary>
        public void Initialize(PrivateKey key)
        {
            _key = key ?? throw new ArgumentNullException(nameof(key));
        }

        /// <summary>Whether the given key is compatible (curve25519).</summary>
        public bool IsKeyCompatible(PublicKey key)
        {
            return key.CurveName() == "curve25519";
        }

        /// <summary>Create a new private-public keypair (crypto.py::generate_diffie_secret).</summary>
        public (PrivateKey Key, byte[] CryptPk) GenerateDiffieSecret()
        {
            var tmpKey = ECCrypto.Default.GenerateKey("curve25519");
            return (tmpKey, tmpKey.GetCryptPk());
        }

        /// <summary>
        /// Generate the shared secret from the received string and the given key
        /// (crypto.py::generate_diffie_shared_secret). NOTE (rust dh.rs ground truth):
        /// PrivateKey.diffie_hellman(peer_pk, sk) == crypto_box_beforenm(peer_pk, sk) —
        /// the shared-secret halves are BEFORENM outputs (clamp + X25519 + HSalsa20),
        /// not raw X25519 outputs.
        /// </summary>
        public (byte[] SharedSecret, byte[] CryptPk, byte[] Auth) GenerateDiffieSharedSecret(
            byte[] dhReceived, PrivateKey key = null)
        {
            key ??= _key;
            if (key == null)
            {
                throw new CryptoException("No key initialized");
            }

            var tmpKey = ECCrypto.Default.GenerateKey("curve25519");
            var sharedSecret = Util.Concat(
                TunnelSessionCrypto.CryptoBoxBeforeNm(dhReceived, tmpKey.GetCryptSk()),
                TunnelSessionCrypto.CryptoBoxBeforeNm(dhReceived, key.GetCryptSk()));

            var cryptPk = tmpKey.GetCryptPk();
            var auth = TunnelSessionCrypto.CryptoAuth(Util.Slice(sharedSecret, 0, 32), cryptPk);

            return (sharedSecret, cryptPk, auth);
        }

        /// <summary>
        /// Generate the shared secret based on the response to the shared string and our own
        /// key (crypto.py::verify_and_generate_shared_secret) — the beforenm composition of
        /// rust dh.rs (see GenerateDiffieSharedSecret).
        /// </summary>
        public static byte[] VerifyAndGenerateSharedSecret(PrivateKey dhSecret, byte[] dhReceived,
                                                           byte[] auth, byte[] b)
        {
            var s1 = TunnelSessionCrypto.CryptoBoxBeforeNm(dhReceived, dhSecret.GetCryptSk());
            var s2 = TunnelSessionCrypto.CryptoBoxBeforeNm(b, dhSecret.GetCryptSk());
            var sharedSecret = Util.Concat(s1, s2);

            if (!TunnelSessionCrypto.CryptoAuthVerify(auth, Util.Slice(sharedSecret, 0, 32), dhReceived))
            {
                throw new CryptoException("Failed to verify the shared secret auth");
            }

            return sharedSecret;
        }

        /// <summary>
        /// Expand a shared secret into session keys using HKDF-SHA256
        /// (crypto.py::generate_session_keys).
        /// </summary>
        public static SessionKeys GenerateSessionKeys(byte[] sharedSecret)
        {
            return TunnelSessionCrypto.GenerateSessionKeys(sharedSecret);
        }

        /// <summary>Expose the key-material lookup of the parent ECCrypto.</summary>
        public PublicKey KeyFromPublicBin(byte[] keystring)
        {
            return ECCrypto.Default.KeyFromPublicBin(keystring);
        }
    }

    /// <summary>
    /// UDP endpoint capable of sending/relaying/exiting CellPayloads
    /// (crypto.py::CryptoEndpoint; an interface in C# because PythonCryptoEndpoint also
    /// derives from EndpointListener, which Python reaches through multiple inheritance).
    /// </summary>
    public interface ICryptoEndpoint
    {
        TunnelSettings Settings { get; set; }
        byte[] Prefix { get; set; }
        Dictionary<long, Circuit> Circuits { get; }
        Dictionary<long, RelayRoute> Relays { get; }
        Dictionary<long, TunnelExitSocket> ExitSockets { get; }

        /// <summary>Set up the TunnelCommunity.</summary>
        void SetupTunnels(TunnelCommunity tunnelCommunity, TunnelSettings settings);

        /// <summary>
        /// Send the given payload directly to the given peer with the appropriate encryption rules.
        /// </summary>
        void SendCell(Address targetAddr, CellPayload cell);
    }

    /// <summary>
    /// UDP endpoint capable of sending/relaying/exiting CellPayloads
    /// (crypto.py::PythonCryptoEndpoint).
    /// </summary>
    public class PythonCryptoEndpoint : EndpointListener, ICryptoEndpoint
    {
        public TunnelSettings Settings { get; set; }
        public byte[] Prefix { get; set; } = new byte[22];
        public Dictionary<long, Circuit> Circuits { get; } = new Dictionary<long, Circuit>();
        public Dictionary<long, RelayRoute> Relays { get; } = new Dictionary<long, RelayRoute>();
        public Dictionary<long, TunnelExitSocket> ExitSockets { get; } = new Dictionary<long, TunnelExitSocket>();

        public TunnelCommunity TunnelCommunity { get; private set; }

        public PythonCryptoEndpoint(Endpoint endpoint) : base(endpoint)
        {
        }

        /// <summary>The maximum number of relay_early cells that are allowed to pass a relay.</summary>
        public int MaxRelayEarly => Settings?.MaxRelayEarly ?? 8;

        public void SetupTunnels(TunnelCommunity tunnelCommunity, TunnelSettings settings)
        {
            Prefix = tunnelCommunity.GetPrefix();
            Settings = settings;

            // Packets will go through the CryptoEndpoint before they end up in the tunnel community.
            Endpoint.RemoveListener(tunnelCommunity);
            // Ensure multiple calls don't keep adding the same listener.
            Endpoint.RemoveListener(this);
            Endpoint.AddPrefixListener(this, Prefix);
            TunnelCommunity = tunnelCommunity;
        }

        /// <summary>Callback for when data is received on this endpoint.</summary>
        public override void OnPacket(Packet packet)
        {
            OnPacket(packet.SourceAddress, packet.Data);
        }

        public void OnPacket(Address sourceAddress, byte[] datagram, bool warnUnknown = true)
        {
            if (Util.StartsWith(datagram, Prefix) && datagram[22] == CellPayload.MsgId)
            {
                ProcessCell(sourceAddress, datagram);
            }
            else if (TunnelCommunity != null)
            {
                TunnelCommunity.OnPacket(new Packet(sourceAddress, datagram));
            }
        }

        /// <summary>
        /// Send the given payload directly to the given peer with the appropriate encryption rules.
        /// (virtual so tests can sniff outgoing cells).
        /// </summary>
        public virtual void SendCell(Address targetAddr, CellPayload cell)
        {
            var circuitId = cell.CircuitId;
            Circuits.TryGetValue(circuitId, out var circuit);
            Relays.TryGetValue(circuitId, out var relay);

            if (circuit != null)
            {
                cell.RelayEarly = cell.Message[0] == 4 || circuit.RelayEarlyCount < MaxRelayEarly;
                if (cell.RelayEarly)
                {
                    circuit.RelayEarlyCount += 1;
                }
            }

            if (OutgoingCrypto(cell) == null)
            {
                return;
            }

            var packet = cell.ToBin(Prefix);
            OnWireSent(packet);
            Endpoint.Send(targetAddr, packet);

            var tunnelObj = (RoutingObject)circuit ?? (RoutingObject)relay;
            if (tunnelObj != null)
            {
                tunnelObj.BytesUp += packet.Length;
            }
        }

        /// <summary>Hook invoked with the FINAL wire packet right before it hits the endpoint
        /// (post relay_early adjustment and post encryption). For wire-level test assertions.</summary>
        protected virtual void OnWireSent(byte[] packet)
        {
        }

        public void ProcessCell(Address sourceAddress, byte[] data)
        {
            var cell = CellPayload.FromBin(data);
            var circuitId = cell.CircuitId;

            if (Relays.TryGetValue(circuitId, out var nextRelay))
            {
                if (Relays.TryGetValue(nextRelay.CircuitId, out var thisRelay))
                {
                    thisRelay.BeatHeart();
                    thisRelay.BytesDown += data.Length;
                }
                RelayCell(cell);
                return;
            }

            if (IncomingCrypto(cell) == null)
            {
                return;
            }

            if ((!cell.RelayEarly && cell.Message[0] == 4) || MaxRelayEarly <= 0)
            {
                // Dropping cell (missing or unexpected relay_early flag).
                return;
            }
            if (cell.Plaintext && !AnonymizationCells.IsNoCrypto(cell.Message[0]))
            {
                // Dropping cell (only create/created can have plaintext flag set).
                return;
            }

            if (TunnelCommunity == null)
            {
                return;
            }

            TunnelCommunity.OnPacket(new Packet(sourceAddress, cell.ToBin(Prefix)));

            if (Circuits.TryGetValue(cell.CircuitId, out var circuit))
            {
                circuit.BeatHeart();
                circuit.BytesDown += data.Length;
            }
        }

        public void RelayCell(CellPayload cell)
        {
            if (cell.Plaintext)
            {
                // Dropping cell (cell not encrypted).
                return;
            }

            var nextRelay = Relays[cell.CircuitId];

            if (cell.RelayEarly && nextRelay.RelayEarlyCount >= MaxRelayEarly)
            {
                // Dropping cell (too many relay_early cells).
                return;
            }

            try
            {
                if (nextRelay.RendezvousRelay)
                {
                    DecryptCell(cell, Tunnel.Forward, nextRelay.Hop);
                    var thisRelay = Relays[nextRelay.CircuitId];
                    EncryptCell(cell, Tunnel.Backward, thisRelay.Hop);
                    cell.RelayEarly = false;
                }
                else
                {
                    var direction = nextRelay.Direction;
                    if (direction == Tunnel.Forward)
                    {
                        DecryptCell(cell, direction, nextRelay.Hop);
                    }
                    else if (direction == Tunnel.Backward)
                    {
                        EncryptCell(cell, direction, nextRelay.Hop);
                    }
                }
            }
            catch (CryptoException)
            {
                // Failed to relay the cell; drop it.
                return;
            }

            cell.CircuitId = nextRelay.CircuitId;
            var packet = cell.ToBin(Prefix);
            Endpoint.Send(nextRelay.Hop.Address, packet);
            nextRelay.BytesUp += packet.Length;
            nextRelay.RelayEarlyCount += 1;
        }

        /// <summary>
        /// Encrypt a CellPayload using the SessionKeys currently available in the routing
        /// table (crypto.py::outgoing_crypto). Returns null if encryption failed.
        /// </summary>
        private CellPayload OutgoingCrypto(CellPayload cell)
        {
            var circuitId = cell.CircuitId;
            Circuits.TryGetValue(circuitId, out var circuit);
            ExitSockets.TryGetValue(circuitId, out var exitSocket);
            Relays.TryGetValue(circuitId, out var relay);

            try
            {
                if (circuit != null)
                {
                    if (circuit.HsSessionKeys != null)
                    {
                        var direction = circuit.CType == Tunnel.CircuitTypeRpSeeder
                            ? Tunnel.Forward
                            : Tunnel.Backward;
                        EncryptCell(cell, direction, new Hop(circuit.Hop.Peer, circuit.HsSessionKeys));
                    }
                    EncryptCell(cell, Tunnel.Forward, Compress(circuit.Hops));
                }
                else if (exitSocket != null)
                {
                    EncryptCell(cell, Tunnel.Backward, exitSocket.Hop);
                }
                else if (relay != null)
                {
                    if (relay.RendezvousRelay)
                    {
                        EncryptCell(cell, Tunnel.Backward, relay.Hop);
                    }
                    else
                    {
                        // We should only get here directly after a created message has been accepted.
                        var other = Relays[relay.CircuitId];
                        EncryptCell(cell, other.Direction, other.Hop);
                    }
                }
            }
            catch (CryptoException)
            {
                return null;
            }

            return cell;
        }

        /// <summary>
        /// Decrypt a CellPayload using the SessionKeys currently available in the routing
        /// table (crypto.py::incoming_crypto). Returns null if decryption failed.
        /// </summary>
        private CellPayload IncomingCrypto(CellPayload cell)
        {
            var circuitId = cell.CircuitId;
            Circuits.TryGetValue(circuitId, out var circuit);
            ExitSockets.TryGetValue(circuitId, out var exitSocket);

            if (circuit == null && exitSocket == null && !cell.Plaintext)
            {
                // Got encrypted cell from unknown circuit.
                return null;
            }

            try
            {
                if (exitSocket != null)
                {
                    DecryptCell(cell, Tunnel.Forward, exitSocket.Hop);
                }
                else if (circuit != null)
                {
                    DecryptCell(cell, Tunnel.Backward, Compress(circuit.Hops));
                    if (circuit.HsSessionKeys != null)
                    {
                        var direction = circuit.CType == Tunnel.CircuitTypeRpDownloader
                            ? Tunnel.Forward
                            : Tunnel.Backward;
                        DecryptCell(cell, direction, new Hop(circuit.Hop.Peer, circuit.HsSessionKeys));
                    }
                }
            }
            catch (CryptoException)
            {
                return null;
            }
            return cell;
        }

        public void EncryptCell(CellPayload cell, int direction, params Hop[] hops)
        {
            if (cell.Plaintext)
            {
                return;
            }

            for (var layer = 0; layer < hops.Length; layer++)
            {
                // py-ipv8 iterates over the REVERSED hop list while encrypting.
                var hop = hops[hops.Length - 1 - layer];
                if (hop.Keys == null)
                {
                    throw new CryptoException(
                        $"Missing keys for circuit {cell.CircuitId} (layer {layer + 1}/{hops.Length})");
                }

                try
                {
                    cell.Message = hop.Keys.EncryptStr(cell.Message, direction);
                }
                catch (Exception e)
                {
                    throw new CryptoException(
                        $"Failed to encrypt cell for {cell.CircuitId} (dir {direction}) (layer {layer + 1}/{hops.Length})", e);
                }
            }
        }

        public void DecryptCell(CellPayload cell, int direction, params Hop[] hops)
        {
            if (cell.Plaintext)
            {
                return;
            }

            for (var layer = 0; layer < hops.Length; layer++)
            {
                var hop = hops[layer];
                if (hop.Keys == null)
                {
                    throw new CryptoException(
                        $"Missing session keys for {cell.CircuitId} (layer {layer + 1}/{hops.Length})");
                }

                try
                {
                    cell.Message = hop.Keys.DecryptStr(cell.Message, direction);
                }
                catch (CryptoException)
                {
                    throw;
                }
                catch (Exception e)
                {
                    throw new CryptoException(
                        $"Failed to decrypt cell for {cell.CircuitId} (dir {direction}) (layer {layer + 1}/{hops.Length})", e);
                }
            }
        }

        private static Hop[] Compress(IReadOnlyList<Hop> hops)
        {
            var result = new Hop[hops.Count];
            for (var i = 0; i < hops.Count; i++)
            {
                result[i] = hops[i];
            }
            return result;
        }
    }
}
