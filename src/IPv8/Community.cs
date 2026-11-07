// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IPv8.Messaging;
using IPv8.Messaging.Interfaces;

namespace IPv8
{
    /// <summary>Callback for packets decoded to a message number: (source address, raw packet bytes).</summary>
    public delegate Task? PacketHandler(Address sourceAddress, byte[] data);

    /// <summary>
    /// Base class for overlay functionality with a rich set of defaults — port of
    /// ipv8/community.py::Community (Phase 1a subset: introductions, punctures, walking).
    /// </summary>
    public abstract class Community : EZPackOverlay
    {
        public const byte Version = 0x02;

        public const int DefaultMaxPeers = 30;

        private static readonly int[] DeprecatedMessageNumbers =
        {
            255, 254, 253, 252, 251, 248, 247, 244, 243, 242, 241, 240, 239, 238, 237, 236, 235
        };

        private static readonly Dictionary<int, string> DeprecatedMessageNames = new Dictionary<int, string>
        {
            { 255, "reserved-255" },
            { 254, "on-missing-sequence" },
            { 253, "missing-proof" },
            { 252, "signature-request" },
            { 251, "signature-response" },
            { 248, "on-identity" },
            { 247, "on-missing-identity" },
            { 244, "destroy-community" },
            { 243, "authorize" },
            { 242, "revoke" },
            { 241, "subjective-set" },
            { 240, "missing-subjective-set" },
            { 239, "on-missing-message" },
            { 238, "undo-own" },
            { 237, "undo-other" },
            { 236, "dynamic-settings" },
            { 235, "missing-last-message" }
        };

        private readonly byte[] _prefix;
        private readonly PacketHandler?[] _decodeMap = new PacketHandler?[256];
        private static readonly Random ChoiceRng = new Random();

        protected Community(CommunitySettings settings, byte[] communityId) : base(WithCommunityId(settings, communityId))
        {
            if (communityId == null || communityId.Length != 20)
            {
                throw new ArgumentException("Attempted to launch a Community without a 20-byte community_id!");
            }
            // community.py: self._prefix = b"\x00" + self.version + self.community_id
            _prefix = new byte[22];
            _prefix[0] = 0x00;
            _prefix[1] = Version;
            Array.Copy(communityId, 0, _prefix, 2, 20);

            MaxPeers = settings.MaxPeers;

            Network.RegisterServiceProvider(communityId, this);
            Network.BlacklistMids.Add(MyPeer.Mid);

            AddMessageHandler(typeof(PunctureRequestPayload), OnOldPunctureRequest);
            AddMessageHandler(typeof(PuncturePayload), OnPuncture);
            AddMessageHandler(typeof(NewPunctureRequestPayload), OnNewPunctureRequest);
            AddMessageHandler(typeof(NewPuncturePayload), OnNewPuncture);
            AddMessageHandler(typeof(IntroductionRequestPayload), OnOldIntroductionRequest);
            AddMessageHandler(typeof(IntroductionResponsePayload), OnOldIntroductionResponse);
            AddMessageHandler(typeof(NewIntroductionRequestPayload), OnNewIntroductionRequest);
            AddMessageHandler(typeof(NewIntroductionResponsePayload), OnNewIntroductionResponse);

            foreach (var deprecated in DeprecatedMessageNumbers)
            {
                AddMessageHandler(deprecated, OnDeprecatedMessage);
            }
        }

        private static CommunitySettings WithCommunityId(CommunitySettings settings, byte[] communityId)
        {
            settings.CommunityId = communityId;
            return settings;
        }

        /// <summary>The number of peers we will grow to before we start rejecting new connections.</summary>
        public int MaxPeers { get; }

        /// <summary>The 22-byte packet prefix: 0x00, version, community_id.</summary>
        public byte[] Prefix => _prefix;

        public override byte[] GetPrefix() => _prefix;

        /// <summary>
        /// Add a handler for a message identifier. Any messages coming in with this identifier will be
        /// delivered to the specified callback function.
        /// </summary>
        protected void AddMessageHandler(int msgNum, PacketHandler callback)
        {
            if (msgNum < 0 || msgNum > 255)
            {
                throw new ArgumentException(
                    $"Attempted to add a handler for message number {msgNum}, which is not a byte!");
            }
            if (_decodeMap[msgNum] != null)
            {
                throw new InvalidOperationException(
                    $"Attempted to add a handler for message number {msgNum}, already mapped!");
            }
            _decodeMap[msgNum] = callback;
        }

        /// <summary>
        /// Add a handler for a Payload type: reads the static ``MsgId`` field of the payload class.
        /// </summary>
        protected void AddMessageHandler(Type payloadType, PacketHandler callback)
        {
            var field = payloadType.GetField("MsgId");
            if (field == null)
            {
                throw new ArgumentException(
                    $"Attempted to add a handler for Payload {payloadType.Name}, which does not specify a MsgId!");
            }
            AddMessageHandler((int)field.GetValue(null), callback);
        }

        /// <summary>Callback for when we receive a known-to-be-deprecated message.</summary>
        protected virtual Task? OnDeprecatedMessage(Address sourceAddress, byte[] data)
        {
            Console.Error.WriteLine(
                $"Received deprecated message: {DeprecatedMessageNames[data[22]]} from {sourceAddress}");
            return null;
        }

        /// <summary>
        /// Create a new introduction request message, without sending it.
        /// </summary>
        public byte[] CreateIntroductionRequest(Address socketAddress, byte[] extraBytes = null,
                                                bool newStyle = false, byte[] prefix = null)
        {
            var globalTime = ClaimGlobalTime() % 65536;
            Payload payload;
            if (newStyle || socketAddress.Type == AddressType.Udpv6)
            {
                payload = new NewIntroductionRequestPayload(socketAddress, MyEstimatedLan, MyPreferredAddress(),
                                                            (long)globalTime, 0, 0, 0, 0, 0, 0, 0, 0,
                                                            extraBytes ?? Util.EmptyBytes);
            }
            else
            {
                // Only supports IPv4 addresses as UDPv4 flavors.
                payload = new IntroductionRequestPayload(socketAddress,
                                                         MyEstimatedLan,
                                                         MyEstimatedWan,
                                                         true,
                                                         "unknown",
                                                         (int)globalTime,
                                                         extraBytes ?? Util.EmptyBytes,
                                                         supportsNewStyle: newStyle);
            }
            var auth = new BinMemberAuthenticationPayload(MyPeer.PublicKey.KeyToBin());
            var dist = new GlobalTimeDistributionPayload(globalTime);

            return EzPack(prefix ?? _prefix, payload.MsgNum, new Payload[] { auth, dist, payload });
        }

        /// <summary>
        /// Create a new introduction response message, without sending it.
        /// </summary>
        public byte[] CreateIntroductionResponse(Address lanSocketAddress, Address socketAddress, long identifier,
                                                 Peer introduction = null, byte[] extraBytes = null,
                                                 byte[] prefix = null, bool newStyle = false)
        {
            var globalTime = ClaimGlobalTime() % 65536;
            var introductionLan = Address.Zero;
            var introductionWan = Address.Zero;
            var introduced = false;
            var other = Network.GetVerifiedByAddress(socketAddress);
            if (introduction == null)
            {
                introduction = GetPeerForIntroduction(exclude: other, newStyle: newStyle);
            }
            if (introduction != null)
            {
                if (introduction.Address.IsUdpv4 && AddressIsLan(introduction.Address.Host))
                {
                    introductionLan = introduction.Address;
                    introductionWan = new Address(AddressType.Udpv4, MyEstimatedWan.Host,
                                                  introductionLan.Port);
                }
                else
                {
                    introductionLan = introduction.Addresses.TryGetValue(AddressType.Udpv4Lan, out var lanAddress)
                        ? lanAddress
                        : Address.Zero;
                    introductionWan = introduction.Address;
                }
                introduced = true;
            }
            var newStyleIntro = introduction?.NewStyleIntro ?? false;
            Payload payload;
            if (newStyle)
            {
                payload = new NewIntroductionResponsePayload(socketAddress, MyEstimatedLan, MyPreferredAddress(),
                                                             introductionLan, introductionWan, identifier,
                                                             newStyleIntro, 0, 0, 0, 0, 0, 0, 0,
                                                             extraBytes ?? Util.EmptyBytes);
            }
            else
            {
                payload = new IntroductionResponsePayload(socketAddress,
                                                          MyEstimatedLan,
                                                          MyEstimatedWan,
                                                          introductionLan,
                                                          introductionWan,
                                                          "unknown",
                                                          (int)identifier,
                                                          extraBytes ?? Util.EmptyBytes,
                                                          introSupportsNewStyle: newStyleIntro,
                                                          peerLimitReached:
                                                          0 <= MaxPeers && MaxPeers <= GetPeers().Count);
            }
            var auth = new BinMemberAuthenticationPayload(MyPeer.PublicKey.KeyToBin());
            var dist = new GlobalTimeDistributionPayload(globalTime);

            if (introduced && introduction != null)
            {
                var puncturePacket = CreatePunctureRequest(lanSocketAddress, socketAddress, identifier,
                                                           prefix: prefix, newStyle: newStyle);
                Endpoint.Send(introduction.Address, puncturePacket);
            }

            return EzPack(prefix ?? _prefix, payload.MsgNum, new Payload[] { auth, dist, payload });
        }

        /// <summary>Create a puncture message for the given LAN/WAN address.</summary>
        public byte[] CreatePuncture(Address lanWalker, Address wanWalker, long identifier, bool newStyle = false)
        {
            var globalTime = ClaimGlobalTime();
            Payload payload;
            if (newStyle)
            {
                payload = new NewPuncturePayload(lanWalker, wanWalker, identifier);
            }
            else
            {
                payload = new PuncturePayload(lanWalker, wanWalker, (int)identifier);
            }
            var auth = new BinMemberAuthenticationPayload(MyPeer.PublicKey.KeyToBin());
            var dist = new GlobalTimeDistributionPayload(globalTime);

            return EzPack(_prefix, payload.MsgNum, new Payload[] { auth, dist, payload });
        }

        /// <summary>Create a request for another peer to puncture a given LAN/WAN address pair.</summary>
        public byte[] CreatePunctureRequest(Address lanWalker, Address wanWalker, long identifier,
                                            byte[] prefix = null, bool newStyle = false)
        {
            var globalTime = ClaimGlobalTime();
            Payload payload;
            if (newStyle || !lanWalker.IsIpv4 || !wanWalker.IsIpv4)
            {
                payload = new NewPunctureRequestPayload(lanWalker, wanWalker, identifier);
            }
            else
            {
                payload = new PunctureRequestPayload(lanWalker, wanWalker, (int)identifier);
            }
            var dist = new GlobalTimeDistributionPayload(globalTime);

            // Puncture requests are unsigned and carry no authentication payload.
            return EzPack(prefix ?? _prefix, payload.MsgNum, new Payload[] { dist, payload }, false);
        }

        /// <summary>
        /// Callback that gets called after an introduction-request has been processed.
        /// </summary>
        protected virtual void IntroductionRequestCallback(Peer peer, GlobalTimeDistributionPayload dist,
                                                           Payload payload)
        {
        }

        /// <summary>
        /// Callback that gets called after an introduction-response has been processed.
        /// </summary>
        protected virtual void IntroductionResponseCallback(Peer peer, GlobalTimeDistributionPayload dist,
                                                            Payload payload)
        {
        }

        private Task? OnOldIntroductionRequest(Address sourceAddress, byte[] data)
        {
            var decoded = EzUnpackAuth<IntroductionRequestPayload>(sourceAddress, data);
            if (decoded.Payload.SupportsNewStyle)
            {
                decoded.Peer.NewStyleIntro = true;
            }
            OnIntroductionRequest(decoded.Peer, decoded.Dist, decoded.Payload);
            return null;
        }

        private Task? OnNewIntroductionRequest(Address sourceAddress, byte[] data)
        {
            var decoded = EzUnpackAuth<NewIntroductionRequestPayload>(sourceAddress, data);
            decoded.Peer.NewStyleIntro = true;
            OnIntroductionRequest(decoded.Peer, decoded.Dist, decoded.Payload);
            return null;
        }

        /// <summary>Callback to handle introduction requests: we respond with an introduction response.</summary>
        protected virtual void OnIntroductionRequest(Peer peer, GlobalTimeDistributionPayload dist,
                                                     IntroductionRequestPayload payload)
            => OnIntroductionRequestCore(peer, dist, payload.DestinationAddress, payload.SourceLanAddress,
                                         payload.Identifier);

        /// <summary>Callback to handle new-style introduction requests.</summary>
        protected virtual void OnIntroductionRequest(Peer peer, GlobalTimeDistributionPayload dist,
                                                     NewIntroductionRequestPayload payload)
            => OnIntroductionRequestCore(peer, dist, payload.DestinationAddress, payload.SourceLanAddress,
                                         payload.Identifier);

        /// <summary>
        /// Core of the introduction-request handling (py-ipv8 on_introduction_request): we respond
        /// with an introduction response.
        /// </summary>
        protected virtual void OnIntroductionRequestCore(Peer peer, GlobalTimeDistributionPayload dist,
                                                         Address destinationAddress, Address sourceLanAddress,
                                                         long identifier)
        {
            if (0 <= MaxPeers && MaxPeers < GetPeers().Count)
            {
                // Dropping introduction request: too many peers!
                return;
            }

            if (sourceLanAddress.Type == AddressType.Udpv4)
            {
                peer.AddAddress(Address.Udpv4Lan(sourceLanAddress.Host, sourceLanAddress.Port));
            }
            Network.AddVerifiedPeer(peer);
            Network.DiscoverServices(peer, new[] { CommunityId });

            var packet = CreateIntroductionResponse(destinationAddress, peer.Address,
                                                    identifier, newStyle: peer.NewStyleIntro);
            Endpoint.Send(peer.Address, packet);

            IntroductionRequestCallback(peer, dist, null);
        }

        private Task? OnOldIntroductionResponse(Address sourceAddress, byte[] data)
        {
            var decoded = EzUnpackAuth<IntroductionResponsePayload>(sourceAddress, data);
            if (decoded.Payload.SupportsNewStyle)
            {
                decoded.Peer.NewStyleIntro = true;
            }
            OnIntroductionResponse(decoded.Peer, decoded.Dist, decoded.Payload);
            return null;
        }

        private Task? OnNewIntroductionResponse(Address sourceAddress, byte[] data)
        {
            var decoded = EzUnpackAuth<NewIntroductionResponsePayload>(sourceAddress, data);
            decoded.Peer.NewStyleIntro = true;
            OnIntroductionResponse(decoded.Peer, decoded.Dist, decoded.Payload);
            return null;
        }

        /// <summary>Callback to handle introduction responses.</summary>
        protected virtual void OnIntroductionResponse(Peer peer, GlobalTimeDistributionPayload dist,
                                                      IntroductionResponsePayload payload)
            => OnIntroductionResponseCore(peer, dist, payload.DestinationAddress, payload.SourceWanAddress,
                                          payload.LanIntroductionAddress, payload.WanIntroductionAddress,
                                          payload.Identifier, payload.IntroSupportsNewStyle);

        /// <summary>Callback to handle new-style introduction responses.</summary>
        protected virtual void OnIntroductionResponse(Peer peer, GlobalTimeDistributionPayload dist,
                                                      NewIntroductionResponsePayload payload)
            => OnIntroductionResponseCore(peer, dist, payload.DestinationAddress, payload.SourceWanAddress,
                                          payload.LanIntroductionAddress, payload.WanIntroductionAddress,
                                          payload.Identifier, payload.IntroSupportsNewStyle);

        /// <summary>Core of the introduction-response handling (py-ipv8 on_introduction_response).</summary>
        protected virtual void OnIntroductionResponseCore(Peer peer, GlobalTimeDistributionPayload dist,
                                                          Address destinationAddress, Address sourceWanAddress,
                                                          Address lanIntroductionAddress,
                                                          Address wanIntroductionAddress, long identifier,
                                                          bool introSupportsNewStyle)
        {
            if (destinationAddress.IsUdpv4
                && !AddressInLanSubnets(destinationAddress.Host))
            {
                MyEstimatedWan = destinationAddress;
            }
            MyPeer.AddAddress(destinationAddress);

            if (peer.NewStyleIntro)
            {
                // Peer wants to use a different interface which we support: not ported in Phase 1a
                // (requires the dispatcher endpoint; py-ipv8 discovers the alternative address here).
            }

            Network.AddVerifiedPeer(peer);
            Network.DiscoverServices(peer, new[] { CommunityId });

            var introductions = new List<Address>();

            if (!IsZeroAddress(wanIntroductionAddress)
                && wanIntroductionAddress.Host != MyEstimatedWan.Host)
            {
                if (!IsZeroAddress(lanIntroductionAddress))
                {
                    introductions.Add(lanIntroductionAddress);
                }
                introductions.Add(wanIntroductionAddress);
            }
            else if (!IsZeroAddress(lanIntroductionAddress)
                     && wanIntroductionAddress.Host == MyEstimatedWan.Host)
            {
                introductions.Add(lanIntroductionAddress);
            }
            else if (!IsZeroAddress(wanIntroductionAddress))
            {
                introductions.Add(wanIntroductionAddress);
                introductions.Add(Address.Udpv4(MyEstimatedLan.Host, wanIntroductionAddress.Port));
            }

            foreach (var introduction in introductions)
            {
                Network.DiscoverAddress(peer, introduction, CommunityId, introSupportsNewStyle);
            }

            IntroductionResponseCallback(peer, dist, null);
        }

        private static bool IsZeroAddress(Address address)
            => address.Host == "0.0.0.0" && address.Port == 0;

        private Task? OnPuncture(Address sourceAddress, byte[] data)
        {
            // When we receive a puncture, we do nothing.
            EzUnpackAuth<PuncturePayload>(sourceAddress, data);
            return null;
        }

        private Task? OnNewPuncture(Address sourceAddress, byte[] data)
        {
            // When we receive a new-style puncture, we do nothing.
            EzUnpackAuth<NewPuncturePayload>(sourceAddress, data);
            return null;
        }

        private Task? OnOldPunctureRequest(Address sourceAddress, byte[] data)
        {
            var (dist, payload) = EzUnpackNoAuth<PunctureRequestPayload>(sourceAddress, data);
            OnPunctureRequest(sourceAddress, dist, payload, false);
            return null;
        }

        private Task? OnNewPunctureRequest(Address sourceAddress, byte[] data)
        {
            var (dist, payload) = EzUnpackNoAuth<NewPunctureRequestPayload>(sourceAddress, data);
            OnPunctureRequest(sourceAddress, dist, payload, true);
            return null;
        }

        /// <summary>Callback to handle puncture requests: we send a puncture to the requested address.</summary>
        protected virtual void OnPunctureRequest(Address sourceAddress, GlobalTimeDistributionPayload dist,
                                                 Payload payload, bool newStyle)
        {
            Address lanWalkerAddress;
            Address wanWalkerAddress;
            long identifier;
            if (payload is NewPunctureRequestPayload newRequest)
            {
                lanWalkerAddress = newRequest.LanWalkerAddress;
                wanWalkerAddress = newRequest.WanWalkerAddress;
                identifier = newRequest.Identifier;
            }
            else
            {
                var oldRequest = (PunctureRequestPayload)payload;
                lanWalkerAddress = oldRequest.LanWalkerAddress;
                wanWalkerAddress = oldRequest.WanWalkerAddress;
                identifier = oldRequest.Identifier;
            }
            var target = wanWalkerAddress;
            if (wanWalkerAddress.Host == MyEstimatedWan.Host)
            {
                target = lanWalkerAddress;
            }

            var packet = CreatePuncture(MyEstimatedLan, wanWalkerAddress, identifier, newStyle);
            Endpoint.Send(target, packet);
        }

        /// <summary>
        /// Callback for when the Endpoint has new data for us: prefix-filter and dispatch on msg byte.
        /// </summary>
        public override void OnPacket(Packet packet)
        {
            var sourceAddress = packet.SourceAddress;
            var data = packet.Data;
            var probablePeer = Network.GetVerifiedByAddress(sourceAddress);
            if (probablePeer != null)
            {
                probablePeer.LastResponse = Util.NowEpoch();
            }
            // community.py: if self._prefix != data[:22]: return
            if (data.Length < _prefix.Length || !MatchesPrefix(data, _prefix))
            {
                return;
            }
            var msgId = data[22];
            var handler = _decodeMap[msgId];
            if (handler != null)
            {
                try
                {
                    var result = handler(sourceAddress, data);
                    if (result != null)
                    {
                        // Fire-and-forget task handling, like py-ipv8's ensure_future.
                        _ = result.ContinueWith(
                            t => Console.Error.WriteLine(
                                $"Exception occurred while handling packet!\n{t.Exception?.GetBaseException()}"),
                            TaskContinuationOptions.OnlyOnFaulted);
                    }
                }
                catch (Exception exception)
                {
                    Console.Error.WriteLine($"Exception occurred while handling packet!\n{exception}");
                    LastHandlerException = exception;
                }
            }
            else
            {
                Console.Error.WriteLine($"Received unknown message: {msgId} from {sourceAddress}");
            }
        }

        /// <summary>The last exception thrown by a packet handler (test/debug aid).</summary>
        public Exception LastHandlerException { get; private set; }

        private bool MatchesPrefix(byte[] data, byte[] prefix)
        {
            for (var i = 0; i < prefix.Length; i++)
            {
                if (data[i] != prefix[i])
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>Attempt to walk directly to the given address.</summary>
        public override void WalkTo(Address address)
        {
            var packet = CreateIntroductionRequest(address, newStyle: Network.IsNewStyle(address));
            Endpoint.Send(address, packet);
        }

        /// <summary>Send an introduction request to a specific peer.</summary>
        public void SendIntroductionRequest(Peer peer)
        {
            var packet = CreateIntroductionRequest(peer.Address, newStyle: peer.NewStyleIntro);
            Endpoint.Send(peer.Address, packet);
        }

        /// <summary>
        /// Get a new introduction, or bootstrap if there are no available peers.
        /// </summary>
        public override void GetNewIntroduction(Peer fromPeer = null)
        {
            if (fromPeer == null)
            {
                var available = GetPeers().ToList();
                if (available.Count > 0)
                {
                    // The py-ipv8 5% bootstrapper keep-alive chance: our minimal bootstrapper list is
                    // always empty in Phase 1a, so this branch is a no-op.
                    fromPeer = available[ChoiceRng.Next(available.Count)];
                }
                else
                {
                    Bootstrap();
                    return;
                }
            }
            SendIntroductionRequest(fromPeer);
        }

        /// <summary>
        /// Perform introduction logic to get into the network: no-op without bootstrappers (Phase 1a).
        /// </summary>
        public override void Bootstrap()
        {
        }

        /// <summary>Return a random peer to send an introduction request to.</summary>
        public override Peer GetPeerForIntroduction(Peer exclude = null, bool newStyle = false)
        {
            var available = GetPeers()
                .Where(p => !p.Equals(exclude)
                            && (newStyle || p.Address.IsUdpv4))
                .ToList();
            return available.Count > 0 ? available[ChoiceRng.Next(available.Count)] : null;
        }

        /// <summary>Get the addresses that we know of but have not been contacted to become a peer.</summary>
        public override IReadOnlyList<Address> GetWalkableAddresses()
            => Network.GetWalkableAddresses(CommunityId);

        /// <summary>Get the peers that we are currently connected to (signed messages received).</summary>
        public override IReadOnlyList<Peer> GetPeers()
            => Network.GetPeersForService(CommunityId);

        /// <summary>
        /// GUESS our own address: the estimated WAN for IPv4 UDP endpoints (py-ipv8 guess_address).
        /// </summary>
        public Address? GuessAddress()
        {
            return AddressInLanSubnets(MyEstimatedLan.Host) ? MyEstimatedLan : (Address?)MyEstimatedWan;
        }

        /// <summary>Our own preferred address (UDPEndpoint exposes no "interfaces" → estimated WAN).</summary>
        protected Address MyPreferredAddress() => MyEstimatedWan;
    }
}
