// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using IPv8.Keyvault;
using IPv8.Messaging;
using IPv8.Messaging.Interfaces;
using IPv8.PeerDiscovery;

namespace IPv8
{
    /// <summary>Overlay settings (py-ipv8 overlay.Settings SimpleNamespace).</summary>
    public class OverlaySettings
    {
        /// <summary>The byte-string used to identify this overlay.</summary>
        public byte[] CommunityId { get; set; }

        /// <summary>The (private key) peer of this peer.</summary>
        public Peer MyPeer { get; set; }

        /// <summary>The endpoint to use for messaging.</summary>
        public Endpoint Endpoint { get; set; }

        /// <summary>The network graph backend.</summary>
        public Network Network { get; set; }

        public OverlaySettings(byte[] communityId, Peer myPeer, Endpoint endpoint, Network network)
        {
            CommunityId = communityId;
            MyPeer = myPeer;
            Endpoint = endpoint;
            Network = network;
        }
    }

    /// <summary>Community settings, extensible for Community subclasses.</summary>
    public class CommunitySettings : OverlaySettings
    {
        /// <summary>The number of peers we will grow to before we start rejecting new connections.</summary>
        public int MaxPeers { get; set; } = 30;

        /// <summary>Request use of a TunnelEndpoint to anonymize all our traffic (not ported in Phase 1a).</summary>
        public bool Anonymize { get; set; }

        public CommunitySettings(byte[] communityId, Peer myPeer, Endpoint endpoint, Network network,
                                 int maxPeers = 30, bool anonymize = false)
            : base(communityId, myPeer, endpoint, network)
        {
            MaxPeers = maxPeers;
            Anonymize = anonymize;
        }
    }

    /// <summary>Interface for an Internet overlay (port of ipv8/overlay.py::Overlay).</summary>
    public abstract class Overlay : EndpointListener
    {
        private readonly TaskManager _taskManager = new TaskManager();

        protected Overlay(OverlaySettings settings) : base(settings.Endpoint)
        {
            Serializer = GetSerializer();
            Crypto = ECCrypto.Default;
            CommunityId = settings.CommunityId;
            MyPeer = settings.MyPeer;
            Endpoint.AddListener(this);
            Network = settings.Network;
        }

        public Serializer Serializer { get; }

        public ECCrypto Crypto { get; }

        /// <summary>The community/overlay identifier (20 bytes).</summary>
        public byte[] CommunityId { get; }

        /// <summary>The peer representing us (with private key).</summary>
        public Peer MyPeer { get; }

        /// <summary>The network graph backend (py-ipv8 lets communities replace this).</summary>
        public Network Network { get; protected set; }

        // py-ipv8's Overlay extends TaskManager; C# single inheritance forces composition here.
        // The forwarding members below mirror the TaskManager API surface used by overlays.
        public PendingTask RegisterTask(object name, Action userTask, double delay = 0, double interval = 0)
            => _taskManager.RegisterTask(name, userTask, delay, interval);

        public PendingTask RegisterAnonymousTask(string basename, Action userTask,
                                                 double delay = 0, double interval = 0)
            => _taskManager.RegisterAnonymousTask(basename, userTask, delay, interval);

        public void CancelPendingTask(object name) => _taskManager.CancelPendingTask(name);

        public List<PendingTask> CancelAllPendingTasks() => _taskManager.CancelAllPendingTasks();

        public bool IsPendingTaskActive(object name) => _taskManager.IsPendingTaskActive(name);

        public PendingTask GetTask(object name) => _taskManager.GetTask(name);

        /// <summary>Unload this overlay: cancel all of our registered tasks.</summary>
        public virtual void Unload() => _taskManager.ShutdownTaskManager();

        /// <summary>Get a Serializer for this Overlay.</summary>
        protected virtual Serializer GetSerializer() => new Serializer();

        /// <summary>The Lamport timestamp of this overlay.</summary>
        public ulong GlobalTime => MyPeer.GetLamportTimestamp();

        /// <summary>Increments the current global time by one and returns this value.</summary>
        public ulong ClaimGlobalTime()
        {
            UpdateGlobalTime(GlobalTime + 1);
            return GlobalTime;
        }

        /// <summary>Increase the local global time if the given GLOBAL_TIME is larger.</summary>
        public void UpdateGlobalTime(ulong globalTime)
        {
            if (globalTime > GlobalTime)
            {
                MyPeer.UpdateClock(globalTime);
            }
        }

        /// <summary>Callback for when data is received on this endpoint.</summary>
        public abstract override void OnPacket(Packet packet);

        /// <summary>Puncture the NAT of an address (send an introduction request to it).</summary>
        public abstract void WalkTo(Address address);

        /// <summary>Get a new introduction, or bootstrap if there are no available peers.</summary>
        public abstract void GetNewIntroduction(Peer fromPeer = null);

        /// <summary>Get the peers for this specific overlay.</summary>
        public abstract IReadOnlyList<Peer> GetPeers();

        /// <summary>Get the list of addresses we can walk to on this overlay.</summary>
        public abstract IReadOnlyList<Address> GetWalkableAddresses();

        /// <summary>Get a peer for introduction (null when there are no available).</summary>
        public virtual Peer GetPeerForIntroduction(Peer exclude = null, bool newStyle = false) => null;

        /// <summary>
        /// Perform introduction logic to get into the network (py-ipv8 Community.bootstrap;
        /// a no-op without bootstrappers).
        /// </summary>
        public virtual void Bootstrap()
        {
        }
    }
}
