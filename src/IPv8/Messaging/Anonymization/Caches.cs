// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;

namespace IPv8.Messaging.Anonymization
{
    /// <summary>A NumberCache identified by its (string) name (requestcache.py::NumberCacheWithName).</summary>
    public abstract class NumberCacheWithName : NumberCache
    {
        protected NumberCacheWithName(RequestCache requestCache, string name, int number)
            : base(requestCache, name, number)
        {
        }
    }

    /// <summary>A RandomNumberCache identified by its (string) name (requestcache.py::RandomNumberCacheWithName).</summary>
    public abstract class RandomNumberCacheWithName : NumberCache
    {
        protected RandomNumberCacheWithName(RequestCache requestCache, string name)
            : base(requestCache, name, RandomNumberCache.FindUnclaimedIdentifier(requestCache, name))
        {
        }
    }

    /// <summary>
    /// The hidden-service swarm registry (py: ``HiddenTunnelCommunity.swarms``). The HS caches
    /// consult it on timeout without coupling the base tunnel module to the hidden community.
    /// </summary>
    public interface IHiddenSwarmRegistry
    {
        Dictionary<byte[], Swarm> Swarms { get; }
    }

    /// <summary>Used to track outstanding create messages (caches.py::CreateRequestCache).</summary>
    public sealed class CreateRequestCache : RandomNumberCacheWithName
    {
        public new const string Name = "create";

        public TunnelCommunity Community { get; }
        public long ExtendIdentifier { get; }
        public long ToCircuitId { get; }
        public long FromCircuitId { get; }
        public Peer Peer { get; }
        public Peer ToPeer { get; }

        public CreateRequestCache(TunnelCommunity community, int identifier, long toCircuitId,
                                  long fromCircuitId, Peer peer, Peer toPeer)
            : base(community.RequestCache, Name)
        {
            Community = community;
            ExtendIdentifier = identifier;
            ToCircuitId = toCircuitId;
            FromCircuitId = fromCircuitId;
            Peer = peer;
            ToPeer = toPeer;
        }

        public override void OnTimeout()
        {
            // We don't need to do anything on timeout.
        }
    }

    /// <summary>Used to track outstanding created messages (caches.py::CreatedRequestCache).</summary>
    public sealed class CreatedRequestCache : NumberCacheWithName
    {
        public new const string Name = "created";

        public long CircuitId { get; }
        public Peer Candidate { get; }
        public Dictionary<byte[], Peer> Candidates { get; }
        public double Timeout { get; }

        public CreatedRequestCache(TunnelCommunity community, long circuitId, Peer candidate,
                                   Dictionary<byte[], Peer> candidates, double timeout)
            : base(community.RequestCache, Name, (int)circuitId)
        {
            CircuitId = circuitId;
            Candidate = candidate;
            Candidates = candidates;
            Timeout = timeout;
        }

        public override double TimeoutDelay => Timeout;

        public override void OnTimeout()
        {
            // We don't need to do anything on timeout.
        }
    }

    /// <summary>Used to track adding additional hops to the circuit (caches.py::RetryRequestCache).</summary>
    public sealed class RetryRequestCache : NumberCacheWithName
    {
        public new const string Name = "retry";

        public delegate void RetryFunc(Circuit circuit, List<object> candidates, int maxTries);

        public TunnelCommunity Community { get; }
        public Circuit Circuit { get; }
        public int PacketIdentifier { get; }
        public List<object> Candidates { get; }
        public int MaxTries { get; set; }
        public RetryFunc RetryFuncDelegate { get; }
        public double Timeout { get; }

        public RetryRequestCache(TunnelCommunity community, Circuit circuit, List<object> candidates,
                                 int maxTries, RetryFunc retryFunc, double timeout)
            : base(community.RequestCache, Name, (int)circuit.CircuitId)
        {
            Community = community;
            Circuit = circuit;
            PacketIdentifier = new Random().Next(1 << 16);
            Candidates = candidates;
            MaxTries = maxTries;
            RetryFuncDelegate = retryFunc;
            Timeout = timeout;
        }

        public override double TimeoutDelay => Timeout;

        public override void OnTimeout()
        {
            // Retry until we run out of candidates. Otherwise, remove the circuit.
            if (Circuit.State == Tunnel.CircuitStateClosing)
            {
                return;
            }
            if (Candidates.Count == 0 || MaxTries < 1)
            {
                Community.RemoveCircuit(Circuit.CircuitId, $"timeout, {MaxTries} tries left");
                return;
            }
            Community.RegisterAnonymousTask("retry-later", () =>
            {
                try
                {
                    RetryFuncDelegate(Circuit, Candidates, MaxTries);
                }
                catch (Exception)
                {
                    // Error encountered during 'on_timeout'.
                }
            });
        }
    }

    /// <summary>Manage a ping to a peer (caches.py::PingRequestCache).</summary>
    public sealed class PingRequestCache : RandomNumberCacheWithName
    {
        public new const string Name = "ping";

        public PingRequestCache(TunnelCommunity community)
            : base(community.RequestCache, Name)
        {
        }

        public override void OnTimeout()
        {
            // We don't need to do anything on timeout.
        }
    }

    /// <summary>Manage introduction point establishment (caches.py::IPRequestCache).</summary>
    public sealed class IpRequestCache : RandomNumberCacheWithName
    {
        public new const string Name = "establish-intro";

        public TunnelCommunity Community { get; }
        public Circuit Circuit { get; }

        public IpRequestCache(TunnelCommunity community, Circuit circuit)
            : base(community.RequestCache, Name)
        {
            Community = community;
            Circuit = circuit;
        }

        public override void OnTimeout()
        {
            // We remove the circuit if we can't establish an introduction point.
            Community.RemoveCircuit(Circuit.CircuitId, "establish-intro timeout");
        }
    }

    /// <summary>Manage rendezvous point establishment (caches.py::RPRequestCache).</summary>
    public sealed class RpRequestCache : RandomNumberCacheWithName
    {
        public new const string Name = "establish-rendezvous";

        public TunnelCommunity Community { get; }
        public RendezvousPoint Rp { get; }

        public RpRequestCache(TunnelCommunity community, RendezvousPoint rp)
            : base(community.RequestCache, Name)
        {
            Community = community;
            Rp = rp;
        }

        public override void OnTimeout()
        {
            // We remove the circuit if we can't establish a rendezvous point.
            Rp.Ready.TrySetResult(null);
            Community.RemoveCircuit(Rp.Circuit.CircuitId, "establish-rendezvous timeout");
        }
    }

    /// <summary>Request peers for the given swarm (info hash) (caches.py::PeersRequestCache).</summary>
    public sealed class PeersRequestCache : RandomNumberCacheWithName
    {
        public new const string Name = "peers-request";

        public TunnelCommunity Community { get; }
        public Circuit Circuit { get; }
        public byte[] InfoHash { get; }
        public IntroductionPoint Target { get; }
        public TaskCompletionSource<object> Future { get; } = new TaskCompletionSource<object>();

        public PeersRequestCache(TunnelCommunity community, Circuit circuit, byte[] infoHash,
                                 IntroductionPoint target)
            : base(community.RequestCache, Name)
        {
            Community = community;
            Circuit = circuit;
            InfoHash = infoHash;
            Target = target;
            RegisterFuture(Future, new Exception("Peers request timeout"));
        }

        public override void OnTimeout()
        {
            // We remove the introduction point if we don't get a response.
            if (Community is IHiddenSwarmRegistry registry
                && registry.Swarms.TryGetValue(InfoHash, out var swarm)
                && Target != null)
            {
                // This introduction point did not respond in time, so drop it.
                swarm.RemoveIntroPoint(Target);
            }
        }
    }

    /// <summary>Cache to track e2e circuit creation (caches.py::E2ERequestCache).</summary>
    public sealed class E2eRequestCache : RandomNumberCacheWithName
    {
        public new const string Name = "e2e-request";

        public byte[] InfoHash { get; }
        public Hop Hop { get; }
        public IntroductionPoint IntroPoint { get; }

        public E2eRequestCache(TunnelCommunity community, byte[] infoHash, Hop hop, IntroductionPoint introPoint)
            : base(community.RequestCache, Name)
        {
            InfoHash = infoHash;
            Hop = hop;
            IntroPoint = introPoint;
        }

        public override void OnTimeout()
        {
            // We don't need to do anything on timeout.
        }
    }

    /// <summary>Cache to track circuit linking (caches.py::LinkRequestCache).</summary>
    public sealed class LinkRequestCache : RandomNumberCacheWithName
    {
        public new const string Name = "link-request";

        public Circuit Circuit { get; }
        public byte[] InfoHash { get; }
        public SessionKeys HsSessionKeys { get; }

        public LinkRequestCache(TunnelCommunity community, Circuit circuit, byte[] infoHash,
                                SessionKeys hsSessionKeys)
            : base(community.RequestCache, Name)
        {
            Circuit = circuit;
            InfoHash = infoHash;
            HsSessionKeys = hsSessionKeys;
        }

        public override void OnTimeout()
        {
            // We don't need to do anything on timeout.
        }
    }

    /// <summary>Cache to track circuit speed tests (caches.py::TestRequestCache).</summary>
    public sealed class TestRequestCache : RandomNumberCacheWithName
    {
        public new const string Name = "test-request";

        public Circuit Circuit { get; }
        public double Ts { get; }
        public TaskCompletionSource<object> Future { get; } = new TaskCompletionSource<object>();

        public TestRequestCache(TunnelCommunity community, Circuit circuit)
            : base(community.RequestCache, Name)
        {
            Circuit = circuit;
            Ts = Util.NowEpoch();
            RegisterFuture(Future);
        }

        public override void OnTimeout()
        {
            // We don't need to do anything on timeout.
        }
    }
}
