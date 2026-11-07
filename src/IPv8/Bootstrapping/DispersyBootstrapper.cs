// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using IPv8.Messaging;

namespace IPv8.Bootstrapping
{
    /// <summary>
    /// Bootstrapper that uses the Dispersy protocol to find initial peers
    /// (port of ipv8/bootstrapping/dispersy/bootstrapper.py::DispersyBootstrapper).
    /// </summary>
    public class DispersyBootstrapper : Bootstrapper
    {
        private static readonly Random ChoiceRng = new Random();

        /// <summary>The resolved bootstrap server addresses to walk to.</summary>
        public List<Address> IpAddresses { get; } = new List<Address>();

        /// <summary>The unresolved (dns host, port) bootstrap addresses.</summary>
        public List<(string Host, int Port)> DnsAddresses { get; }

        public double BootstrapTimeout { get; }

        public double LastBootstrap { get; set; }

        public DispersyBootstrapper(IEnumerable<Address> ipAddresses,
                                    IEnumerable<(string Host, int Port)> dnsAddresses,
                                    double bootstrapTimeout = 30.0)
        {
            IpAddresses.AddRange(ipAddresses.Select(addr => Address.Udpv4(addr.Host, addr.Port)));
            DnsAddresses = dnsAddresses.ToList();

            BootstrapTimeout = bootstrapTimeout;

            LastBootstrap = 0;
        }

        /// <summary>
        /// Resolve the bootstrap server DNS names defined in DnsAddresses and insert them into
        /// IpAddresses.
        /// </summary>
        public async Task ResolveDnsBootstrapAddressesAsync()
        {
            var resolutions = DnsAddresses.Select(async entry =>
            {
                try
                {
                    // py-ipv8's gethostbyname returns a single IPv4 for the host.
                    var hostEntry = await Dns.GetHostEntryAsync(entry.Host);
                    var ip = hostEntry.AddressList.FirstOrDefault(a => a.AddressFamily
                               == System.Net.Sockets.AddressFamily.InterNetwork)
                           ?? throw new System.Net.Sockets.SocketException(
                               (int)System.Net.Sockets.SocketError.HostNotFound);
                    var address = Address.Udpv4(ip.ToString(), entry.Port);
                    if (!IpAddresses.Contains(address))
                    {
                        IpAddresses.Add(address);
                    }
                }
                catch (Exception)
                {
                    Console.Error.WriteLine(
                        $"Unable to resolve bootstrap DNS address ({entry.Host}, {entry.Port})");
                }
            });
            await Task.WhenAll(resolutions);
        }

        public override async Task<bool> InitializeAsync(Community overlay)
        {
            if (!Initialized)
            {
                Initialized = true;
                overlay.Network.Blacklist.AddRange(IpAddresses);
                await ResolveDnsBootstrapAddressesAsync();
            }
            return true;
        }

        public override Task<IReadOnlyList<Address>> GetAddressesAsync(Community overlay, double timeout)
        {
            if (Util.NowEpoch() - LastBootstrap < BootstrapTimeout)
            {
                return Task.FromResult<IReadOnlyList<Address>>(new List<Address>());
            }
            Console.Error.WriteLine(
                $"Bootstrapping {overlay.GetType().Name}, current peers {overlay.GetPeers().Count}");
            LastBootstrap = Util.NowEpoch();
            foreach (var socketAddress in IpAddresses)
            {
                overlay.EnsureBlacklisted(socketAddress);
                overlay.WalkTo(socketAddress);
            }
            return Task.FromResult<IReadOnlyList<Address>>(new List<Address>());
        }

        public override void KeepAlive(Community overlay)
        {
            // Keep at least one connection to any bootstrap server open. This avoids network
            // splits/partitioning.
            if (IpAddresses.Count > 0)
            {
                var address = IpAddresses[ChoiceRng.Next(IpAddresses.Count)];
                overlay.EnsureBlacklisted(address);
                overlay.WalkTo(address);
            }
        }

        /// <summary>Overlays should not consider bootstrap nodes to be normal peers.</summary>
        public override IReadOnlyList<Address> Blacklist() => IpAddresses;

        public override void Unload()
        {
            // Unload this bootstrapper (nothing to clean up: no sockets are held).
        }
    }
}
