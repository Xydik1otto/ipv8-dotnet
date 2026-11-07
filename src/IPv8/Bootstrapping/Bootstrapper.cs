// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System.Collections.Generic;
using System.Threading.Tasks;
using IPv8.Messaging;

namespace IPv8.Bootstrapping
{
    /// <summary>
    /// A script to connect to external bootstrapping resources, using external hardware
    /// (port of ipv8/bootstrapping/bootstrapper_interface.py::Bootstrapper).
    ///
    /// When not to crash:
    ///  - Loading this module when missing dependencies.
    ///  - Initializing a subclass when the service is unavailable (return false).
    ///  - Failing to retrieve peers for a service (return an empty list).
    ///
    /// When to crash:
    ///  - Initializing this subclass when missing dependencies.
    /// </summary>
    public abstract class Bootstrapper
    {
        protected Bootstrapper()
        {
            Initialized = false;
        }

        /// <summary>Whether this bootstrapper has been successfully initialized.</summary>
        public bool Initialized { get; protected set; }

        /// <summary>
        /// Start connecting to this bootstrapping service. Don't perform any network traffic in
        /// the constructor!
        /// </summary>
        /// <returns>whether the initialization was successful.</returns>
        public abstract Task<bool> InitializeAsync(Community overlay);

        /// <summary>
        /// Return some IPv8 addresses (if available) from this bootstrapping service.
        /// These addresses should be walkable (not blocked by a NAT or firewall).
        /// </summary>
        /// <param name="overlay">the network overlay to get peers for.</param>
        /// <param name="timeout">the maximum time we wish to wait until we get any result.</param>
        public abstract Task<IReadOnlyList<Address>> GetAddressesAsync(Community overlay, double timeout);

        /// <summary>Periodically called to keep this bootstrap connection alive.</summary>
        public abstract void KeepAlive(Community overlay);

        /// <summary>Returns the blacklisted addresses for this Bootstrapper.</summary>
        public abstract IReadOnlyList<Address> Blacklist();

        /// <summary>Stop and unload all the resources used by this Bootstrapper.</summary>
        public abstract void Unload();
    }
}
