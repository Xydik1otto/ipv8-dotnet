// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;

namespace IPv8.Dht
{
    /// <summary>Generic error for DHT-related failures (ipv8/dht/__init__.py::DHTError).</summary>
    public class DhtError : Exception
    {
        public DhtError(string message) : base(message)
        {
        }
    }
}
