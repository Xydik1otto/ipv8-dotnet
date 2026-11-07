// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using IPv8.Bootstrapping;
using IPv8.Keyvault;
using IPv8.Messaging;
using IPv8.Messaging.Interfaces;
using IPv8.PeerDiscovery;

namespace IPv8
{
    /// <summary>Key definition block of the IPv8 configuration (py-ipv8 "keys" list entries).</summary>
    public sealed class IPv8KeyConfig
    {
        public string Alias { get; set; }

        /// <summary>Optional file path to load the key from (or to persist a generated key into).</summary>
        public string File { get; set; }

        /// <summary>Optional base64-encoded private key ("LibNaCLSK:" binary).</summary>
        public string Bin { get; set; }

        /// <summary>Curve to generate when neither file nor bin is given ("curve25519").</summary>
        public string Generation { get; set; }
    }

    /// <summary>Endpoint interface definition block (py-ipv8 "interfaces" list entries).</summary>
    public sealed class IPv8InterfaceConfig
    {
        public string Interface { get; set; } = "UDPIPv4";

        public string Ip { get; set; } = "0.0.0.0";

        public int Port { get; set; } = 8090;
    }

    /// <summary>Walker definition block (py-ipv8 "walkers" list entries).</summary>
    public sealed class IPv8WalkerConfig
    {
        public string Strategy { get; set; }

        /// <summary>Target number of peers (-1 = always walk).</summary>
        public int Peers { get; set; } = -1;

        /// <summary>Constructor keyword arguments for the strategy.</summary>
        public Dictionary<string, object> Init { get; set; } = new Dictionary<string, object>();
    }

    /// <summary>Bootstrapper definition block (py-ipv8 "bootstrappers" list entries).</summary>
    public sealed class IPv8BootstrapperConfig
    {
        public string Class { get; set; }

        /// <summary>Constructor keyword arguments for the bootstrapper.</summary>
        public Dictionary<string, object> Init { get; set; } = new Dictionary<string, object>();
    }

    /// <summary>Overlay definition block (py-ipv8 "overlays" list entries).</summary>
    public sealed class IPv8OverlayConfig
    {
        public string Class { get; set; }

        /// <summary>The key alias to use as our peer identity.</summary>
        public string Key { get; set; }

        /// <summary>Settings properties to set on the community settings object.</summary>
        public Dictionary<string, object> Initialize { get; set; } = new Dictionary<string, object>();

        public List<IPv8WalkerConfig> Walkers { get; set; } = new List<IPv8WalkerConfig>();

        /// <summary>Methods to invoke on the overlay when the service starts: (name, args...).</summary>
        public List<object[]> OnStart { get; set; } = new List<object[]>();

        public List<IPv8BootstrapperConfig> Bootstrappers { get; set; } = new List<IPv8BootstrapperConfig>();
    }

    /// <summary>Port of the py-ipv8 configuration dictionary shape.</summary>
    public sealed class IPv8Configuration
    {
        public List<IPv8KeyConfig> Keys { get; set; } = new List<IPv8KeyConfig>();

        public List<IPv8InterfaceConfig> Interfaces { get; set; } = new List<IPv8InterfaceConfig>();

        public List<IPv8OverlayConfig> Overlays { get; set; } = new List<IPv8OverlayConfig>();

        public double WalkerInterval { get; set; } = 0.5;
    }

    /// <summary>
    /// The main IPv8 controller that reads configurations and makes components
    /// (port of ipv8_service.py::IPv8 — renamed IPv8Service to avoid the C# namespace clash).
    /// </summary>
    public sealed class IPv8Service
    {
        /// <summary>The communities known to the service by their configuration class name.</summary>
        public static readonly Dictionary<string, Func<CommunitySettings, Overlay>> Communities =
            new Dictionary<string, Func<CommunitySettings, Overlay>>
            {
                // Phase 1b: the DHT discovery community. Phase 2 adds IdentityCommunity and
                // AttestationCommunity here.
                ["DHTDiscoveryCommunity"] = settings => new Dht.DhtCommunity(settings)
            };

        /// <summary>The walkers known to the service by their configuration strategy name.</summary>
        public static readonly Dictionary<string, Func<Overlay, Dictionary<string, object>, DiscoveryStrategy>>
            Walkers = new Dictionary<string, Func<Overlay, Dictionary<string, object>, DiscoveryStrategy>>
            {
                ["EdgeWalk"] = (overlay, args) => CreateWithKwargs(typeof(EdgeWalk), overlay, args),
                ["RandomWalk"] = (overlay, args) => CreateWithKwargs(typeof(RandomWalk), overlay, args)
            };

        public IPv8Configuration Configuration { get; }

        public Endpoint Endpoint { get; }

        public Network Network { get; }

        public Dictionary<string, Peer> Keys { get; } = new Dictionary<string, Peer>();

        public double WalkInterval { get; private set; }

        private readonly object _overlayLock = new object();

        /// <summary>(strategy, target_peers) pairs, like py-ipv8 self.strategies.</summary>
        private readonly List<(DiscoveryStrategy Strategy, int TargetPeers)> _strategies =
            new List<(DiscoveryStrategy, int)>();

        private readonly List<Overlay> _overlays = new List<Overlay>();

        private readonly List<(Overlay Overlay, string MethodName, object[] Args)> _onStart =
            new List<(Overlay, string, object[])>();

        private Task _stateMachineTask;
        private CancellationTokenSource _stateMachineCts;

        public IReadOnlyList<Overlay> Overlays
        {
            get
            {
                lock (_overlayLock)
                {
                    return _overlays.ToList();
                }
            }
        }

        /// <summary>The number of registered (strategy, target peers) pairs.</summary>
        public int StrategiesCount
        {
            get
            {
                lock (_overlayLock)
                {
                    return _strategies.Count;
                }
            }
        }

        public IPv8Service(IPv8Configuration configuration,
                           Endpoint endpointOverride = null,
                           bool enableStatistics = false,
                           Dictionary<string, Func<CommunitySettings, Overlay>> extraCommunities = null)
        {
            Configuration = configuration;

            // Setup logging: skipped (Console.Error diagnostics everywhere in this port).

            if (endpointOverride != null)
            {
                Endpoint = endpointOverride;
            }
            else
            {
                // py-ipv8 uses a DispatcherEndpoint over the configured interface specs; only the
                // UDPIPv4 interface is ported, so we construct it directly.
                if (configuration.Interfaces.Count == 0)
                {
                    throw new ArgumentException("No endpoint interfaces configured");
                }
                if (configuration.Interfaces.Count > 1)
                {
                    throw new NotImplementedException(
                        "Multiple endpoint interfaces require the DispatcherEndpoint (not ported)");
                }
                var spec = configuration.Interfaces[0];
                if (spec.Interface != "UDPIPv4")
                {
                    throw new ArgumentException($"Unknown interface type: {spec.Interface}");
                }
                Endpoint = new Messaging.Interfaces.Udp.UDPEndpoint(spec.Port, spec.Ip);
            }

            // StatisticsEndpoint/TunnelEndpoint wrappers are not ported (Phase 3 tunnels).
            if (enableStatistics)
            {
                Console.Error.WriteLine("Ignoring enable_statistics: StatisticsEndpoint not ported");
            }

            Network = new Network();

            // Load/generate keys
            foreach (var keyBlock in configuration.Keys)
            {
                if (keyBlock.File != null && File.Exists(keyBlock.File))
                {
                    Keys[keyBlock.Alias] =
                        new Peer(ECCrypto.Default.KeyFromPrivateBin(File.ReadAllBytes(keyBlock.File)));
                }
                else
                {
                    var key = keyBlock.Bin != null
                        ? ECCrypto.Default.KeyFromPrivateBin(Convert.FromBase64String(keyBlock.Bin))
                        : ECCrypto.Default.GenerateKey(keyBlock.Generation);
                    Keys[keyBlock.Alias] = new Peer(key);
                    if (keyBlock.File != null)
                    {
                        File.WriteAllBytes(keyBlock.File, key.KeyToBin());
                    }
                }
            }

            foreach (var overlay in configuration.Overlays)
            {
                var overlayFactory = Communities.TryGetValue(overlay.Class, out var builtIn)
                    ? builtIn
                    : extraCommunities != null && extraCommunities.TryGetValue(overlay.Class, out var extra)
                        ? extra
                        : null;
                if (overlayFactory == null)
                {
                    throw new ArgumentException($"Key {overlay.Class} has no associated Community!");
                }
                var settings = new CommunitySettings(null, Keys[overlay.Key], Endpoint, Network);
                foreach (var pair in overlay.Initialize)
                {
                    ReflectionUtil.SetPropertyOrField(settings, pair.Key, pair.Value);
                }
                var overlayInstance = overlayFactory(settings);
                lock (_overlayLock)
                {
                    _overlays.Add(overlayInstance);
                }
                foreach (var walker in overlay.Walkers)
                {
                    var walkerFactory = Walkers.TryGetValue(walker.Strategy, out var builtInWalker)
                        ? builtInWalker
                        : null;
                    if (walkerFactory == null)
                    {
                        throw new ArgumentException($"Key {walker.Strategy} has no associated DiscoveryStrategy!");
                    }
                    var strategy = walkerFactory(overlayInstance, walker.Init);
                    lock (_overlayLock)
                    {
                        _strategies.Add((strategy, walker.Peers));
                    }
                }
                foreach (var config in overlay.OnStart)
                {
                    var methodName = (string)config[0];
                    var args = config.Length > 1 ? config.Skip(1).ToArray() : Array.Empty<object>();
                    lock (_overlayLock)
                    {
                        _onStart.Add((overlayInstance, methodName, args));
                    }
                }
                foreach (var bootstrapper in overlay.Bootstrappers)
                {
                    if (!(overlayInstance is Community community))
                    {
                        throw new ArgumentException(
                            $"Bootstrapper {bootstrapper.Class} called for non-Community {overlayInstance}!");
                    }
                    community.Bootstrappers.Add(CreateBootstrapper(bootstrapper));
                }
            }
            WalkInterval = configuration.WalkerInterval;
        }

        private static Bootstrapping.Bootstrapper CreateBootstrapper(IPv8BootstrapperConfig config)
        {
            var kwargs = config.Init ?? new Dictionary<string, object>();
            switch (config.Class)
            {
                case "DispersyBootstrapper":
                {
                    var dnsAddresses = kwargs.TryGetValue("dns_addresses", out var dnsValue)
                        ? ((IEnumerable<object>)dnsValue)
                          .Select(pair => ((IEnumerable<object>)pair).ToArray())
                          .Select(parts => ((string)parts[0], Convert.ToInt32(parts[1])))
                        : Enumerable.Empty<(string, int)>();
                    var ipAddresses = kwargs.TryGetValue("ip_addresses", out var ipValue)
                        ? ((IEnumerable<object>)ipValue)
                          .Select(pair => ((IEnumerable<object>)pair).ToArray())
                          .Select(parts => Address.Udpv4((string)parts[0], Convert.ToInt32(parts[1])))
                        : Enumerable.Empty<Address>();
                    return new DispersyBootstrapper(ipAddresses, dnsAddresses,
                        kwargs.TryGetValue("bootstrap_timeout", out var timeoutValue)
                            ? Convert.ToDouble(timeoutValue)
                            : 30.0);
                }
                case "UDPBroadcastBootstrapper":
                    return new UdpBroadcastBootstrapper(
                        kwargs.TryGetValue("bootstrap_timeout", out var timeout)
                            ? Convert.ToDouble(timeout)
                            : 30.0);
                default:
                    throw new ArgumentException($"Unknown bootstrapper class: {config.Class}");
            }
        }

        /// <summary>
        /// Instantiate a DiscoveryStrategy by (snake_case) keyword arguments, mirroring
        /// ``strategy_class(overlay, **args)``.
        /// </summary>
        private static DiscoveryStrategy CreateWithKwargs(Type strategyType, Overlay overlay,
                                                          Dictionary<string, object> kwargs)
        {
            var ctor = strategyType
                .GetConstructors()
                .First(c => c.GetParameters().Length >= 1
                            && typeof(Overlay).IsAssignableFrom(c.GetParameters()[0].ParameterType));
            var parameters = ctor.GetParameters();
            var args = new object[parameters.Length];
            args[0] = overlay;
            for (var i = 1; i < parameters.Length; i++)
            {
                var parameter = parameters[i];
                // Match py snake_case kwargs against C# PascalCase parameter names.
                var pyName = parameter.Name.ToLowerInvariant().Replace("_", "");
                var provided = kwargs.FirstOrDefault(pair =>
                    pair.Key.ToLowerInvariant().Replace("_", "") == pyName);
                args[i] = provided.Key != null
                    ? ReflectionUtil.ConvertValue(provided.Value, parameter.ParameterType)
                    : parameter.HasDefaultValue
                        ? parameter.DefaultValue
                        : throw new ArgumentException(
                            $"Missing argument '{parameter.Name}' for {strategyType.Name}");
            }
            return (DiscoveryStrategy)ctor.Invoke(args);
        }

        /// <summary>
        /// Open the IPv8 endpoint and schedule (possibly periodic) tasks.
        /// </summary>
        public void Start()
        {
            Endpoint.Open();

            List<(Overlay, string, object[])> onStartSnapshot;
            lock (_overlayLock)
            {
                onStartSnapshot = _onStart.ToList();
            }
            foreach (var (overlay, methodName, args) in onStartSnapshot)
            {
                var method = overlay.GetType().GetMethod(methodName,
                    BindingFlags.Public | BindingFlags.Instance, null,
                    args.Select(a => a == null ? typeof(object) : a.GetType()).ToArray(), null)
                    ?? overlay.GetType().GetMethod(methodName, BindingFlags.Public | BindingFlags.Instance)
                    ?? throw new MissingMethodException(overlay.GetType().Name, methodName);
                method.Invoke(overlay, args);
            }

            _stateMachineCts = new CancellationTokenSource();
            _stateMachineTask = Task.Run(() => TickerLoopAsync(_stateMachineCts.Token));
        }

        private async Task TickerLoopAsync(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                await OnTickAsync(cancellationToken);
            }
        }

        /// <summary>The main IPv8 loop that schedules all registered strategies.</summary>
        public async Task OnTickAsync(CancellationToken cancellationToken = default)
        {
            if (!Endpoint.IsOpen || _stateMachineTask == null)
            {
                return;
            }
            List<(DiscoveryStrategy, int)> strategiesSnapshot;
            lock (_overlayLock)
            {
                strategiesSnapshot = _strategies.ToList();
            }
            var smooth = strategiesSnapshot.Count > 0 ? WalkInterval / strategiesSnapshot.Count : 0;
            var ticker = strategiesSnapshot.Count;
            var broke = false;
            foreach (var (strategy, targetPeers) in strategiesSnapshot)
            {
                var startTime = Util.NowEpoch();
                try
                {
                    // We wrap the take_step into a general except as it is prone to programmer error.
                    if (targetPeers == -1 || strategy.GetPeerCount() < targetPeers)
                    {
                        strategy.TakeStep();
                    }
                }
                catch (Exception exception)
                {
                    Console.Error.WriteLine($"Exception occurred while trying to walk!\n{exception}");
                }
                ticker -= ticker > 0 ? 1 : 0;
                var sleepTime = smooth - (Util.NowEpoch() - startTime);
                if (ticker != 0 && sleepTime > 0.01)
                {
                    await Task.Delay(TimeSpan.FromSeconds(sleepTime), cancellationToken);
                }
                if (cancellationToken.IsCancellationRequested || _stateMachineTask.IsCompleted)
                {
                    // By awaiting, we might have been stopped. In that case, exit out of the loop.
                    broke = true;
                    break;
                }
            }
            if (!broke && !cancellationToken.IsCancellationRequested)
            {
                await Task.Delay(TimeSpan.FromSeconds(WalkInterval), cancellationToken);
            }
        }

        /// <summary>
        /// Register a strategy to call every tick unless a target number of peers has been reached.
        /// If the target_peers is equal to -1, the strategy is always called.
        /// </summary>
        public void AddStrategy(Overlay overlay, DiscoveryStrategy strategy, int targetPeers)
        {
            lock (_overlayLock)
            {
                if (!_overlays.Contains(overlay))
                {
                    _overlays.Add(overlay);
                }
                _strategies.Add((strategy, targetPeers));
            }
        }

        /// <summary>Unregister and unload a given overlay instance.</summary>
        public Task UnloadOverlay(Overlay instance)
        {
            lock (_overlayLock)
            {
                _overlays.RemoveAll(overlay => ReferenceEquals(overlay, instance));
                _strategies.RemoveAll(pair => ReferenceEquals(pair.Strategy.Overlay, instance));
            }
            instance.Unload();
            return Task.CompletedTask;
        }

        /// <summary>Get any loaded overlay instance from a given class type, if it exists.</summary>
        public Overlay GetOverlay(Type overlayCls)
            => GetOverlays(overlayCls).FirstOrDefault();

        public T GetOverlay<T>() where T : Overlay
            => GetOverlays<T>().FirstOrDefault();

        /// <summary>Get all loaded overlay instances from a given class type.</summary>
        public IEnumerable<Overlay> GetOverlays(Type overlayCls)
        {
            lock (_overlayLock)
            {
                return _overlays.Where(o => overlayCls.IsInstanceOfType(o)).ToList();
            }
        }

        public IEnumerable<T> GetOverlays<T>() where T : Overlay
        {
            lock (_overlayLock)
            {
                return _overlays.OfType<T>().ToList();
            }
        }

        /// <summary>
        /// Stop all registered IPv8 strategies, unload all registered overlays and close the endpoint.
        /// </summary>
        public async Task StopAsync()
        {
            if (_stateMachineTask != null)
            {
                _stateMachineCts?.Cancel();
                try
                {
                    await _stateMachineTask;
                }
                catch (OperationCanceledException)
                {
                    // Expected on cancellation.
                }
            }
            List<Overlay> overlaysSnapshot;
            lock (_overlayLock)
            {
                overlaysSnapshot = _overlays.ToList();
            }
            foreach (var overlay in overlaysSnapshot)
            {
                await UnloadOverlay(overlay);
            }
            Endpoint.Close();
        }
    }

    /// <summary>Reflection helpers shared by the service configuration.</summary>
    internal static class ReflectionUtil
    {
        public static void SetPropertyOrField(object target, string name, object value)
        {
            const BindingFlags flags = BindingFlags.Public | BindingFlags.Instance;
            var property = target.GetType().GetProperty(name, flags);
            if (property != null && property.CanWrite)
            {
                property.SetValue(target, ConvertValue(value, property.PropertyType));
                return;
            }
            var field = target.GetType().GetField(name, flags);
            if (field != null)
            {
                field.SetValue(target, ConvertValue(value, field.FieldType));
                return;
            }
            throw new ArgumentException(
                $"{target.GetType().Name} has no property or field '{name}'");
        }

        public static object ConvertValue(object value, Type targetType)
        {
            if (value == null)
            {
                return null;
            }
            if (targetType.IsInstanceOfType(value))
            {
                return value;
            }
            if (targetType == typeof(Address))
            {
                // Accept ("host", port) pairs for address-typed settings.
                if (value is object[] parts)
                {
                    return Address.Udpv4((string)parts[0], Convert.ToInt32(parts[1]));
                }
                return Address.Udpv4(value.ToString(), 0);
            }
            try
            {
                return Convert.ChangeType(value, targetType);
            }
            catch (Exception exception)
            {
                throw new ArgumentException(
                    $"Cannot convert {value} to {targetType.Name}", exception);
            }
        }
    }
}
