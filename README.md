# ipv8-dotnet

C# port of the [IPv8](https://github.com/Tribler/py-ipv8) P2P networking layer
(tribler.org) — pure managed code, no native dependencies (crypto via
BouncyCastle), wire-compatible with py-ipv8.

**Status:** Phase 1a in progress (keys, serializer, packet format, discovery
payloads, UDP endpoint, minimal walk). See `../CONTRACT.md` for the port
contract and `../contract/vectors.json` for golden test vectors.

- License: LGPL-3.0-or-later (derived from Tribler/py-ipv8)
- Targets: netstandard2.0 / net8.0 / net10.0
- Ukrainian/English: контract README bilingual by design.

## Build

```sh
dotnet build                       # all TFMs
dotnet test tests/IPv8.Tests       # golden + roundtrip tests
```
