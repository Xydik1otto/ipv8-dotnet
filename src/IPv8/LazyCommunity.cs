// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using IPv8.Keyvault;
using IPv8.Messaging;
using IPv8.Messaging.Interfaces;

namespace IPv8
{
    /// <summary>Exception for when binary data doesn't match its expected format.</summary>
    public class PacketDecodingError : Exception
    {
        public PacketDecodingError(string message) : base(message)
        {
        }
    }

    /// <summary>Result of an authenticated unpack: peer, global time distribution and the payload.</summary>
    public sealed class DecodedPacket<TPayload> where TPayload : Payload
    {
        public Peer Peer { get; }
        public GlobalTimeDistributionPayload Dist { get; }
        public TPayload Payload { get; }

        public DecodedPacket(Peer peer, GlobalTimeDistributionPayload dist, TPayload payload)
        {
            Peer = peer;
            Dist = dist;
            Payload = payload;
        }
    }

    /// <summary>
    /// Base class that provides easy ways to pack and unpack payloads
    /// (port of ipv8/lazy_community.py::EZPackOverlay).
    /// </summary>
    public abstract class EZPackOverlay : Overlay
    {
        protected EZPackOverlay(OverlaySettings settings) : base(settings)
        {
        }

        /// <summary>Get the prefix of this overlay.</summary>
        public abstract byte[] GetPrefix();

        /// <summary>
        /// Send a Payload instance (with a defined msg number) to a peer. If you supply more than one
        /// Payload instance, the msg number of the LAST instance will be used.
        /// </summary>
        public void EzSend(Peer peer, params Payload[] payloads)
        {
            EzSendTo(peer.Address, payloads);
        }

        /// <summary>Send a Payload instance to an address.</summary>
        public void EzSendTo(Address address, params Payload[] payloads)
        {
            if (payloads == null || payloads.Length == 0)
            {
                throw new ArgumentException("EzSendTo requires at least one payload");
            }
            Endpoint.Send(address, EzrPack(payloads[payloads.Length - 1].MsgNum, true, payloads));
        }

        /// <summary>
        /// The easier way to pack your messages: supply the message number and the payloads.
        /// Optionally you can choose to sign the message (prepends the BinMemberAuthenticationPayload).
        /// </summary>
        public byte[] EzrPack(int msgNum, params Payload[] payloads) => EzrPack(msgNum, true, payloads);

        public byte[] EzrPack(int msgNum, bool sig, params Payload[] payloads)
        {
            if (sig)
            {
                var auth = new BinMemberAuthenticationPayload(MyPeer.PublicKey.KeyToBin());
                var withAuth = new Payload[payloads.Length + 1];
                withAuth[0] = auth;
                for (var i = 0; i < payloads.Length; i++)
                {
                    withAuth[i + 1] = payloads[i];
                }
                payloads = withAuth;
            }
            return EzPack(GetPrefix(), msgNum, payloads, sig);
        }

        /// <summary>
        /// Packet = prefix + msg_num(1B) + pack_serializable_list(payloads) [+ 64-byte Ed25519 signature
        /// over ALL preceding packet bytes] (py-ipv8 _ez_pack).
        /// </summary>
        public byte[] EzPack(byte[] prefix, int msgNum, IReadOnlyList<Payload> payloads, bool sig = true)
        {
            var packet = Util.Concat(prefix, new[] { (byte)msgNum }, Serializer.PackSerializableList(payloads));
            if (sig)
            {
                packet = Util.Concat(packet, Crypto.CreateSignature((PrivateKey)MyPeer.Key, packet));
            }
            return packet;
        }

        /// <summary>
        /// Replicates lazy_community._verify_signature exactly, including the "quirky" remainder slice:
        /// remainder = data[2 + len(public_key_bin):-signature_length]. The caller is expected to
        /// re-offset by 23 bytes into this remainder (which lands right after the auth payload for
        /// the standard 74-byte LibNaCLPK public keys).
        /// </summary>
        public (bool Valid, byte[] Remainder) VerifySignature(BinMemberAuthenticationPayload auth, byte[] data)
        {
            var publicKey = Crypto.KeyFromPublicBin(auth.PublicKeyBin);
            var signatureLength = Crypto.GetSignatureLength(publicKey);
            var remainderStart = 2 + auth.PublicKeyBin.Length;
            var remainder = Util.Slice(data, remainderStart,
                                       data.Length - signatureLength - remainderStart);
            var signature = Util.Slice(data, data.Length - signatureLength, signatureLength);
            var valid = Crypto.IsValidSignature(publicKey,
                                                Util.Slice(data, 0, data.Length - signatureLength), signature);
            return (valid, remainder);
        }

        /// <summary>
        /// Unpack a signed message: BinMemberAuthenticationPayload at byte offset 23, signature check,
        /// then [GlobalTimeDistributionPayload, TPayload] from the (re-23-offset) remainder — exactly
        /// like py-ipv8's ``lazy_wrapper`` decorator.
        /// </summary>
        public DecodedPacket<TPayload> EzUnpackAuth<TPayload>(Address sourceAddress, byte[] data)
            where TPayload : Payload, new()
        {
            // UNPACK
            var auth = Serializer.UnpackSerializableAs<BinMemberAuthenticationPayload>(data, 23);
            var (signatureValid, remainder) = VerifySignature(auth, data);
            var unpacked = Serializer.UnpackSerializableList(
                new[] { typeof(GlobalTimeDistributionPayload), typeof(TPayload) }, remainder, 23);
            // ASSERT
            if (!signatureValid)
            {
                throw new PacketDecodingError(
                    $"Incoming packet [{typeof(TPayload).Name}] has an invalid signature");
            }
            // PRODUCE
            var peer = Network.GetVerifiedByPublicKeyBin(auth.PublicKeyBin);
            if (peer != null)
            {
                peer.AddAddress(sourceAddress);
            }
            return new DecodedPacket<TPayload>(peer ?? new Peer(auth.PublicKeyBin, sourceAddress),
                                               (GlobalTimeDistributionPayload)unpacked[0],
                                               (TPayload)unpacked[1]);
        }

        /// <summary>
        /// Unpack a signed message WITHOUT a GlobalTimeDistributionPayload header — the
        /// ``lazy_wrapper``/``lazy_wrapper_wd`` semantics used by py-ipv8's DHT messages (the
        /// packets carry only [auth, payload] + signature).
        /// </summary>
        public (Peer Peer, TPayload Payload) EzUnpackAuthNoDist<TPayload>(Address sourceAddress, byte[] data)
            where TPayload : Payload, new()
        {
            var auth = Serializer.UnpackSerializableAs<BinMemberAuthenticationPayload>(data, 23);
            var (signatureValid, remainder) = VerifySignature(auth, data);
            var unpacked = Serializer.UnpackSerializableList(new[] { typeof(TPayload) }, remainder, 23);
            if (!signatureValid)
            {
                throw new PacketDecodingError(
                    $"Incoming packet [{typeof(TPayload).Name}] has an invalid signature");
            }
            var peer = Network.GetVerifiedByPublicKeyBin(auth.PublicKeyBin);
            if (peer != null)
            {
                peer.AddAddress(sourceAddress);
            }
            return (peer ?? new Peer(auth.PublicKeyBin, sourceAddress), (TPayload)unpacked[0]);
        }

        /// <summary>
        /// Unpack just the normal payloads (starting at byte offset 23), like py-ipv8's
        /// ``lazy_wrapper_unsigned``. Returns (dist, payload) or (null, payload) without global time.
        /// </summary>
        public (GlobalTimeDistributionPayload Dist, TPayload Payload) EzUnpackNoAuth<TPayload>(
            Address sourceAddress, byte[] data, bool globalTime = true)
            where TPayload : Payload, new()
        {
            var formats = new List<Type>();
            if (globalTime)
            {
                formats.Add(typeof(GlobalTimeDistributionPayload));
            }
            formats.Add(typeof(TPayload));
            var unpacked = Serializer.UnpackSerializableList(formats, data, 23);
            var dist = globalTime ? (GlobalTimeDistributionPayload)unpacked[0] : null;
            var payload = (TPayload)unpacked[unpacked.Count - 1];
            return (dist, payload);
        }
    }
}
