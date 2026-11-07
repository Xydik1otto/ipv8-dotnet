// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;

namespace IPv8.Attestation.TokenTree
{
    /// <summary>
    /// A double pointer, pointing to a previous token and content
    /// (port of ipv8/attestation/tokentree/token.py::Token).
    /// </summary>
    public class Token : AbstractSignedObject
    {
        public Token(byte[] previousTokenHash, byte[] content, byte[] contentHash,
                     Keyvault.PrivateKey privateKey, byte[] signature)
        {
            if (content != null && contentHash == null)
            {
                Content = content;
                ContentHash = Sha3.Sha3_256(content);
            }
            else if (content == null && contentHash != null)
            {
                Content = null;
                ContentHash = contentHash;
            }
            else
            {
                throw new InvalidOperationException("Specify either content or content_hash!");
            }

            PreviousTokenHash = previousTokenHash;

            // py: super().__init__(private_key, signature) is the LAST statement of __init__,
            // so the plaintext must be fully established before signing.
            Sign(privateKey, signature);
        }

        public byte[] PreviousTokenHash { get; }

        public byte[] Content { get; private set; }

        public byte[] ContentHash { get; }

        /// <summary>The double pointer of this Token in plain text format (two concatenated hashes).</summary>
        public override byte[] GetPlaintext() => Util.Concat(PreviousTokenHash, ContentHash);

        /// <summary>Unserialize a token from the given binary data at the given offset.</summary>
        public static Token Unserialize(byte[] data, Keyvault.PublicKey publicKey, int offset = 0)
        {
            var sigLen = publicKey.GetSignatureLength();
            var previousTokenHash = Util.Slice(data, offset, 32);
            var contentHash = Util.Slice(data, offset + 32, 32);
            var signature = Util.Slice(data, offset + 64, sigLen);
            return new Token(previousTokenHash, null, contentHash, null, signature);
        }

        /// <summary>Attempt to receive some content, only add it if its hash matches what we expect.</summary>
        public bool ReceiveContent(byte[] content)
        {
            var contentHash = Sha3.Sha3_256(content);
            if (Util.BytesEqual(contentHash, ContentHash))
            {
                Content = content;
                return true;
            }
            return false;
        }

        /// <summary>Create and sign a token that exists in a token tree.</summary>
        public static Token Create(Token previousToken, byte[] content, Keyvault.PrivateKey privateKey)
            => new Token(previousToken.GetHash(), content, null, privateKey, null);

        /// <summary>Four byte strings for database insertion (previous hash, signature, content hash, content).</summary>
        public (byte[] PreviousHash, byte[] Signature, byte[] ContentHash, byte[] Content) ToDatabaseTuple()
            => (PreviousTokenHash, Signature, ContentHash, Content);

        /// <summary>Create a Token from a four-byte-string database representation.</summary>
        public static Token FromDatabaseTuple(byte[] previousTokenHash, byte[] signature,
                                              byte[] contentHash, byte[] content)
        {
            var token = new Token(previousTokenHash, null, contentHash, null, signature);
            if (content != null)
            {
                token.ReceiveContent(content);
            }
            return token;
        }

        public override string ToString()
            => $"Token[{Util.Hex(GetHash())}]({Util.Hex(PreviousTokenHash)}, {Util.Hex(ContentHash)})";
    }

    /// <summary>
    /// Raw datatype for chains of double pointers (Tokens)
    /// (port of ipv8/attestation/tokentree/tree.py::TokenTree).
    /// </summary>
    public class TokenTree
    {
        public Keyvault.PublicKey PublicKey { get; }

        public Keyvault.PrivateKey PrivateKey { get; }

        public byte[] GenesisHash { get; }

        /// <summary>The known tokens, by their own hash (py: dict — insertion ordered).</summary>
        public readonly Dictionary<byte[], Token> Elements =
            new Dictionary<byte[], Token>(ByteArrayEqualityComparer.Instance);

        /// <summary>Insertion-ordered pending tokens that miss their predecessor.</summary>
        public readonly LinkedList<Token> Unchained = new LinkedList<Token>();

        public int UnchainedMaxSize { get; set; } = 100;

        public TokenTree(Keyvault.PublicKey publicKey = null, Keyvault.PrivateKey privateKey = null)
        {
            if (publicKey != null && privateKey == null)
            {
                PublicKey = publicKey.Pub();
                PrivateKey = null;
            }
            else if (publicKey == null && privateKey != null)
            {
                PrivateKey = privateKey;
                PublicKey = privateKey.Pub();
            }
            else
            {
                throw new InvalidOperationException("Specify either public_key or private_key!");
            }

            GenesisHash = Sha3.Sha3_256(PublicKey.KeyToBin());
        }

        /// <summary>Tokenize new content and add it to this chain.</summary>
        public Token Add(byte[] content, Token after = null)
        {
            if (PrivateKey == null)
            {
                throw new InvalidOperationException("Attempted to create token without a key!");
            }
            var previousHash = after == null ? GenesisHash : after.GetHash();
            return Append(new Token(previousHash, content, null, PrivateKey, null));
        }

        /// <summary>Add the promise of tokenized content to this chain.</summary>
        public Token AddByHash(byte[] contentHash, Token after = null)
        {
            if (PrivateKey == null)
            {
                throw new InvalidOperationException("Attempted to create token without a key!");
            }
            var previousHash = after == null ? GenesisHash : after.GetHash();
            return Append(new Token(previousHash, null, contentHash, PrivateKey, null));
        }

        /// <summary>
        /// Attempt to add received data to this chain. Data may be pending missing Tokens before
        /// being added to the chain structure. Returns the added token or null.
        /// </summary>
        public Token GatherToken(Token token)
        {
            if (!token.Verify(PublicKey))
            {
                return null;
            }
            if (!Util.BytesEqual(token.PreviousTokenHash, GenesisHash)
                && !Elements.ContainsKey(token.PreviousTokenHash))
            {
                Unchained.AddLast(token);
                if (Unchained.Count > UnchainedMaxSize)
                {
                    // py: popitem(False) removes the FIRST (oldest) item.
                    Unchained.RemoveFirst();
                }
                return null;
            }
            if (Elements.TryGetValue(token.GetHash(), out var shadowToken))
            {
                if (shadowToken.Content == null && token.Content != null)
                {
                    shadowToken.ReceiveContent(token.Content);
                }
                return shadowToken;
            }
            AppendChainReactionToken(token);
            return token;
        }

        /// <summary>Gather all the preceding hashes that have been specified but not collected.</summary>
        public HashSet<byte[]> GetMissing()
        {
            var missing = new HashSet<byte[]>(ByteArrayEqualityComparer.Instance);
            foreach (var token in Unchained)
            {
                missing.Add(token.PreviousTokenHash);
            }
            return missing;
        }

        /// <summary>Verify the chain integrity: all preceding tokens are correctly signed and stored.</summary>
        public bool Verify(Token token, int maxdepth = 1000)
        {
            var current = token;
            var steps = 0;
            while (maxdepth == -1 || maxdepth > steps)
            {
                if (!current.Verify(PublicKey))
                {
                    return false;
                }
                if (Util.BytesEqual(current.PreviousTokenHash, GenesisHash))
                {
                    break;
                }
                if (!Elements.TryGetValue(current.PreviousTokenHash, out var previous))
                {
                    return false;
                }
                current = previous;
                steps++;
            }
            return steps < maxdepth;
        }

        /// <summary>Calculate the path back to the root, including this token.</summary>
        public List<Token> GetRootPath(Token token, int maxdepth = 1000)
        {
            var current = token;
            var steps = 0;
            var path = new List<Token> { token };
            while (maxdepth == -1 || maxdepth > steps)
            {
                if (!current.Verify(PublicKey))
                {
                    return new List<Token>();
                }
                if (Util.BytesEqual(current.PreviousTokenHash, GenesisHash))
                {
                    break;
                }
                if (!Elements.TryGetValue(current.PreviousTokenHash, out var previous))
                {
                    return new List<Token>();
                }
                current = previous;
                path.Add(current);
                steps++;
            }
            if (steps < maxdepth)
            {
                return path;
            }
            return new List<Token>();
        }

        /// <summary>Serialize all the signed double pointers of this chain.</summary>
        public byte[] SerializePublic(Token upTo = null)
        {
            if (upTo != null)
            {
                var output = upTo.GetPlaintextSigned();
                var nextToken = upTo.PreviousTokenHash;
                while (Elements.TryGetValue(nextToken, out var token))
                {
                    output = Util.Concat(output, token.GetPlaintextSigned());
                    nextToken = token.PreviousTokenHash;
                }
                return output;
            }
            var parts = new List<byte[]>();
            foreach (var token in Elements.Values)
            {
                parts.Add(token.GetPlaintextSigned());
            }
            return Util.Concat(parts.ToArray());
        }

        /// <summary>Given a serialized tree format, unserialize with the tree's public key.</summary>
        public bool UnserializePublic(byte[] s)
        {
            var sigLen = PublicKey.GetSignatureLength();
            var chunkSize = 64 + sigLen;
            var correct = true;
            for (var i = 0; i + chunkSize <= s.Length; i += chunkSize)
            {
                correct &= GatherToken(Token.Unserialize(s, PublicKey, i)) != null;
            }
            return correct;
        }

        private Token Append(Token token)
        {
            Elements[token.GetHash()] = token;
            return token;
        }

        /// <summary>Append the given token and wake up any tokens stored in Unchained that pointed to it.</summary>
        private void AppendChainReactionToken(Token token)
        {
            Append(token);
            LinkedListNode<Token> retryNode = null;
            for (var node = Unchained.First; node != null; node = node.Next)
            {
                if (Util.BytesEqual(node.Value.PreviousTokenHash, token.GetHash()))
                {
                    retryNode = node;
                    break;
                }
            }
            if (retryNode != null)
            {
                var retryToken = retryNode.Value;
                Unchained.Remove(retryNode);
                if (GatherToken(retryToken) == null)
                {
                    // Dropped illegal token.
                }
            }
        }
    }
}
