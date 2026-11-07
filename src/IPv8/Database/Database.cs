// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

namespace IPv8.Database
{
    /// <summary>Exception for database integrity violations (py-ipv8 DatabaseException).</summary>
    public class DatabaseException : Exception
    {
        public DatabaseException(string message) : base(message)
        {
        }
    }

    /// <summary>
    /// Marker exception: ignore all commits made within the body of a transaction
    /// (py-ipv8 IgnoreCommits, used with ``with database:``).
    /// </summary>
    public class IgnoreCommits : Exception
    {
        public IgnoreCommits() : base("Ignore all commits made within the transaction scope")
        {
        }
    }

    /// <summary>A database row: ordered column → value mapping. Values are byte[], string, long, double or bool.</summary>
    public sealed class DbRow
    {
        public readonly Dictionary<string, object> Columns = new Dictionary<string, object>();

        public object this[string column]
        {
            get => Columns.TryGetValue(column, out var value) ? value : null;
            set => Columns[column] = value;
        }

        public byte[] GetBytes(string column) => Columns[column] as byte[];

        public string GetString(string column)
        {
            var value = Columns[column];
            if (value is byte[] bytes)
            {
                return Util.Utf8ToString(bytes, 0, bytes.Length);
            }
            return value as string;
        }

        public long GetLong(string column) => Convert.ToInt64(Columns[column], CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// Pure-managed database shim exposing the ipv8/database.py API SHAPE over an in-memory
    /// table store with optional JSON-file persistence.
    ///
    /// DEVIATION (documented, contract Phase 2 step 2a): py-ipv8 wraps native SQLite3. Native
    /// SQLite is forbidden by this port's purity rules. The shim provides:
    ///  - named tables with INSERT-(OR IGNORE)-semantics over composite primary keys,
    ///  - SELECT-WHERE column equality scans,
    ///  - u64 autoincrement row ids (``execute(..., get_lastrowid=True)`` shape),
    ///  - commit deferral (``with database:``) and flush-to-JSON-file persistence.
    /// The per-file-path global lock (py ``db_locks``) is kept.
    /// </summary>
    public abstract class Database
    {
        private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, object> DbLocks =
            new System.Collections.Concurrent.ConcurrentDictionary<string, object>();

        private readonly Dictionary<string, List<DbRow>> _tables = new Dictionary<string, List<DbRow>>();
        private readonly Dictionary<string, string[]> _primaryKeys = new Dictionary<string, string[]>();
        private readonly Dictionary<string, ulong> _autoIncrement = new Dictionary<string, ulong>();
        private readonly object _rowLock = new object();
        private ulong _lastRowId;
        private int _pendingCommits;

        protected Database(string filePath)
        {
            FilePath = filePath ?? throw new ArgumentNullException(nameof(filePath));
        }

        public string FilePath { get; }

        public bool IsOpen { get; private set; }

        /// <summary>The current (expected) version of the database.</summary>
        public int DatabaseVersion { get; private set; }

        /// <summary>Open a connection to the underlying database (file) store.</summary>
        public bool Open(bool initialStatements = true, bool prepareVisioning = true)
        {
            lock (DbLocks.GetOrAdd(FilePath, _ => new object()))
            {
                if (IsOpen)
                {
                    throw new DatabaseException("Database.open() has already been called");
                }
                if (FilePath != ":memory:" && !File.Exists(FilePath))
                {
                    var directory = Path.GetDirectoryName(System.IO.Path.GetFullPath(FilePath));
                    if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                    {
                        Directory.CreateDirectory(directory);
                    }
                }
                LoadFromFile();
                IsOpen = true;
                if (prepareVisioning)
                {
                    var version = GetOptionBytes("database_version");
                    DatabaseVersion = CheckDatabase(version);
                    SetOptionBytes("database_version", Util.Utf8(DatabaseVersion.ToString(CultureInfo.InvariantCulture)));
                    Commit();
                }
                return true;
            }
        }

        /// <summary>Close the connection to the database.</summary>
        public bool Close(bool commit = true)
        {
            lock (DbLocks.GetOrAdd(FilePath, _ => new object()))
            {
                if (!IsOpen)
                {
                    throw new DatabaseException(
                        "Database.close() has been called or Database.open() has not been called");
                }
                if (commit)
                {
                    Commit();
                }
                IsOpen = false;
                return true;
            }
        }

        /// <summary>
        /// Check the database and upgrade if required. Called once on open with the stored
        /// version (empty when the option table is missing); returns the new version.
        /// </summary>
        protected abstract int CheckDatabase(byte[] databaseVersion);

        /// <summary>Commit (= flush to the persistence file; a no-op for ":memory:").</summary>
        public void Commit()
        {
            lock (DbLocks.GetOrAdd(FilePath, _ => new object()))
            {
                if (_pendingCommits > 0)
                {
                    _pendingCommits++;
                    return;
                }
                Flush();
            }
        }

        /// <summary>
        /// Enter a no-commit state (py-ipv8 ``with database:``). The commit is performed when the
        /// returned scope is disposed; raising <see cref="IgnoreCommits"/> inside the scope drops
        /// the deferred commits instead.
        /// NOTE: unlike Python's context manager, a C# ``using`` block cannot observe which
        /// exception escaped the body. For the full ``with database:`` semantics (including
        /// ``raise IgnoreCommits()``) use <see cref="RunInTransaction(Action)"/>.
        /// </summary>
        public IDisposable EnterTransaction()
        {
            _pendingCommits = Math.Max(1, _pendingCommits);
            return new TransactionScope(this);
        }

        /// <summary>
        /// Exact port of py-ipv8's ``with database:`` block: enters the no-commit state, runs the
        /// body, and on exit commits the deferred commits unless the body raised
        /// <see cref="IgnoreCommits"/> (which drops them). Any other exception propagates.
        /// </summary>
        public void RunInTransaction(Action body)
        {
            if (body == null)
            {
                throw new ArgumentNullException(nameof(body));
            }
            lock (DbLocks.GetOrAdd(FilePath, _ => new object()))
            {
                var completed = false;
                _pendingCommits = Math.Max(1, _pendingCommits);
                try
                {
                    body();
                    completed = true;
                }
                catch (IgnoreCommits)
                {
                    // py __exit__ with IgnoreCommits: swallow the exception, drop the deferred commits.
                }
                finally
                {
                    // py __exit__: ``self._pending_commits, pending_commits = 0, self._pending_commits``
                    // (unconditionally reset, exactly like the reference). Commits are performed
                    // only when the body exited normally (exc_type is None in py).
                    var savedPending = _pendingCommits;
                    _pendingCommits = 0;
                    if (completed && savedPending > 1)
                    {
                        Flush();
                    }
                }
            }
        }

        private sealed class TransactionScope : IDisposable
        {
            private readonly Database _database;

            public TransactionScope(Database database)
            {
                _database = database;
            }

            public void Dispose()
            {
                var pending = _database._pendingCommits;
                _database._pendingCommits = 0;
                if (pending > 1)
                {
                    _database.Flush();
                }
            }
        }

        // ------------------------------------------------------------------
        // Row operations (the shim's "execute" replacements)
        // ------------------------------------------------------------------

        /// <summary>Ensure a table exists with the given composite primary key (empty PK = free-form rows).</summary>
        protected void CreateTable(string table, string[] primaryKey)
        {
            lock (_rowLock)
            {
                if (!_tables.ContainsKey(table))
                {
                    _tables[table] = new List<DbRow>();
                    _primaryKeys[table] = primaryKey ?? Array.Empty<string>();
                }
            }
        }

        /// <summary>Insert a row; with orIgnore the insert is skipped when the primary key exists.</summary>
        protected void Insert(string table, DbRow values, bool orIgnore = false)
        {
            lock (_rowLock)
            {
                if (!_tables.ContainsKey(table))
                {
                    throw new DatabaseException($"Table '{table}' does not exist");
                }
                var key = PackKey(table, values);
                if (key != null)
                {
                    foreach (var row in _tables[table])
                    {
                        if (Util.BytesEqual(PackKey(table, row), key))
                        {
                            if (orIgnore)
                            {
                                return;
                            }
                            throw new DatabaseException($"Duplicate primary key in table '{table}'");
                        }
                    }
                }
                _tables[table].Add(values);
            }
        }

        private byte[] PackKey(string table, DbRow row)
        {
            var primaryKey = _primaryKeys.TryGetValue(table, out var value) ? value : Array.Empty<string>();
            if (primaryKey.Length == 0)
            {
                return null;
            }
            var parts = new List<byte[]>();
            foreach (var column in primaryKey)
            {
                parts.Add(Util.Utf8($"{column}\u0000"));
                parts.Add(ValueToBytes(row[column]));
            }
            return Util.Concat(parts.ToArray());
        }

        private static byte[] ValueToBytes(object value)
        {
            switch (value)
            {
                case null: return new byte[] { 0xFF };
                case byte[] bytes: return bytes;
                case string s: return Util.Utf8(s);
                default: return Util.Utf8(Convert.ToString(value, CultureInfo.InvariantCulture));
            }
        }

        /// <summary>Select rows matching all (column, value) equalities; no filters = all rows.</summary>
        protected List<DbRow> Select(string table, params (string Column, object Value)[] where)
        {
            lock (_rowLock)
            {
                if (!_tables.TryGetValue(table, out var rows))
                {
                    throw new DatabaseException($"Table '{table}' does not exist");
                }
                var result = new List<DbRow>();
                foreach (var row in rows)
                {
                    var match = true;
                    foreach (var (column, expected) in where)
                    {
                        if (!Util.BytesEqual(ValueToBytes(row[column]), ValueToBytes(expected)))
                        {
                            match = false;
                            break;
                        }
                    }
                    if (match)
                    {
                        result.Add(row);
                    }
                }
                return result;
            }
        }

        /// <summary>Select the first matching row (py fetch_all=False semantics), or null.</summary>
        protected DbRow SelectFirst(string table, params (string Column, object Value)[] where)
        {
            var rows = Select(table, where);
            return rows.Count > 0 ? rows[0] : null;
        }

        /// <summary>Delete rows matching all (column, value) equalities; returns the number of deletions.</summary>
        protected int Delete(string table, params (string Column, object Value)[] where)
        {
            lock (_rowLock)
            {
                if (!_tables.TryGetValue(table, out var rows))
                {
                    throw new DatabaseException($"Table '{table}' does not exist");
                }
                var removed = 0;
                for (var i = rows.Count - 1; i >= 0; i--)
                {
                    var match = true;
                    foreach (var (column, expected) in where)
                    {
                        if (!Util.BytesEqual(ValueToBytes(rows[i][column]), ValueToBytes(expected)))
                        {
                            match = false;
                            break;
                        }
                    }
                    if (match)
                    {
                        rows.RemoveAt(i);
                        removed++;
                    }
                }
                return removed;
            }
        }

        /// <summary>
        /// Claim the next u64 autoincrement row id for a table (py ``cursor.lastrowid`` shape).
        /// </summary>
        protected ulong NextRowId(string table)
        {
            lock (_rowLock)
            {
                if (!_autoIncrement.TryGetValue(table, out var next))
                {
                    next = 1;
                }
                _autoIncrement[table] = next + 1;
                _lastRowId = next;
                return next;
            }
        }

        /// <summary>The last claimed autoincrement row id.</summary>
        public ulong LastRowId => _lastRowId;

        // ------------------------------------------------------------------
        // option table (database_version bookkeeping)
        // ------------------------------------------------------------------

        private const string OptionTable = "option";

        protected byte[] GetOptionBytes(string key)
        {
            CreateTable(OptionTable, new[] { "key" });
            var row = SelectFirst(OptionTable, ("key", key));
            return row?.GetBytes("value");
        }

        protected void SetOptionBytes(string key, byte[] value)
        {
            CreateTable(OptionTable, new[] { "key" });
            Delete(OptionTable, ("key", key));
            var row = new DbRow { ["key"] = key, ["value"] = value };
            Insert(OptionTable, row);
        }

        // ------------------------------------------------------------------
        // Persistence (JSON file; ":memory:" keeps everything in RAM)
        // ------------------------------------------------------------------

        private void LoadFromFile()
        {
            if (FilePath == ":memory:" || !File.Exists(FilePath))
            {
                return;
            }
            var json = File.ReadAllText(FilePath);
            if (json.Length == 0)
            {
                return;
            }
            var root = (Dictionary<string, object>)MiniJson.DecodeBytesMarkers(MiniJson.Parse(json));
            _tables.Clear();
            _primaryKeys.Clear();
            _autoIncrement.Clear();
            if (root.TryGetValue("database_version", out var version))
            {
                DatabaseVersion = Convert.ToInt32(version, CultureInfo.InvariantCulture);
            }
            if (!root.TryGetValue("tables", out var tablesObject))
            {
                return;
            }
            foreach (var pair in (Dictionary<string, object>)tablesObject)
            {
                var spec = (Dictionary<string, object>)pair.Value;
                var pkColumns = new List<string>();
                foreach (var column in (List<object>)spec["pk"])
                {
                    pkColumns.Add((string)column);
                }
                _primaryKeys[pair.Key] = pkColumns.ToArray();
                var rows = new List<DbRow>();
                foreach (var rowObject in (List<object>)spec["rows"])
                {
                    var row = new DbRow();
                    foreach (var columnPair in (Dictionary<string, object>)rowObject)
                    {
                        row[columnPair.Key] = NormalizeValue(columnPair.Value);
                    }
                    rows.Add(row);
                }
                _tables[pair.Key] = rows;
                if (spec.TryGetValue("autoinc", out var autoinc))
                {
                    _autoIncrement[pair.Key] = Convert.ToUInt64(autoinc, CultureInfo.InvariantCulture);
                }
            }
        }

        private static object NormalizeValue(object value)
        {
            switch (value)
            {
                case long l: return l;
                case double d: return d;
                case bool b: return b;
                case string s: return s;
                default: return value;
            }
        }

        private void Flush()
        {
            if (FilePath == ":memory:")
            {
                return;
            }
            var root = new Dictionary<string, object>
            {
                ["database_version"] = DatabaseVersion
            };
            var tables = new Dictionary<string, object>();
            lock (_rowLock)
            {
                foreach (var pair in _tables)
                {
                    var pkColumns = new List<object>();
                    var primaryKey = _primaryKeys.TryGetValue(pair.Key, out var pk) ? pk : Array.Empty<string>();
                    foreach (var column in primaryKey)
                    {
                        pkColumns.Add(column);
                    }
                    var rows = new List<object>();
                    foreach (var row in pair.Value)
                    {
                        var columns = new Dictionary<string, object>();
                        foreach (var columnPair in row.Columns)
                        {
                            columns[columnPair.Key] = EncodeValue(columnPair.Value);
                        }
                        rows.Add(columns);
                    }
                    var spec = new Dictionary<string, object>
                    {
                        ["pk"] = pkColumns,
                        ["rows"] = rows
                    };
                    if (_autoIncrement.TryGetValue(pair.Key, out var autoinc))
                    {
                        spec["autoinc"] = autoinc;
                    }
                    tables[pair.Key] = spec;
                }
            }
            root["tables"] = tables;
            var directory = Path.GetDirectoryName(System.IO.Path.GetFullPath(FilePath));
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }
            File.WriteAllText(FilePath, MiniJson.Serialize(root), new UTF8Encoding(false));
        }

        private static object EncodeValue(object value)
        {
            switch (value)
            {
                case byte[] bytes: return MiniJsonSerializeBytes(bytes);
                case string s: return s;
                case long l: return l;
                case int i: return (long)i;
                case double d: return d;
                case bool b: return b;
                case null: return null;
                default: return Convert.ToString(value, CultureInfo.InvariantCulture);
            }
        }

        private static Dictionary<string, object> MiniJsonSerializeBytes(byte[] bytes)
            => new Dictionary<string, object> { ["__bytes_b64"] = Convert.ToBase64String(bytes) };
    }
}
