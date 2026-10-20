using Microsoft.Data.Sqlite;

namespace AccessControlStudio.Api;

// Every persisted and returned field is explicit. No argument, token, response, or exception payload enters this model.
public sealed record SecurityAuditEvent(long Id, string CorrelationId, string Kind, DateTimeOffset TimestampUtc,
    string Subject, string Role, string ToolName, string Decision, string ReasonCode,
    string Enforcement, string UpstreamStatus, string? ErrorCategory, long DurationMs);

public sealed record AuditPage(IReadOnlyList<SecurityAuditEvent> Items, long? NextCursor);
public sealed record SecurityOverview(long PersistedTerminalCount, long Allowed, long Denied,
    long Forwarded, long Blocked, long Succeeded, long ToolErrors, long Unknown);

public interface IAuditWriter
{
    Task WriteAsync(SecurityAuditEvent entry, CancellationToken cancellationToken);
}

public sealed class SqliteAuditStore : IAuditWriter
{
    private const int MaximumRows = 20_000;
    private readonly string connectionString;
    private readonly string path;
    private readonly SemaphoreSlim writes = new(1, 1);

    public SqliteAuditStore(string path)
    {
        this.path = Path.GetFullPath(path);
        connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = this.path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Pooling = false,
            DefaultTimeout = 2
        }.ToString();
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA journal_mode = WAL;";
        await command.ExecuteNonQueryAsync(cancellationToken);
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS audit_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              correlation_id TEXT NOT NULL, kind TEXT NOT NULL,
              timestamp_utc TEXT NOT NULL, subject TEXT NOT NULL, role TEXT NOT NULL,
              tool_name TEXT NOT NULL, decision TEXT NOT NULL, reason_code TEXT NOT NULL,
              enforcement TEXT NOT NULL, upstream_status TEXT NOT NULL,
              error_category TEXT, duration_ms INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_audit_correlation ON audit_events(correlation_id);
            """;
        await command.ExecuteNonQueryAsync(cancellationToken);
        command.CommandText = "PRAGMA user_version;";
        var version = Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken));
        if (version is not (0 or 1)) throw new InvalidOperationException("Unsupported audit database schema.");
        if (version == 0)
        {
            command.CommandText = "PRAGMA user_version = 1;";
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    public async Task WriteAsync(SecurityAuditEvent entry, CancellationToken cancellationToken)
    {
        await writes.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenAsync(cancellationToken);
            await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
            await using var command = connection.CreateCommand();
            command.Transaction = (SqliteTransaction)transaction;
            command.CommandText = """
                INSERT INTO audit_events (correlation_id, kind, timestamp_utc, subject, role,
                  tool_name, decision, reason_code, enforcement, upstream_status, error_category, duration_ms)
                VALUES ($correlation, $kind, $timestamp, $subject, $role, $tool, $decision,
                  $reason, $enforcement, $upstream, $error, $duration);
                DELETE FROM audit_events WHERE id <= (SELECT COALESCE(MAX(id), 0) - $retention FROM audit_events);
                """;
            command.Parameters.AddWithValue("$correlation", entry.CorrelationId);
            command.Parameters.AddWithValue("$kind", entry.Kind);
            command.Parameters.AddWithValue("$timestamp", entry.TimestampUtc.ToString("O"));
            command.Parameters.AddWithValue("$subject", entry.Subject);
            command.Parameters.AddWithValue("$role", entry.Role);
            command.Parameters.AddWithValue("$tool", entry.ToolName);
            command.Parameters.AddWithValue("$decision", entry.Decision);
            command.Parameters.AddWithValue("$reason", entry.ReasonCode);
            command.Parameters.AddWithValue("$enforcement", entry.Enforcement);
            command.Parameters.AddWithValue("$upstream", entry.UpstreamStatus);
            command.Parameters.AddWithValue("$error", (object?)entry.ErrorCategory ?? DBNull.Value);
            command.Parameters.AddWithValue("$duration", entry.DurationMs);
            command.Parameters.AddWithValue("$retention", MaximumRows);
            await command.ExecuteNonQueryAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        finally { writes.Release(); }
    }

    public async Task<AuditPage> ReadPageAsync(int limit, long? cursor, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, correlation_id, kind, timestamp_utc, subject, role, tool_name, decision,
              reason_code, enforcement, upstream_status, error_category, duration_ms
            FROM audit_events WHERE $cursor IS NULL OR id < $cursor
            ORDER BY id DESC LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$cursor", (object?)cursor ?? DBNull.Value);
        command.Parameters.AddWithValue("$limit", limit + 1);
        var items = new List<SecurityAuditEvent>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
            items.Add(new(reader.GetInt64(0), reader.GetString(1), reader.GetString(2),
                DateTimeOffset.Parse(reader.GetString(3), System.Globalization.CultureInfo.InvariantCulture),
                reader.GetString(4), reader.GetString(5), reader.GetString(6), reader.GetString(7),
                reader.GetString(8), reader.GetString(9), reader.GetString(10),
                reader.IsDBNull(11) ? null : reader.GetString(11), reader.GetInt64(12)));
        var hasMore = items.Count > limit;
        if (hasMore) items.RemoveAt(limit);
        return new(items, hasMore ? items[^1].Id : null);
    }

    public async Task<SecurityOverview> ReadOverviewAsync(CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT COUNT(*),
              COALESCE(SUM(decision = 'Allow'), 0), COALESCE(SUM(decision = 'Deny'), 0),
              COALESCE(SUM(enforcement = 'Forwarded'), 0), COALESCE(SUM(enforcement = 'Blocked'), 0),
              COALESCE(SUM(upstream_status = 'Succeeded'), 0),
              COALESCE(SUM(upstream_status = 'ToolError'), 0),
              COALESCE(SUM(upstream_status = 'Unknown'), 0)
            FROM audit_events WHERE kind = 'Terminal';
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        await reader.ReadAsync(cancellationToken);
        return new(reader.GetInt64(0), reader.GetInt64(1), reader.GetInt64(2), reader.GetInt64(3),
            reader.GetInt64(4), reader.GetInt64(5), reader.GetInt64(6), reader.GetInt64(7));
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(connectionString);
        try
        {
            await connection.OpenAsync(cancellationToken);
            return connection;
        }
        catch { await connection.DisposeAsync(); throw; }
    }
}

// Best effort by design. Failure never changes enforcement and never retries forwarding.
public sealed class AuditRecorder(IAuditWriter writer, ILogger<AuditRecorder> logger)
{
    public async Task RecordAsync(SecurityAuditEvent entry)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        try { await writer.WriteAsync(entry, timeout.Token); }
        catch (Exception) { logger.LogWarning("Security audit persistence failed ({Kind}).", entry.Kind); }
    }
}
