using System.Linq;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.SignalR.Client;
using MudBlazor;
using MySqlConnector;
using Logging;
using NetLock_RMM_Web_Console.Configuration;

namespace NetLock_RMM_Web_Console.Components.Pages.Support
{
    public partial class IssueReports : IAsyncDisposable
    {
        [Inject] public NavigationManager NavigationManager { get; set; } = default!;
        [Inject] public ISnackbar Snackbar { get; set; } = default!;
        [Inject] public IDialogService DialogService { get; set; } = default!;
        [Inject] public AuthenticationStateProvider AuthenticationStateProvider { get; set; } = default!;

        private readonly List<IssueReportRecord> issueReports = new();
        private string searchText = string.Empty;
        private bool permissionChecked;
        private bool hasPermission;
        private bool tenantsFullAccess;
        private List<string> permittedTenantGuids = new();
        private string netlockUsername = string.Empty;
        private string token = string.Empty;
        private HubConnection? hubConnection;

        private IEnumerable<IssueReportRecord> FilteredReports
            => issueReports
                .Where(report => TenantMatches(report))
                .Where(report => MatchesSearch(report))
                .OrderByDescending(report => report.SubmittedAt)
                .ToList();

        protected override async Task OnAfterRenderAsync(bool firstRender)
        {
            if (firstRender)
                await InitializeAsync();
        }

        private async Task InitializeAsync()
        {
            permissionChecked = false;
            hasPermission = await EnsurePermissionsAsync();
            permissionChecked = true;
            await InvokeAsync(StateHasChanged);

            if (!hasPermission)
                return;

            await LoadIssueReportsAsync();
            await SetupSignalRAsync();
            await InvokeAsync(StateHasChanged);
        }

        private async Task<bool> EnsurePermissionsAsync()
        {
            try
            {
                var authState = await AuthenticationStateProvider.GetAuthenticationStateAsync();
                var user = authState.User;

                if (user?.Identity is not { IsAuthenticated: true })
                {
                    NavigationManager.NavigateTo("/logout", true);
                    return false;
                }

                netlockUsername = user.FindFirst(ClaimTypes.Email)?.Value ?? string.Empty;
                token = await Classes.Authentication.User.Get_Remote_Session_Token(netlockUsername);

                hasPermission = await Classes.Authentication.Permissions.Verify_Permission(netlockUsername, "support_incidents_enabled");
                if (!hasPermission)
                    return false;

                permittedTenantGuids = await Classes.Authentication.Permissions.Get_Tenants(netlockUsername, true);
                tenantsFullAccess = await Classes.Authentication.Permissions.Verify_Tenants_Full_Access(netlockUsername);

                return true;
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("/issue_reports -> EnsurePermissionsAsync", "Error", ex.ToString());
                Snackbar.Add($"Berechtigungen konnten nicht geladen werden: {ex.Message}", Severity.Error);
                return false;
            }
        }

        private async Task LoadIssueReportsAsync()
        {
            try
            {
                using var conn = new MySqlConnection(Configuration.MySQL.Connection_String);
                await conn.OpenAsync();
                await EnsureIssueReportTableExistsAsync(conn);

                string query = "SELECT report_guid, device_id, device_name, device_hwid, tenant_id, tenant_guid, location_id, location_guid, submitted_at, reported_by, severity, summary, description, contact, context_json, status FROM device_issue_reports";

                if (!tenantsFullAccess)
                {
                    if (permittedTenantGuids.Count == 0)
                    {
                        issueReports.Clear();
                        return;
                    }

                    string placeholders = string.Join(",", permittedTenantGuids.Select((_, index) => $"@tenant{index}"));
                    query += $" WHERE tenant_guid IN ({placeholders})";
                }

                query += " ORDER BY submitted_at DESC";

                using var cmd = new MySqlCommand(query, conn);
                if (!tenantsFullAccess)
                {
                    for (int i = 0; i < permittedTenantGuids.Count; i++)
                        cmd.Parameters.AddWithValue($"@tenant{i}", permittedTenantGuids[i]);
                }

                using var reader = await cmd.ExecuteReaderAsync();
                issueReports.Clear();

                while (await reader.ReadAsync())
                {
                    issueReports.Add(new IssueReportRecord
                    {
                        ReportGuid = reader.GetString("report_guid"),
                        DeviceId = reader.GetInt32("device_id"),
                        DeviceName = reader.GetString("device_name"),
                        DeviceHwid = reader.GetString("device_hwid"),
                        TenantId = reader.GetInt32("tenant_id"),
                        TenantGuid = reader.GetString("tenant_guid"),
                        LocationId = reader.GetInt32("location_id"),
                        LocationGuid = reader.GetString("location_guid"),
                        SubmittedAt = DateTime.SpecifyKind(reader.GetDateTime("submitted_at"), DateTimeKind.Utc),
                        ReportedBy = reader.GetString("reported_by"),
                        Severity = reader.GetString("severity"),
                        Summary = reader.GetString("summary"),
                        Description = reader.GetString("description"),
                        Contact = reader.IsDBNull(reader.GetOrdinal("contact")) ? null : reader.GetString("contact"),
                        ContextJson = reader.IsDBNull(reader.GetOrdinal("context_json")) ? "{}" : reader.GetString("context_json"),
                        Status = reader.GetString("status")
                    });
                }
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("/issue_reports -> LoadIssueReportsAsync", "Error", ex.ToString());
                Snackbar.Add($"Fehler beim Laden der Problemberichte: {ex.Message}", Severity.Error);
            }
        }

        private async Task SetupSignalRAsync()
        {
            try
            {
                if (hubConnection != null)
                    return;

                var adminIdentity = new Remote_Admin_Identity { token = token };
                string identityJson = JsonSerializer.Serialize(new RemoteIdentityEnvelope { admin_identity = adminIdentity });

                hubConnection = new HubConnectionBuilder()
                    .WithUrl(Configuration.Remote_Server.Connection_String + "/commandHub", options =>
                    {
                        options.Headers.Add("Admin-Identity", Uri.EscapeDataString(identityJson));
                    })
                    .WithAutomaticReconnect()
                    .Build();

                hubConnection.On<string>("ReceiveTrayIconIssueReport", message => HandleReportBroadcastAsync(message));
                hubConnection.On<string>("ReceiveTrayIconIssueReportStatusChanged", message => HandleStatusBroadcastAsync(message));

                hubConnection.Closed += async error =>
                {
                    Logging.Handler.Warning("/issue_reports -> SetupSignalRAsync", "Connection closed", error?.ToString() ?? string.Empty);
                    await Task.Delay(TimeSpan.FromSeconds(5));
                    await TryStartHubAsync();
                };

                await TryStartHubAsync();
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("/issue_reports -> SetupSignalRAsync", "Error", ex.ToString());
                Snackbar.Add($"SignalR-Verbindung konnte nicht hergestellt werden: {ex.Message}", Severity.Warning);
            }
        }

        private async Task TryStartHubAsync()
        {
            if (hubConnection == null)
                return;

            if (hubConnection.State == HubConnectionState.Connected)
                return;

            try
            {
                await hubConnection.StartAsync();
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("/issue_reports -> TryStartHubAsync", "Error", ex.ToString());
            }
        }

        private async Task HandleReportBroadcastAsync(string message)
        {
            try
            {
                IssueReportBroadcast? broadcast = JsonSerializer.Deserialize<IssueReportBroadcast>(message);
                if (broadcast == null)
                    return;

                if (!TenantMatches(broadcast))
                    return;

                await InvokeAsync(() =>
                {
                    var existing = issueReports.FirstOrDefault(r => r.ReportGuid == broadcast.report_guid);
                    if (existing != null)
                        UpdateRecord(existing, broadcast);
                    else
                        issueReports.Insert(0, IssueReportRecord.FromBroadcast(broadcast));

                    StateHasChanged();
                });
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("/issue_reports -> HandleReportBroadcastAsync", "Error", ex.ToString());
            }
        }

        private async Task HandleStatusBroadcastAsync(string message)
        {
            try
            {
                IssueReportBroadcast? broadcast = JsonSerializer.Deserialize<IssueReportBroadcast>(message);
                if (broadcast == null)
                    return;

                await InvokeAsync(() =>
                {
                    var existing = issueReports.FirstOrDefault(r => r.ReportGuid == broadcast.report_guid);
                    if (existing != null)
                    {
                        UpdateRecord(existing, broadcast);
                        StateHasChanged();
                    }
                });
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("/issue_reports -> HandleStatusBroadcastAsync", "Error", ex.ToString());
            }
        }

        private static void UpdateRecord(IssueReportRecord target, IssueReportBroadcast source)
        {
            target.DeviceId = source.device_id;
            target.DeviceName = source.device_name;
            target.DeviceHwid = source.device_hwid;
            target.TenantId = source.tenant_id;
            target.TenantGuid = source.tenant_guid;
            target.LocationId = source.location_id;
            target.LocationGuid = source.location_guid;
            target.SubmittedAt = DateTime.SpecifyKind(source.submitted_at, DateTimeKind.Utc);
            target.ReportedBy = source.reported_by;
            target.Severity = source.severity;
            target.Summary = source.summary;
            target.Description = source.description;
            target.Contact = source.contact;
            target.ContextJson = source.context_json ?? "{}";
            target.Status = source.status;
            target.ResetCachedContext();
        }

        private RenderFragment SeverityChip(IssueReportRecord report) => builder =>
        {
            builder.OpenComponent<MudChip>(0);
            builder.AddAttribute(1, nameof(MudChip.Color), SeverityColor(report.Severity));
            builder.AddAttribute(2, nameof(MudChip.Variant), Variant.Outlined);
            builder.AddAttribute(3, nameof(MudChip.Dense), true);
            builder.AddAttribute(4, nameof(MudChip.ChildContent), (RenderFragment)(childBuilder =>
            {
                childBuilder.AddContent(5, FormatSeverity(report.Severity));
            }));
            builder.CloseComponent();
        };

        private RenderFragment StatusChip(IssueReportRecord report) => builder =>
        {
            builder.OpenComponent<MudChip>(0);
            builder.AddAttribute(1, nameof(MudChip.Color), StatusColor(report.Status));
            builder.AddAttribute(2, nameof(MudChip.Variant), Variant.Filled);
            builder.AddAttribute(3, nameof(MudChip.Dense), true);
            builder.AddAttribute(4, nameof(MudChip.ChildContent), (RenderFragment)(childBuilder =>
            {
                childBuilder.AddContent(5, FormatStatus(report.Status));
            }));
            builder.CloseComponent();
        };

        private Color SeverityColor(string severity) => severity.ToLowerInvariant() switch
        {
            "kritisch" => Color.Error,
            "hoch" => Color.Error,
            "mittel" => Color.Warning,
            _ => Color.Success
        };

        private Color StatusColor(string status) => status.ToLowerInvariant() switch
        {
            "resolved" => Color.Success,
            "in_progress" => Color.Warning,
            _ => Color.Info
        };

        private static string FormatSeverity(string severity) => severity switch
        {
            "kritisch" => "Kritisch",
            "hoch" => "Hoch",
            "mittel" => "Mittel",
            "niedrig" => "Niedrig",
            _ => severity
        };

        private static string FormatStatus(string status) => status switch
        {
            "resolved" => "Erledigt",
            "in_progress" => "In Bearbeitung",
            "open" => "Offen",
            _ => status
        };

        private bool MatchesSearch(IssueReportRecord report)
        {
            if (string.IsNullOrWhiteSpace(searchText))
                return true;

            string needle = searchText.Trim().ToLowerInvariant();

            return (report.DeviceName?.ToLowerInvariant().Contains(needle) ?? false)
                   || (report.ReportedBy?.ToLowerInvariant().Contains(needle) ?? false)
                   || (report.Summary?.ToLowerInvariant().Contains(needle) ?? false)
                   || (report.Description?.ToLowerInvariant().Contains(needle) ?? false)
                   || (report.Contact?.ToLowerInvariant().Contains(needle) ?? false);
        }

        private bool TenantMatches(IssueReportRecord report)
            => tenantsFullAccess || permittedTenantGuids.Contains(report.TenantGuid);

        private bool TenantMatches(IssueReportBroadcast report)
            => tenantsFullAccess || permittedTenantGuids.Contains(report.tenant_guid);

        private async Task UpdateStatusAsync(IssueReportRecord report, string status)
        {
            if (hubConnection == null)
                return;

            try
            {
                var request = new IssueReportStatusUpdateRequest
                {
                    admin_identity = new Remote_Admin_Identity { token = token },
                    update = new IssueReportStatusUpdate { report_guid = report.ReportGuid, status = status }
                };

                string payload = JsonSerializer.Serialize(request);
                await hubConnection.SendAsync("UpdateIssueReportStatus", payload);

                report.Status = status;
                StateHasChanged();
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("/issue_reports -> UpdateStatusAsync", "Error", ex.ToString());
                Snackbar.Add($"Status konnte nicht aktualisiert werden: {ex.Message}", Severity.Error);
            }
        }

        private async Task ShowDetailsAsync(IssueReportRecord report)
        {
            try
            {
                var parameters = new DialogParameters
                {
                    ["Report"] = report
                };

                var options = new DialogOptions
                {
                    CloseButton = true,
                    MaxWidth = MaxWidth.Large,
                    FullWidth = true
                };

                await DialogService.Show<Dialogs.IssueReportDetailsDialog>(report.Summary, parameters, options).Result;
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("/issue_reports -> ShowDetailsAsync", "Error", ex.ToString());
            }
        }

        private static async Task EnsureIssueReportTableExistsAsync(MySqlConnection conn)
        {
            string createTableSql = @"CREATE TABLE IF NOT EXISTS `device_issue_reports` (
                    `id` INT NOT NULL AUTO_INCREMENT,
                    `report_guid` VARCHAR(64) NOT NULL,
                    `device_id` INT NOT NULL,
                    `device_name` VARCHAR(255) NOT NULL,
                    `device_hwid` VARCHAR(255) NULL,
                    `tenant_id` INT NOT NULL,
                    `tenant_guid` VARCHAR(64) NOT NULL,
                    `location_id` INT NOT NULL,
                    `location_guid` VARCHAR(64) NOT NULL,
                    `submitted_at` DATETIME NOT NULL,
                    `reported_by` VARCHAR(255) NOT NULL,
                    `severity` VARCHAR(32) NOT NULL,
                    `summary` TEXT NOT NULL,
                    `description` LONGTEXT NOT NULL,
                    `contact` VARCHAR(255) NULL,
                    `context_json` LONGTEXT NULL,
                    `status` VARCHAR(32) NOT NULL DEFAULT 'open',
                    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    `updated_at` DATETIME NULL,
                    PRIMARY KEY (`id`),
                    UNIQUE KEY `ux_device_issue_reports_report_guid` (`report_guid`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";

            using var cmd = new MySqlCommand(createTableSql, conn);
            await cmd.ExecuteNonQueryAsync();
        }

        public async ValueTask DisposeAsync()
        {
            if (hubConnection != null)
            {
                await hubConnection.DisposeAsync();
            }
        }

        private record RemoteIdentityEnvelope
        {
            public Remote_Admin_Identity admin_identity { get; set; } = new();
        }

        public class Remote_Admin_Identity
        {
            public string token { get; set; } = string.Empty;
        }

        public class IssueReportStatusUpdateRequest
        {
            public Remote_Admin_Identity? admin_identity { get; set; }
            public IssueReportStatusUpdate? update { get; set; }
        }

        public class IssueReportStatusUpdate
        {
            public string report_guid { get; set; } = string.Empty;
            public string status { get; set; } = string.Empty;
        }

        public class IssueReportBroadcast
        {
            public string report_guid { get; set; } = string.Empty;
            public int device_id { get; set; }
            public string device_name { get; set; } = string.Empty;
            public string device_hwid { get; set; } = string.Empty;
            public int tenant_id { get; set; }
            public string tenant_guid { get; set; } = string.Empty;
            public int location_id { get; set; }
            public string location_guid { get; set; } = string.Empty;
            public DateTime submitted_at { get; set; }
            public string reported_by { get; set; } = string.Empty;
            public string severity { get; set; } = string.Empty;
            public string summary { get; set; } = string.Empty;
            public string description { get; set; } = string.Empty;
            public string? contact { get; set; }
            public string? context_json { get; set; }
            public string status { get; set; } = "open";
        }

        public class IssueReportRecord
        {
            private TrayIssueReportContext? cachedContext;

            public string ReportGuid { get; set; } = string.Empty;
            public int DeviceId { get; set; }
            public string DeviceName { get; set; } = string.Empty;
            public string DeviceHwid { get; set; } = string.Empty;
            public int TenantId { get; set; }
            public string TenantGuid { get; set; } = string.Empty;
            public int LocationId { get; set; }
            public string LocationGuid { get; set; } = string.Empty;
            public DateTime SubmittedAt { get; set; }
            public string ReportedBy { get; set; } = string.Empty;
            public string Severity { get; set; } = string.Empty;
            public string Summary { get; set; } = string.Empty;
            public string Description { get; set; } = string.Empty;
            public string? Contact { get; set; }
            public string ContextJson { get; set; } = "{}";
            public string Status { get; set; } = "open";

            public TrayIssueReportContext? Context
            {
                get
                {
                    if (cachedContext == null && !string.IsNullOrWhiteSpace(ContextJson))
                    {
                        try
                        {
                            cachedContext = JsonSerializer.Deserialize<TrayIssueReportContext>(ContextJson);
                        }
                        catch
                        {
                            cachedContext = null;
                        }
                    }

                    return cachedContext;
                }
            }

            public void ResetCachedContext() => cachedContext = null;

            public static IssueReportRecord FromBroadcast(IssueReportBroadcast source)
            {
                return new IssueReportRecord
                {
                    ReportGuid = source.report_guid,
                    DeviceId = source.device_id,
                    DeviceName = source.device_name,
                    DeviceHwid = source.device_hwid,
                    TenantId = source.tenant_id,
                    TenantGuid = source.tenant_guid,
                    LocationId = source.location_id,
                    LocationGuid = source.location_guid,
                    SubmittedAt = DateTime.SpecifyKind(source.submitted_at, DateTimeKind.Utc),
                    ReportedBy = source.reported_by,
                    Severity = source.severity,
                    Summary = source.summary,
                    Description = source.description,
                    Contact = source.contact,
                    ContextJson = source.context_json ?? "{}",
                    Status = source.status
                };
            }
        }

        public class TrayIssueReportContext
        {
            public DateTime captured_at { get; set; }
            public int logical_processors { get; set; }
            public double? cpu_usage_percent { get; set; }
            public MemorySnapshot? memory { get; set; }
            public List<ProcessSnapshot>? top_processes { get; set; }
            public Dictionary<string, string>? environment { get; set; }
        }

        public class MemorySnapshot
        {
            public double? total_mb { get; set; }
            public double? available_mb { get; set; }
            public double? used_mb { get; set; }
        }

        public class ProcessSnapshot
        {
            public string name { get; set; } = string.Empty;
            public int pid { get; set; }
            public double memory_mb { get; set; }
            public DateTime? start_time { get; set; }
            public string? file_name { get; set; }
        }
    }
}
