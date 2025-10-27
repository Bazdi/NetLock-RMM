using Avalonia.Controls;
using Avalonia.Media;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Global.Helper;

namespace NetLock_RMM_Tray_Icon
{
    public partial class IssueReportWindow : Window
    {
        private bool _isSubmitting;

        public IssueReportWindow()
        {
            InitializeComponent();

            SummaryTextBox.TextChanged += (_, __) => ValidateForm();
            DescriptionTextBox.TextChanged += (_, __) => ValidateForm();
            CancelButton.Click += (_, __) => Close();
            SubmitButton.Click += SubmitButton_Click;
        }

        private void ValidateForm()
        {
            SubmitButton.IsEnabled = !_isSubmitting
                                     && !string.IsNullOrWhiteSpace(SummaryTextBox.Text)
                                     && !string.IsNullOrWhiteSpace(DescriptionTextBox.Text);
        }

        private async void SubmitButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            await SubmitAsync();
        }

        private async Task SubmitAsync()
        {
            if (_isSubmitting)
                return;

            _isSubmitting = true;
            ValidateForm();
            StatusTextBlock.Text = "Problembericht wird erstellt...";
            StatusTextBlock.Foreground = Brushes.Gray;

            try
            {
                string summary = SummaryTextBox.Text?.Trim() ?? string.Empty;
                string description = DescriptionTextBox.Text?.Trim() ?? string.Empty;
                string severity = SeverityComboBox.SelectedItem is ComboBoxItem item
                    ? item.Content?.ToString() ?? "Mittel"
                    : "Mittel";
                string contact = ContactTextBox.Text?.Trim() ?? string.Empty;
                bool includeProcesses = IncludeProcessListCheckBox.IsChecked ?? true;
                bool includePerformance = IncludePerformanceSnapshotCheckBox.IsChecked ?? true;

                var payload = await TrayIssueReportBuilder.BuildAsync(summary, description, severity, contact,
                    includeProcesses, includePerformance);

                string json = JsonSerializer.Serialize(payload, new JsonSerializerOptions
                {
                    WriteIndented = true
                });

                string base64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(json));

                await UserClient.Local_Server_Send_Message($"issue_report${base64}");

                StatusTextBlock.Foreground = Brushes.ForestGreen;
                StatusTextBlock.Text = "Problembericht gesendet.";

                await Task.Delay(1500);

                Close();
            }
            catch (Exception ex)
            {
                Logging.Error("IssueReportWindow", "SubmitAsync", ex.ToString());
                StatusTextBlock.Foreground = Brushes.OrangeRed;
                StatusTextBlock.Text = $"Fehler beim Senden: {ex.Message}";
            }
            finally
            {
                _isSubmitting = false;
                ValidateForm();
            }
        }
    }

    internal static class TrayIssueReportBuilder
    {
        private static readonly string[] SeverityMap = { "niedrig", "mittel", "hoch", "kritisch" };

        public static async Task<TrayIssueReportPayload> BuildAsync(string summary, string description, string severity,
            string contact, bool includeProcesses, bool includePerformance)
        {
            string normalizedSeverity = NormalizeSeverity(severity);

            var payload = new TrayIssueReportPayload
            {
                report_guid = Guid.NewGuid().ToString("N"),
                submitted_at = DateTime.UtcNow,
                reported_by = Environment.UserName,
                machine_name = Environment.MachineName,
                operating_system = Environment.OSVersion.VersionString,
                application_version = typeof(TrayIssueReportBuilder).Assembly.GetName().Version?.ToString() ?? "unknown",
                summary = summary,
                description = description,
                severity = normalizedSeverity,
                contact = string.IsNullOrWhiteSpace(contact) ? null : contact,
            };

            if (includeProcesses || includePerformance)
            {
                payload.context = await CaptureContextAsync(includeProcesses, includePerformance);
            }

            return payload;
        }

        private static string NormalizeSeverity(string severity)
        {
            if (string.IsNullOrWhiteSpace(severity))
                return "mittel";

            string lookup = severity.Trim().ToLowerInvariant();
            if (SeverityMap.Contains(lookup))
                return lookup;

            return lookup switch
            {
                "low" => "niedrig",
                "medium" => "mittel",
                "med" => "mittel",
                "high" => "hoch",
                "critical" => "kritisch",
                _ => "mittel"
            };
        }

        private static async Task<TrayIssueReportContext?> CaptureContextAsync(bool includeProcesses, bool includePerformance)
        {
            var context = new TrayIssueReportContext
            {
                captured_at = DateTime.UtcNow,
                logical_processors = Environment.ProcessorCount,
                environment = new Dictionary<string, string>
                {
                    ["user_domain"] = Environment.UserDomainName,
                    ["user_name"] = Environment.UserName,
                    ["machine_name"] = Environment.MachineName
                }
            };

            if (includePerformance)
            {
                context.cpu_usage_percent = await CaptureCpuUsageAsync();
                context.memory = await CaptureMemoryUsageAsync();
            }

            if (includeProcesses)
            {
                context.top_processes = CaptureProcesses();
            }

            return context;
        }

        private static async Task<double?> CaptureCpuUsageAsync()
        {
            try
            {
                if (OperatingSystem.IsWindows())
                {
                    using var counter = new PerformanceCounter("Processor", "% Processor Time", "_Total", true);
                    counter.NextValue();
                    await Task.Delay(500);
                    return Math.Round(counter.NextValue(), 1);
                }
                else if (OperatingSystem.IsLinux())
                {
                    return await CaptureCpuUsageLinuxAsync();
                }
            }
            catch (Exception ex)
            {
                Logging.Error("TrayIssueReportBuilder", "CaptureCpuUsageAsync", ex.ToString());
            }

            return null;
        }

        private static async Task<double?> CaptureCpuUsageLinuxAsync()
        {
            try
            {
                string[] first = await File.ReadAllLinesAsync("/proc/stat");
                string cpuLine1 = first.FirstOrDefault(l => l.StartsWith("cpu ")) ?? string.Empty;
                if (string.IsNullOrEmpty(cpuLine1))
                    return null;

                var firstValues = cpuLine1.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                    .Skip(1)
                    .Select(v => double.Parse(v))
                    .ToArray();

                await Task.Delay(500);

                string[] second = await File.ReadAllLinesAsync("/proc/stat");
                string cpuLine2 = second.FirstOrDefault(l => l.StartsWith("cpu ")) ?? string.Empty;
                var secondValues = cpuLine2.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                    .Skip(1)
                    .Select(v => double.Parse(v))
                    .ToArray();

                double idle1 = firstValues[3] + firstValues[4];
                double idle2 = secondValues[3] + secondValues[4];
                double nonIdle1 = firstValues.Take(3).Sum() + firstValues.Skip(5).Take(3).Sum();
                double nonIdle2 = secondValues.Take(3).Sum() + secondValues.Skip(5).Take(3).Sum();

                double total1 = idle1 + nonIdle1;
                double total2 = idle2 + nonIdle2;

                double totalDiff = total2 - total1;
                double idleDiff = idle2 - idle1;

                if (totalDiff <= 0)
                    return null;

                double cpuPercentage = ((totalDiff - idleDiff) / totalDiff) * 100.0;
                return Math.Round(cpuPercentage, 1);
            }
            catch (Exception ex)
            {
                Logging.Error("TrayIssueReportBuilder", "CaptureCpuUsageLinuxAsync", ex.ToString());
                return null;
            }
        }

        private static async Task<MemorySnapshot?> CaptureMemoryUsageAsync()
        {
            try
            {
                if (OperatingSystem.IsWindows())
                {
                    using var searcher = new ManagementObjectSearcher("SELECT TotalVisibleMemorySize, FreePhysicalMemory FROM Win32_OperatingSystem");
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        double totalMb = Convert.ToDouble(obj["TotalVisibleMemorySize"]) / 1024.0;
                        double freeMb = Convert.ToDouble(obj["FreePhysicalMemory"]) / 1024.0;
                        return new MemorySnapshot
                        {
                            total_mb = Math.Round(totalMb, 2),
                            available_mb = Math.Round(freeMb, 2),
                            used_mb = Math.Round(totalMb - freeMb, 2)
                        };
                    }
                }
                else if (OperatingSystem.IsLinux())
                {
                    string[] lines = await File.ReadAllLinesAsync("/proc/meminfo");
                    double total = ParseMemInfo(lines, "MemTotal");
                    double free = ParseMemInfo(lines, "MemAvailable");

                    if (total > 0)
                    {
                        return new MemorySnapshot
                        {
                            total_mb = Math.Round(total / 1024.0, 2),
                            available_mb = Math.Round(free / 1024.0, 2),
                            used_mb = Math.Round((total - free) / 1024.0, 2)
                        };
                    }
                }
            }
            catch (Exception ex)
            {
                Logging.Error("TrayIssueReportBuilder", "CaptureMemoryUsageAsync", ex.ToString());
            }

            return null;
        }

        private static double ParseMemInfo(string[] lines, string key)
        {
            string? line = lines.FirstOrDefault(l => l.StartsWith(key, StringComparison.OrdinalIgnoreCase));
            if (line == null)
                return 0;

            string[] parts = line.Split(':', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2)
                return 0;

            string valuePart = parts[1].Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "0";
            if (double.TryParse(valuePart, out double value))
                return value;

            return 0;
        }

        private static List<ProcessSnapshot> CaptureProcesses()
        {
            var processes = new List<ProcessSnapshot>();

            foreach (var process in Process.GetProcesses())
            {
                try
                {
                    string name = process.ProcessName;
                    long workingSet = process.WorkingSet64;
                    DateTime? startTime = TryGetStartTime(process);

                    processes.Add(new ProcessSnapshot
                    {
                        name = name,
                        pid = process.Id,
                        memory_mb = Math.Round(workingSet / 1048576.0, 2),
                        start_time = startTime,
                        file_name = TryGetFileName(process)
                    });
                }
                catch
                {
                    // Ignore processes we cannot access
                }
            }

            return processes
                .OrderByDescending(p => p.memory_mb)
                .Take(10)
                .ToList();
        }

        private static DateTime? TryGetStartTime(Process process)
        {
            try
            {
                return process.StartTime;
            }
            catch
            {
                return null;
            }
        }

        private static string? TryGetFileName(Process process)
        {
            try
            {
                return process.MainModule?.FileName;
            }
            catch
            {
                return null;
            }
        }
    }

    internal class TrayIssueReportPayload
    {
        public string report_guid { get; set; } = string.Empty;
        public DateTime submitted_at { get; set; }
        public string reported_by { get; set; } = string.Empty;
        public string machine_name { get; set; } = string.Empty;
        public string operating_system { get; set; } = string.Empty;
        public string application_version { get; set; } = string.Empty;
        public string summary { get; set; } = string.Empty;
        public string description { get; set; } = string.Empty;
        public string severity { get; set; } = string.Empty;
        public string? contact { get; set; }
        public TrayIssueReportContext? context { get; set; }
    }

    internal class TrayIssueReportContext
    {
        public DateTime captured_at { get; set; }
        public int logical_processors { get; set; }
        public double? cpu_usage_percent { get; set; }
        public MemorySnapshot? memory { get; set; }
        public List<ProcessSnapshot>? top_processes { get; set; }
        public Dictionary<string, string>? environment { get; set; }
    }

    internal class MemorySnapshot
    {
        public double? total_mb { get; set; }
        public double? available_mb { get; set; }
        public double? used_mb { get; set; }
    }

    internal class ProcessSnapshot
    {
        public string name { get; set; } = string.Empty;
        public int pid { get; set; }
        public double memory_mb { get; set; }
        public DateTime? start_time { get; set; }
        public string? file_name { get; set; }
    }
}
