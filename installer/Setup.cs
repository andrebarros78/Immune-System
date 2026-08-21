using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Microsoft.Win32;

[assembly: AssemblyTitle("Sistema Imunologico Setup")]
[assembly: AssemblyCompany("BarrosTech")]
[assembly: AssemblyProduct("Sistema Imunologico")]
[assembly: AssemblyVersion("1.2.0.0")]
[assembly: AssemblyFileVersion("1.2.0.0")]

namespace BarrosTech.ImmuneInstaller
{
    internal sealed class InstallResult
    {
        internal bool Success;
        internal string Message;
    }

    internal static class InstallerEngine
    {
        internal static readonly string InstallRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "BarrosTech", "Sistema Imunologico");
        internal static readonly string DataRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "BarrosTech", "Sistema Imunologico");
        private const string UninstallKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SistemaImunologico";

        internal static bool IsInstalled()
        {
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(UninstallKey))
                return key != null && Directory.Exists(InstallRoot);
        }

        internal static InstallResult Install(string targetType, string targetValue, bool repair)
        {
            InstallResult result = new InstallResult();
            string temp = null;
            string backup = null;
            bool hadExisting = Directory.Exists(InstallRoot);
            try
            {
                ValidateWindows();
                temp = Path.Combine(Path.GetTempPath(), "SistemaImunologico-Setup-" + Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(temp);
                string zip = Path.Combine(temp, "payload.zip");
                ExtractPayloadResource(zip);
                VerifyFileHash(zip, BuildConstants.PayloadZipSha256);
                string stage = Path.Combine(temp, "payload");
                ZipFile.ExtractToDirectory(zip, stage);
                VerifyPayloadManifest(stage);

                Directory.CreateDirectory(DataRoot);
                if (hadExisting)
                {
                    string existingQuiesce = Path.Combine(InstallRoot, "host", "quiesce-host.ps1");
                    if (File.Exists(existingQuiesce))
                    {
                        int q = RunPowerShell(existingQuiesce, "-InstallRoot " + Q(InstallRoot) + " -DataRoot " + Q(DataRoot), 120000);
                        if (q != 0) throw new InvalidOperationException("NÃ£o foi possÃ­vel colocar a instalaÃ§Ã£o existente em estado seguro para atualizaÃ§Ã£o.");
                    }
                    string rollbackRoot = Path.Combine(DataRoot, "rollback");
                    Directory.CreateDirectory(rollbackRoot);
                    backup = Path.Combine(rollbackRoot, "install-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss"));
                    CopyDirectory(InstallRoot, backup, true);
                }

                Directory.CreateDirectory(InstallRoot);
                CopyDirectory(stage, InstallRoot, true);

                string request = Path.Combine(DataRoot, "install-request.json");
                Dictionary<string, object> req = new Dictionary<string, object>();
                req["operation"] = repair ? "repair" : "install";
                req["target_type"] = targetType ?? "none";
                req["target_value"] = targetValue ?? "";
                req["installer_version"] = BuildConstants.InstallerVersion;
                req["core_version"] = BuildConstants.CoreVersion;
                req["core_commit"] = BuildConstants.CoreCommit;
                req["requested_at_utc"] = DateTime.UtcNow.ToString("o");
                File.WriteAllText(request, new JavaScriptSerializer().Serialize(req), new UTF8Encoding(false));

                string bootstrapOutput;
                int boot = RunPowerShellCapture(
                    Path.Combine(InstallRoot, "host", "bootstrap-host.ps1"),
                    "-InstallRoot " + Q(InstallRoot) + " -DataRoot " + Q(DataRoot) + " -RequestFile " + Q(request),
                    180000,
                    out bootstrapOutput);
                try { File.WriteAllText(Path.Combine(DataRoot, "installer-bootstrap.log"), bootstrapOutput ?? "", new UTF8Encoding(false)); } catch { }
                if (boot != 0) throw new InvalidOperationException("Bootstrap do host falhou. CÃ³digo=" + boot + " SaÃ­da=" + (bootstrapOutput ?? "").Trim());

                string setupDir = Path.Combine(InstallRoot, "setup");
                Directory.CreateDirectory(setupDir);
                string installedSetup = Path.Combine(setupDir, "Sistema-Imunologico-Setup.exe");
                string currentExe = Assembly.GetExecutingAssembly().Location;
                if (!PathsEqual(currentExe, installedSetup)) File.Copy(currentExe, installedSetup, true);
                RegisterUninstall(installedSetup);

                result.Success = true;
                result.Message = repair ? "Reparo concluÃ­do e validado." : "InstalaÃ§Ã£o concluÃ­da e validada.";
                return result;
            }
            catch (Exception ex)
            {
                try
                {
                    Directory.CreateDirectory(DataRoot);
                    File.WriteAllText(Path.Combine(DataRoot, "installer-error.log"), DateTime.UtcNow.ToString("o") + " " + ex.ToString(), new UTF8Encoding(false));
                }
                catch { }
                try { CleanupHostBestEffort(); } catch { }
                try
                {
                    if (hadExisting && backup != null && Directory.Exists(backup))
                    {
                        if (Directory.Exists(InstallRoot)) Directory.Delete(InstallRoot, true);
                        CopyDirectory(backup, InstallRoot, true);
                    }
                    else if (!hadExisting && Directory.Exists(InstallRoot))
                    {
                        Directory.Delete(InstallRoot, true);
                    }
                }
                catch { }
                result.Success = false;
                result.Message = ex.Message;
                return result;
            }
            finally
            {
                try { if (temp != null && Directory.Exists(temp)) Directory.Delete(temp, true); } catch { }
            }
        }

        internal static InstallResult Uninstall(bool purge)
        {
            InstallResult result = new InstallResult();
            try
            {
                string cleanup = Path.Combine(InstallRoot, "host", "uninstall-host.ps1");
                if (File.Exists(cleanup)) { string cleanupOutput; int cleanupCode = RunPowerShellCapture(cleanup, "-InstallRoot " + Q(InstallRoot) + " -DataRoot " + Q(DataRoot), 120000, out cleanupOutput); if (cleanupCode != 0) throw new InvalidOperationException("Uninstall host cleanup falhou. CÃ³digo=" + cleanupCode + " SaÃ­da=" + (cleanupOutput ?? "").Trim()); }
                using (RegistryKey root = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", true))
                    if (root != null) root.DeleteSubKeyTree("SistemaImunologico", false);

                string currentExe = Assembly.GetExecutingAssembly().Location;
                if (IsUnder(currentExe, InstallRoot))
                    ScheduleDeleteAfterExit(InstallRoot, purge ? DataRoot : null);
                else
                {
                    if (Directory.Exists(InstallRoot)) Directory.Delete(InstallRoot, true);
                    if (purge && Directory.Exists(DataRoot)) Directory.Delete(DataRoot, true);
                }
                result.Success = true;
                result.Message = purge ? "Sistema e dados removidos." : "Sistema removido; evidÃªncias e backups preservados.";
                return result;
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Message = ex.Message;
                return result;
            }
        }

        internal static int RunSelfTest(out string output)
        {
            string script = Path.Combine(InstallRoot, "host", "self-test.ps1");
            if (!File.Exists(script)) { output = "SELF_TEST_SCRIPT_MISSING"; return 2; }
            return RunPowerShellCapture(script, "-InstallRoot " + Q(InstallRoot) + " -DataRoot " + Q(DataRoot), 120000, out output);
        }

        private static void ValidateWindows()
        {
            Version v = Environment.OSVersion.Version;
            if (Environment.OSVersion.Platform != PlatformID.Win32NT || v.Major < 10)
                throw new PlatformNotSupportedException("Windows 10/11 ou Windows Server equivalente Ã© obrigatÃ³rio.");
            if (!Environment.Is64BitOperatingSystem)
                throw new PlatformNotSupportedException("Windows 64-bit Ã© obrigatÃ³rio.");
        }

        private static void ExtractPayloadResource(string output)
        {
            using (Stream input = Assembly.GetExecutingAssembly().GetManifestResourceStream("Immune.Payload.zip"))
            {
                if (input == null) throw new InvalidDataException("Payload embutido ausente.");
                using (FileStream fs = new FileStream(output, FileMode.Create, FileAccess.Write, FileShare.None)) input.CopyTo(fs);
            }
        }

        private static void VerifyPayloadManifest(string stage)
        {
            string manifest = Path.Combine(stage, "payload.sha256");
            if (!File.Exists(manifest)) throw new InvalidDataException("Manifesto SHA-256 do payload ausente.");
            foreach (string raw in File.ReadAllLines(manifest, Encoding.UTF8))
            {
                string line = raw.Trim();
                if (line.Length == 0) continue;
                if (line.Length < 67 || line[64] != ' ' || line[65] != '*') throw new InvalidDataException("Linha invÃ¡lida no manifesto de payload.");
                string expected = line.Substring(0, 64).ToLowerInvariant();
                string relative = line.Substring(66).Replace('/', Path.DirectorySeparatorChar);
                string full = Path.GetFullPath(Path.Combine(stage, relative));
                if (!IsUnder(full, stage)) throw new InvalidDataException("Path traversal bloqueado no payload.");
                VerifyFileHash(full, expected);
            }
        }

        private static void VerifyFileHash(string path, string expected)
        {
            if (!File.Exists(path)) throw new FileNotFoundException("Arquivo do payload ausente", path);
            string actual;
            using (SHA256 sha = SHA256.Create())
            using (FileStream fs = File.OpenRead(path)) actual = ToHex(sha.ComputeHash(fs));
            if (!string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Falha de integridade SHA-256: " + Path.GetFileName(path));
        }

        private static string ToHex(byte[] data)
        {
            StringBuilder sb = new StringBuilder(data.Length * 2);
            foreach (byte b in data) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }

        private static void CopyDirectory(string source, string destination, bool overwrite)
        {
            Directory.CreateDirectory(destination);
            foreach (string dir in Directory.GetDirectories(source, "*", SearchOption.AllDirectories))
                Directory.CreateDirectory(Path.Combine(destination, dir.Substring(source.Length).TrimStart(Path.DirectorySeparatorChar)));
            foreach (string file in Directory.GetFiles(source, "*", SearchOption.AllDirectories))
            {
                string rel = file.Substring(source.Length).TrimStart(Path.DirectorySeparatorChar);
                string dst = Path.Combine(destination, rel);
                Directory.CreateDirectory(Path.GetDirectoryName(dst));
                File.Copy(file, dst, overwrite);
            }
        }

        private static void RegisterUninstall(string setupPath)
        {
            using (RegistryKey key = Registry.LocalMachine.CreateSubKey(UninstallKey))
            {
                key.SetValue("DisplayName", "Sistema ImunolÃ³gico");
                key.SetValue("DisplayVersion", BuildConstants.InstallerVersion);
                key.SetValue("Publisher", "BarrosTech");
                key.SetValue("InstallLocation", InstallRoot);
                key.SetValue("UninstallString", Q(setupPath) + " /uninstall");
                key.SetValue("ModifyPath", Q(setupPath) + " /repair");
                key.SetValue("NoModify", 0, RegistryValueKind.DWord);
                key.SetValue("NoRepair", 0, RegistryValueKind.DWord);
            }
        }

        private static void CleanupHostBestEffort()
        {
            string cleanup = Path.Combine(InstallRoot, "host", "uninstall-host.ps1");
            if (File.Exists(cleanup)) RunPowerShell(cleanup, "-InstallRoot " + Q(InstallRoot) + " -DataRoot " + Q(DataRoot), 60000);
        }

        private static int RunPowerShell(string script, string arguments, int timeoutMs)
        {
            string ignored;
            return RunPowerShellCapture(script, arguments, timeoutMs, out ignored);
        }

        private static int RunPowerShellCapture(string script, string arguments, int timeoutMs, out string output)
        {
            string ps = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"WindowsPowerShell\v1.0\powershell.exe");
            ProcessStartInfo psi = new ProcessStartInfo(ps, "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File " + Q(script) + " " + arguments);
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            StringBuilder sb = new StringBuilder();
            using (Process p = new Process())
            {
                p.StartInfo = psi;
                p.OutputDataReceived += delegate(object sender, DataReceivedEventArgs e) { if (e.Data != null) lock (sb) sb.AppendLine(e.Data); };
                p.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs e) { if (e.Data != null) lock (sb) sb.AppendLine(e.Data); };
                p.Start();
                p.BeginOutputReadLine();
                p.BeginErrorReadLine();
                if (!p.WaitForExit(timeoutMs))
                {
                    try { p.Kill(); } catch { }
                    throw new TimeoutException("Tempo limite excedido em " + Path.GetFileName(script));
                }
                p.WaitForExit();
                output = sb.ToString();
                return p.ExitCode;
            }
        }

        private static void ScheduleDeleteAfterExit(string installDir, string dataDir)
        {
            int pid = Process.GetCurrentProcess().Id;
            string ps = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"WindowsPowerShell\v1.0\powershell.exe");
            string script = "Wait-Process -Id " + pid + " -ErrorAction SilentlyContinue; Start-Sleep -Milliseconds 500; Remove-Item -LiteralPath '" + installDir.Replace("'", "''") + "' -Recurse -Force -ErrorAction SilentlyContinue";
            if (!string.IsNullOrEmpty(dataDir)) script += "; Remove-Item -LiteralPath '" + dataDir.Replace("'", "''") + "' -Recurse -Force -ErrorAction SilentlyContinue";
            ProcessStartInfo psi = new ProcessStartInfo(ps, "-NoProfile -NonInteractive -WindowStyle Hidden -Command " + Q(script));
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            Process.Start(psi);
        }

        private static bool IsUnder(string path, string root)
        {
            string p = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            string r = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            return p.StartsWith(r, StringComparison.OrdinalIgnoreCase) || PathsEqual(path, root);
        }

        private static bool PathsEqual(string a, string b)
        {
            return string.Equals(Path.GetFullPath(a).TrimEnd(Path.DirectorySeparatorChar), Path.GetFullPath(b).TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase);
        }

        internal static string Q(string text)
        {
            return "\"" + (text ?? "").Replace("\"", "\\\"") + "\"";
        }
    }

    internal sealed class SetupForm : Form
    {
        private readonly ComboBox targetType = new ComboBox();
        private readonly TextBox targetValue = new TextBox();
        private readonly Label status = new Label();
        private readonly Button primary = new Button();
        private readonly Dictionary<int, string> mapping = new Dictionary<int, string>
        {
            {0,"this_pc"},{1,"local_project"},{2,"other_windows"},{3,"linux_server"},{4,"api"},{5,"database"},{6,"docker"},{7,"custom"},{8,"none"}
        };

        internal SetupForm()
        {
            Text = "Sistema ImunolÃ³gico â€” InstalaÃ§Ã£o";
            StartPosition = FormStartPosition.CenterScreen;
            Size = new Size(760, 500);
            Font = new Font("Segoe UI", 10F);

            Label title = new Label { Text = "Sistema ImunolÃ³gico", Font = new Font("Segoe UI Semibold", 20F), AutoSize = true, Location = new Point(28, 24) };
            Controls.Add(title);
            Label question = new Label { Text = "QUAL SISTEMA DESEJA PROTEGER?", Font = new Font("Segoe UI Semibold", 12F), AutoSize = true, Location = new Point(30, 90) };
            Controls.Add(question);

            targetType.DropDownStyle = ComboBoxStyle.DropDownList;
            targetType.Items.AddRange(new object[] {
                "Este computador",
                "Um projeto/aplicaÃ§Ã£o deste computador",
                "Outro computador Windows",
                "Servidor Linux / VPS",
                "API / serviÃ§o web",
                "Banco de dados",
                "Sistema em Docker",
                "Outro sistema personalizado",
                "NÃ£o anexar agora"
            });
            targetType.SelectedIndex = 8;
            targetType.Location = new Point(30, 125);
            targetType.Width = 670;
            Controls.Add(targetType);

            Label valueLabel = new Label { Text = "Caminho/endereÃ§o/identificaÃ§Ã£o (quando aplicÃ¡vel):", AutoSize = true, Location = new Point(30, 175) };
            Controls.Add(valueLabel);
            targetValue.Location = new Point(30, 205);
            targetValue.Width = 670;
            Controls.Add(targetValue);

            primary.Text = InstallerEngine.IsInstalled() ? "Reparar" : "Instalar";
            primary.Location = new Point(30, 270);
            primary.Width = 160;
            primary.Click += delegate { RunInstall(); };
            Controls.Add(primary);

            Button uninstall = new Button { Text = "Desinstalar", Location = new Point(210, 270), Width = 160, Enabled = InstallerEngine.IsInstalled() };
            uninstall.Click += delegate
            {
                if (MessageBox.Show("Desinstalar o Sistema ImunolÃ³gico?", "ConfirmaÃ§Ã£o", MessageBoxButtons.YesNo) == DialogResult.Yes)
                {
                    InstallResult r = InstallerEngine.Uninstall(false);
                    MessageBox.Show(r.Message, "Sistema ImunolÃ³gico");
                    if (r.Success) Close();
                }
            };
            Controls.Add(uninstall);

            status.Location = new Point(30, 330);
            status.Size = new Size(670, 70);
            status.BorderStyle = BorderStyle.FixedSingle;
            Controls.Add(status);
        }

        private void RunInstall()
        {
            string tt = mapping[targetType.SelectedIndex];
            string tv = targetValue.Text;
            if (tt == "this_pc") tv = Environment.MachineName;
            if (tt != "none" && tt != "this_pc" && string.IsNullOrWhiteSpace(tv))
            {
                MessageBox.Show("Informe o caminho, endereÃ§o ou identificaÃ§Ã£o do sistema escolhido.", "Sistema ImunolÃ³gico");
                return;
            }
            primary.Enabled = false;
            status.Text = "Instalando e validando...";
            status.Refresh();
            InstallResult r = InstallerEngine.Install(tt, tv, InstallerEngine.IsInstalled());
            string output = r.Message;
            int code = 3;
            if (r.Success) code = InstallerEngine.RunSelfTest(out output);
            status.Text = r.Message + " Self-test=" + (code == 0 ? "PASS" : "FAIL");
            MessageBox.Show(status.Text + "\r\n\r\n" + output, "Sistema ImunolÃ³gico");
            primary.Enabled = true;
            if (r.Success && code == 0) Close();
        }
    }

    internal static class Program
    {
        [STAThread]
        private static int Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            bool silent = Has(args, "/silent");
            bool uninstall = Has(args, "/uninstall");
            bool repair = Has(args, "/repair");
            bool purge = Has(args, "/purge");

            if (uninstall)
            {
                InstallResult u = InstallerEngine.Uninstall(purge);
                if (!silent) MessageBox.Show(u.Message, "Sistema ImunolÃ³gico");
                return u.Success ? 0 : 2;
            }
            if (silent || repair)
            {
                string target = Value(args, "/target=", repair ? "preserve" : "none");
                string targetValue = Value(args, "/targetvalue=", "");
                InstallResult r = InstallerEngine.Install(target, targetValue, repair);
                if (!r.Success) return 3;
                string output;
                return InstallerEngine.RunSelfTest(out output) == 0 ? 0 : 4;
            }
            Application.Run(new SetupForm());
            return 0;
        }

        private static bool Has(string[] args, string key)
        {
            foreach (string a in args) if (string.Equals(a, key, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        private static string Value(string[] args, string prefix, string fallback)
        {
            foreach (string a in args) if (a.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return a.Substring(prefix.Length);
            return fallback;
        }
    }
}
