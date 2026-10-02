using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Threading;
using System.Windows.Forms;

[assembly: System.Reflection.AssemblyTitle("ForensicKit Local Workbench")]
[assembly: System.Reflection.AssemblyProduct("ForensicKit")]
[assembly: System.Reflection.AssemblyCompany("ForensicKit")]
[assembly: System.Reflection.AssemblyVersion("1.2.3.0")]
[assembly: System.Reflection.AssemblyFileVersion("1.2.3.0")]

internal static class Program
{
    internal static void AppendDiagnostic(string eventCode)
    {
        string[] permitted = { "LAUNCHER_STARTED", "SERVER_READY", "SERVER_EXITED", "SERVER_STOP_REQUESTED", "CASE_UNAVAILABLE", "STARTUP_FAILED", "LOGIN_RESET" };
        if (!permitted.Contains(eventCode)) return;
        try
        {
            string localData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (String.IsNullOrEmpty(localData)) return;
            string directory = Path.Combine(localData, "ForensicKit");
            Directory.CreateDirectory(directory);
            string path = Path.Combine(directory, "launcher.log");
            var info = new FileInfo(path);
            if (info.Exists && info.Length >= 1024 * 1024) return;
            string line = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ", System.Globalization.CultureInfo.InvariantCulture) + " " + eventCode + Environment.NewLine;
            using (var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read))
            using (var writer = new StreamWriter(stream, new System.Text.UTF8Encoding(false))) writer.Write(line);
        }
        catch { /* Diagnostics must never prevent local analysis or reveal raw errors. */ }
    }

    [STAThread]
    private static void Main(string[] args)
    {
        bool created;
        using (var mutex = new Mutex(true, "Local\\ForensicKit.Desktop.v1", out created))
        {
            if (!created)
            {
                MessageBox.Show("ForensicKit is already running for this Windows session.", "ForensicKit", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            if (args.Length == 1 && String.Equals(args[0], "--reset-login", StringComparison.OrdinalIgnoreCase))
            {
                ResetLogin();
                return;
            }
            Application.Run(new LauncherForm(args));
        }
    }

    private static string RootDirectory { get { return AppDomain.CurrentDomain.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar); } }

    private static ProcessStartInfo RuntimeCommand(string arguments, string casePath)
    {
        string python = Path.Combine(RootDirectory, "runtime", "python.exe");
        string app = Path.Combine(RootDirectory, "app");
        if (!File.Exists(python) || !Directory.Exists(app)) throw new FileNotFoundException("The bundled ForensicKit runtime is incomplete.");
        var info = new ProcessStartInfo();
        info.FileName = python;
        info.Arguments = "-P -m forensickit " + arguments;
        info.WorkingDirectory = RootDirectory;
        info.UseShellExecute = false;
        info.CreateNoWindow = true;
        info.RedirectStandardOutput = true;
        info.RedirectStandardError = true;
        info.RedirectStandardInput = true;
        info.EnvironmentVariables["PYTHONHOME"] = Path.Combine(RootDirectory, "runtime");
        info.EnvironmentVariables["PYTHONPATH"] = app;
        info.EnvironmentVariables["PYTHONNOUSERSITE"] = "1";
        info.EnvironmentVariables["PYTHONUTF8"] = "1";
        info.EnvironmentVariables["PYTHONSAFEPATH"] = "1";
        if (casePath != null) info.Arguments += " --case-dir " + QuoteArgument(casePath);
        return info;
    }

    private static string QuoteArgument(string value)
    {
        if (value == null) return "\"\"";
        var output = new System.Text.StringBuilder("\"");
        int slashes = 0;
        foreach (char ch in value)
        {
            if (ch == '\\') { slashes++; continue; }
            if (ch == '"')
            {
                output.Append('\\', slashes * 2 + 1);
                output.Append('"');
                slashes = 0;
                continue;
            }
            output.Append('\\', slashes);
            slashes = 0;
            output.Append(ch);
        }
        output.Append('\\', slashes * 2);
        output.Append('"');
        return output.ToString();
    }

    private static string SelectCase(string[] args)
    {
        string path = Path.Combine(RootDirectory, "app", "examples", "sample-case");
        if (args.Length == 0) return path;
        if (args.Length == 1 && !args[0].StartsWith("--", StringComparison.Ordinal)) path = args[0];
        else if (args.Length == 2 && String.Equals(args[0], "--case-dir", StringComparison.OrdinalIgnoreCase)) path = args[1];
        else throw new ArgumentException("Use ForensicKit.exe [--case-dir <case-folder>].");
        string full = Path.GetFullPath(path);
        if (!Directory.Exists(full)) throw new DirectoryNotFoundException("The selected case directory is unavailable.");
        return full;
    }

    private static void ResetLogin()
    {
        var answer = MessageBox.Show(
            "This resets only the local ForensicKit sign-in record. It does not delete or change any case, analyst notes, or source evidence.\n\nFirst close any running ForensicKit window. Continue?",
            "Reset local sign-in", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
        if (answer != DialogResult.Yes) return;
        try
        {
            using (var process = Process.Start(RuntimeCommand("reset-login --confirm", null)))
            {
                process.WaitForExit(15000);
                if (!process.HasExited) { process.Kill(); throw new TimeoutException(); }
                if (process.ExitCode != 0) throw new InvalidOperationException();
            }
            AppendDiagnostic("LOGIN_RESET");
            MessageBox.Show("Local sign-in reset. Start ForensicKit again to create a new one-time setup code. Case data was not changed.", "ForensicKit", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch
        {
            MessageBox.Show("The local sign-in could not be reset. Close ForensicKit and check that the bundled application files are present.", "ForensicKit", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private sealed class LauncherForm : Form
    {
        private readonly Label status;
        private readonly Label setupNotice;
        private readonly TextBox setupCode;
        private readonly LinkLabel localUrl;
        private readonly Button openButton;
        private readonly Button copyButton;
        private Process serverProcess;
        private string url;
        private bool serverReady;

        internal LauncherForm(string[] args)
        {
            Text = "ForensicKit · Local Workbench";
            StartPosition = FormStartPosition.CenterScreen;
            MinimumSize = new Size(510, 395);
            ClientSize = new Size(600, 450);
            BackColor = Color.FromArgb(246, 247, 251);
            Font = new Font("Segoe UI", 9F, FontStyle.Regular, GraphicsUnit.Point);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;

            var header = new Panel { Dock = DockStyle.Top, Height = 98, BackColor = Color.White, Padding = new Padding(26, 18, 26, 16) };
            var mark = new Label { Text = "FK", Width = 48, Height = 48, TextAlign = ContentAlignment.MiddleCenter, BackColor = Color.FromArgb(104, 73, 216), ForeColor = Color.White, Font = new Font("Segoe UI", 12F, FontStyle.Bold), Location = new Point(26, 22) };
            var title = new Label { Text = "ForensicKit", AutoSize = true, ForeColor = Color.FromArgb(32, 36, 56), Font = new Font("Segoe UI", 16F, FontStyle.Bold), Location = new Point(90, 22) };
            var subtitle = new Label { Text = "Local investigation workbench", AutoSize = true, ForeColor = Color.FromArgb(111, 119, 139), Location = new Point(92, 54) };
            header.Controls.Add(mark); header.Controls.Add(title); header.Controls.Add(subtitle);

            status = new Label { Text = "Starting the local analysis engine…", AutoSize = false, Height = 36, Dock = DockStyle.Top, ForeColor = Color.FromArgb(71, 79, 98), Padding = new Padding(0, 12, 0, 0) };
            localUrl = new LinkLabel { Text = "", AutoSize = true, LinkColor = Color.FromArgb(88, 59, 192), Margin = new Padding(0, 8, 0, 14) };
            localUrl.LinkClicked += delegate { OpenWorkbench(); };
            setupNotice = new Label { Text = "First-run setup code — enter this in the local workbench", AutoSize = true, ForeColor = Color.FromArgb(76, 82, 101), Margin = new Padding(0, 18, 0, 6) };
            setupCode = new TextBox { ReadOnly = true, UseSystemPasswordChar = false, Font = new Font("Consolas", 12F, FontStyle.Bold), BackColor = Color.White, BorderStyle = BorderStyle.FixedSingle, Width = 390, Height = 34 };
            setupCode.AccessibleName = "One-time first-run setup code";
            setupNotice.Visible = false; setupCode.Visible = false;
            copyButton = new Button { Text = "Copy code", AutoSize = true, Enabled = false, FlatStyle = FlatStyle.Flat, BackColor = Color.White, ForeColor = Color.FromArgb(82, 69, 130), Margin = new Padding(8, 0, 0, 0) };
            copyButton.Click += delegate { if (!String.IsNullOrEmpty(setupCode.Text)) { Clipboard.SetText(setupCode.Text); status.Text = "Setup code copied. Keep it private; it works only once."; } };
            var codeRow = new FlowLayoutPanel { FlowDirection = FlowDirection.LeftToRight, AutoSize = true, WrapContents = false, Margin = new Padding(0, 0, 0, 0) };
            codeRow.Controls.Add(setupCode); codeRow.Controls.Add(copyButton);

            var localOnly = new Label { Text = "Offline by default · Server bound to this computer · Source evidence is read-only", AutoSize = true, ForeColor = Color.FromArgb(21, 121, 99), Margin = new Padding(0, 21, 0, 0) };
            var limitation = new Label { Text = "Local sign-in is an application access gate; it does not protect files from other processes or people with access to this Windows account.", AutoSize = false, Height = 42, MaximumSize = new Size(535, 0), ForeColor = Color.FromArgb(111, 119, 139), Margin = new Padding(0, 8, 0, 0) };

            openButton = new Button { Text = "Open workbench", AutoSize = true, Enabled = false, FlatStyle = FlatStyle.Flat, BackColor = Color.FromArgb(104, 73, 216), ForeColor = Color.White, Padding = new Padding(16, 6, 16, 6) };
            openButton.Click += delegate { OpenWorkbench(); };
            var exitButton = new Button { Text = "Exit", AutoSize = true, FlatStyle = FlatStyle.Flat, BackColor = Color.White, ForeColor = Color.FromArgb(73, 80, 98), Padding = new Padding(16, 6, 16, 6) };
            exitButton.Click += delegate { Close(); };
            var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, Dock = DockStyle.Bottom, Height = 54, Padding = new Padding(0, 8, 0, 0) };
            buttons.Controls.Add(exitButton); buttons.Controls.Add(openButton);

            var content = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, Padding = new Padding(28, 18, 28, 18), BackColor = BackColor };
            content.Controls.Add(status); content.Controls.Add(localUrl); content.Controls.Add(setupNotice); content.Controls.Add(codeRow); content.Controls.Add(localOnly); content.Controls.Add(limitation);
            Controls.Add(content); Controls.Add(buttons); Controls.Add(header);
            Shown += delegate { StartServer(args); };
            FormClosing += StopServer;
        }

        private void StartServer(string[] args)
        {
            try
            {
                string casePath = SelectCase(args);
                Program.AppendDiagnostic("LAUNCHER_STARTED");
                serverProcess = new Process { StartInfo = RuntimeCommand("desktop", casePath), EnableRaisingEvents = true };
                serverProcess.OutputDataReceived += HandleOutput;
                serverProcess.ErrorDataReceived += delegate { /* Raw errors are discarded; they may contain sensitive local paths. */ };
                serverProcess.Exited += delegate { Program.AppendDiagnostic("SERVER_EXITED"); SafeUi(delegate { if (!IsDisposed && !Disposing) { status.Text = serverReady ? "The local workbench has stopped." : "ForensicKit could not start. Check the non-sensitive launcher log."; openButton.Enabled = false; } }); };
                if (!serverProcess.Start()) throw new InvalidOperationException();
                serverProcess.BeginOutputReadLine();
                serverProcess.BeginErrorReadLine();
            }
            catch (Exception ex)
            {
                Program.AppendDiagnostic(ex is DirectoryNotFoundException ? "CASE_UNAVAILABLE" : "STARTUP_FAILED");
                status.Text = ex is DirectoryNotFoundException ? "The selected case folder is unavailable." : "ForensicKit could not start. Check the installation and case folder.";
                openButton.Enabled = false;
            }
        }

        private void HandleOutput(object sender, DataReceivedEventArgs args)
        {
            if (String.IsNullOrEmpty(args.Data)) return;
            if (args.Data.StartsWith("BOOTSTRAP_CODE=", StringComparison.Ordinal))
            {
                string code = args.Data.Substring("BOOTSTRAP_CODE=".Length);
                SafeUi(delegate { if (!IsDisposed && !Disposing) { setupCode.Text = code; setupCode.Visible = true; setupNotice.Visible = true; copyButton.Enabled = true; } });
                return;
            }
            if (args.Data.StartsWith("WORKBENCH_URL=", StringComparison.Ordinal))
            {
                string candidate = args.Data.Substring("WORKBENCH_URL=".Length);
                Uri parsed;
                if (!Uri.TryCreate(candidate, UriKind.Absolute, out parsed) || parsed.Scheme != "http" || parsed.Host != "127.0.0.1") return;
                Program.AppendDiagnostic("SERVER_READY");
                SafeUi(delegate { if (!IsDisposed && !Disposing) { serverReady = true; url = parsed.AbsoluteUri; localUrl.Text = url; status.Text = "ForensicKit is running locally."; openButton.Enabled = true; OpenWorkbench(); } });
                return;
            }
            if (args.Data == "ACCOUNT_SETUP_COMPLETE=1")
            {
                SafeUi(delegate { if (!IsDisposed && !Disposing) { setupCode.Clear(); setupCode.Visible = false; setupNotice.Visible = false; copyButton.Enabled = false; status.Text = "Local analyst account created. Sign in through the workbench."; } });
            }
        }

        private void SafeUi(MethodInvoker action)
        {
            if (IsDisposed || Disposing) return;
            try { if (InvokeRequired) BeginInvoke(action); else action(); }
            catch (InvalidOperationException) { }
        }

        private void OpenWorkbench()
        {
            if (String.IsNullOrEmpty(url)) return;
            try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); }
            catch { status.Text = "The workbench is ready. Copy the local address into your browser."; }
        }

        private void StopServer(object sender, FormClosingEventArgs args)
        {
            try
            {
                if (serverProcess == null || serverProcess.HasExited) return;
                Program.AppendDiagnostic("SERVER_STOP_REQUESTED");
                serverProcess.StandardInput.WriteLine("QUIT");
                if (!serverProcess.WaitForExit(5000)) serverProcess.Kill();
            }
            catch { /* Closing the parent process is the final fallback for local shutdown. */ }
            finally { if (serverProcess != null) serverProcess.Dispose(); }
        }
    }
}
