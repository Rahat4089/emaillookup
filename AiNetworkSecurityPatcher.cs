using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using System.Xml.Linq;

namespace APKPatcher
{
    public class CmdResult
    {
        public int ExitCode { get; set; }
        public string StdOut { get; set; }
        public string StdErr { get; set; }

        public string CombinedOutput
        {
            get
            {
                var sb = new StringBuilder();
                if (!string.IsNullOrWhiteSpace(StdOut)) sb.AppendLine(StdOut.Trim());
                if (!string.IsNullOrWhiteSpace(StdErr)) sb.AppendLine(StdErr.Trim());
                return sb.ToString().Trim();
            }
        }
    }

    public static class CmdRunner
    {
        public static CmdResult Run(string exe, string args, string workingDir, int timeoutMs)
        {
            var result = new CmdResult { ExitCode = -1, StdOut = string.Empty, StdErr = string.Empty };
            var stdout = new StringBuilder();
            var stderr = new StringBuilder();

            using (var process = new Process())
            {
                process.StartInfo = new ProcessStartInfo(exe, args)
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    WorkingDirectory = workingDir
                };

                process.OutputDataReceived += delegate (object sender, DataReceivedEventArgs e)
                {
                    if (e.Data != null) stdout.AppendLine(e.Data);
                };
                process.ErrorDataReceived += delegate (object sender, DataReceivedEventArgs e)
                {
                    if (e.Data != null) stderr.AppendLine(e.Data);
                };

                try
                {
                    if (!process.Start())
                    {
                        result.StdErr = "Process failed to start: " + exe;
                        return result;
                    }

                    process.BeginOutputReadLine();
                    process.BeginErrorReadLine();

                    bool finished = process.WaitForExit(timeoutMs);
                    if (!finished)
                    {
                        try { process.Kill(); } catch { }
                        result.StdErr = "Command timed out after " + timeoutMs + " ms";
                        return result;
                    }

                    result.ExitCode = process.ExitCode;
                    result.StdOut = stdout.ToString();
                    result.StdErr = stderr.ToString();
                    return result;
                }
                catch (Exception ex)
                {
                    result.StdErr = ex.Message;
                    return result;
                }
            }
        }
    }

    public static class AppPaths
    {
        public static readonly string AppRoot = AppDomain.CurrentDomain.BaseDirectory;
        public static readonly string ToolsDir = Path.Combine(AppRoot, "tools");
        public static readonly string TemplatePath = Path.Combine(AppRoot, "network_security_config.xml");
        public static readonly string OutputDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "APK_NETWORK_PATCHED");
    }

    public class Toolchain
    {
        public string JavaExe;
        public string ApktoolExe;
        public string ApktoolJar;
        public string ZipalignExe;
        public string ApksignerExe;
        public string ApksignerJar;
        public string KeytoolExe;
        public string JarsignerExe;
        public string UberApkSignerJar;

        public bool HasJava { get { return !string.IsNullOrWhiteSpace(JavaExe); } }
        public bool HasApktool { get { return !string.IsNullOrWhiteSpace(ApktoolExe) || !string.IsNullOrWhiteSpace(ApktoolJar); } }
        public bool HasZipalign { get { return !string.IsNullOrWhiteSpace(ZipalignExe); } }
        public bool HasApksigner { get { return !string.IsNullOrWhiteSpace(ApksignerExe) || !string.IsNullOrWhiteSpace(ApksignerJar); } }
        public bool HasJarsigner { get { return !string.IsNullOrWhiteSpace(JarsignerExe); } }
        public bool HasUberSigner { get { return !string.IsNullOrWhiteSpace(UberApkSignerJar); } }
        public bool HasKeytool { get { return !string.IsNullOrWhiteSpace(KeytoolExe); } }
        public bool CanPatch { get { return HasJava && HasApktool; } }
        public bool CanSign { get { return HasApksigner || HasJarsigner || HasUberSigner; } }
        public bool IsReady { get { return CanPatch && CanSign; } }

        public static Toolchain Detect()
        {
            Directory.CreateDirectory(AppPaths.ToolsDir);

            var tc = new Toolchain();
            tc.JavaExe = FindTool("java.exe", "java");
            tc.ApktoolExe = FindTool("apktool.exe", "apktool.bat", "apktool.cmd", "apktool");
            tc.ApktoolJar = FindFirstFile(AppPaths.ToolsDir, "apktool*.jar");
            tc.ZipalignExe = FindTool("zipalign.exe", "zipalign");
            tc.ApksignerExe = FindTool("apksigner.bat", "apksigner.cmd", "apksigner.exe", "apksigner");
            tc.ApksignerJar = FindFirstFile(AppPaths.ToolsDir, "apksigner*.jar");
            tc.KeytoolExe = FindTool("keytool.exe", "keytool");
            tc.JarsignerExe = FindTool("jarsigner.exe", "jarsigner");
            tc.UberApkSignerJar = FindFirstFile(AppPaths.ToolsDir, "uber-apk-signer*.jar");
            return tc;
        }

        public string BuildStatusLine()
        {
            var missing = new List<string>();
            if (!HasJava) missing.Add("java");
            if (!HasApktool) missing.Add("apktool");
            if (!CanSign) missing.Add("apksigner/jarsigner/uber-apk-signer");

            if (missing.Count == 0)
            {
                var zipalignStatus = HasZipalign ? "zipalign: yes" : "zipalign: optional-missing";
                return "READY - core tools detected (" + zipalignStatus + ")";
            }

            return "Missing required tools: " + string.Join(", ", missing);
        }

        public CmdResult RunApktool(string args, string workingDir)
        {
            if (!string.IsNullOrWhiteSpace(ApktoolJar))
            {
                string jarArgs = "-Xmx1024M -Duser.language=en -Dfile.encoding=UTF8 -jar \"" + ApktoolJar + "\" " + args;
                return CmdRunner.Run(JavaExe, jarArgs, workingDir, 15 * 60 * 1000);
            }

            return CmdRunner.Run(ApktoolExe, args, workingDir, 15 * 60 * 1000);
        }

        public CmdResult RunApksigner(string args, string workingDir)
        {
            if (!string.IsNullOrWhiteSpace(ApksignerJar))
            {
                return CmdRunner.Run(JavaExe, "-jar \"" + ApksignerJar + "\" " + args, workingDir, 5 * 60 * 1000);
            }

            return CmdRunner.Run(ApksignerExe, args, workingDir, 5 * 60 * 1000);
        }

        private static string FindTool(params string[] names)
        {
            foreach (var n in names)
            {
                string localPath = Path.Combine(AppPaths.ToolsDir, n);
                if (File.Exists(localPath)) return localPath;
            }

            foreach (var n in names)
            {
                string fromPath = FindFromPath(n);
                if (!string.IsNullOrWhiteSpace(fromPath)) return fromPath;
            }

            return null;
        }

        private static string FindFromPath(string name)
        {
            try
            {
                var result = CmdRunner.Run("where", name, Environment.CurrentDirectory, 10 * 1000);
                if (result.ExitCode != 0) return null;
                return result.StdOut
                    .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                    .FirstOrDefault();
            }
            catch
            {
                return null;
            }
        }

        private static string FindFirstFile(string dir, string pattern)
        {
            try
            {
                if (!Directory.Exists(dir)) return null;
                return Directory.GetFiles(dir, pattern, SearchOption.TopDirectoryOnly).FirstOrDefault();
            }
            catch
            {
                return null;
            }
        }
    }

    public static class SecurityConfigTemplate
    {
        private const string DefaultTemplate =
@"<?xml version=""1.0"" encoding=""utf-8""?>
<network-security-config>
    <base-config cleartextTrafficPermitted=""true"">
        <trust-anchors>
            <certificates src=""system"" />
            <certificates src=""user"" />
        </trust-anchors>
    </base-config>
</network-security-config>";

        public static string Load()
        {
            try
            {
                if (File.Exists(AppPaths.TemplatePath))
                {
                    string content = File.ReadAllText(AppPaths.TemplatePath).Trim();
                    if (content.IndexOf("<network-security-config", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        return content;
                    }
                }
            }
            catch
            {
                // Fall back to hardcoded template.
            }

            return DefaultTemplate;
        }
    }

    public static class ManifestPatcher
    {
        public static bool EnsureNetworkSecurityConfig(string manifestPath, Action<string, Color> log)
        {
            if (!File.Exists(manifestPath))
            {
                log("ERROR: AndroidManifest.xml not found", Color.Red);
                return false;
            }

            try
            {
                return PatchWithXmlModel(manifestPath, log);
            }
            catch (Exception ex)
            {
                log("Manifest XML parse warning: " + ex.Message, Color.Yellow);
                log("Trying fallback manual patch...", Color.Yellow);
                return PatchManually(manifestPath, log);
            }
        }

        private static bool PatchWithXmlModel(string manifestPath, Action<string, Color> log)
        {
            var doc = XDocument.Load(manifestPath, LoadOptions.PreserveWhitespace);
            var manifest = doc.Root;
            if (manifest == null || !string.Equals(manifest.Name.LocalName, "manifest", StringComparison.OrdinalIgnoreCase))
            {
                log("ERROR: Invalid AndroidManifest.xml structure", Color.Red);
                return false;
            }

            XNamespace androidNs = "http://schemas.android.com/apk/res/android";
            bool changed = false;

            if (manifest.Attribute(XNamespace.Xmlns + "android") == null)
            {
                manifest.SetAttributeValue(XNamespace.Xmlns + "android", androidNs.NamespaceName);
                changed = true;
            }

            var application = manifest.Elements().FirstOrDefault(e => string.Equals(e.Name.LocalName, "application", StringComparison.OrdinalIgnoreCase));
            if (application == null)
            {
                application = new XElement("application");
                manifest.Add(application);
                changed = true;
                log("Manifest had no <application>; created one.", Color.Yellow);
            }

            changed |= UpsertAttribute(application, androidNs + "networkSecurityConfig", "@xml/network_security_config");
            changed |= UpsertAttribute(application, androidNs + "usesCleartextTraffic", "true");

            if (changed)
            {
                doc.Save(manifestPath);
                log("Manifest updated with network security config.", Color.FromArgb(0, 210, 120));
            }
            else
            {
                log("Manifest already had required network security settings.", Color.FromArgb(0, 210, 120));
            }

            return true;
        }

        private static bool PatchManually(string manifestPath, Action<string, Color> log)
        {
            string content = File.ReadAllText(manifestPath);
            string updated = content;

            if (!Regex.IsMatch(updated, "<manifest\\b[^>]*xmlns:android\\s*=", RegexOptions.IgnoreCase))
            {
                updated = Regex.Replace(
                    updated,
                    "<manifest\\b",
                    "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\"",
                    RegexOptions.IgnoreCase);
            }

            var appTag = Regex.Match(updated, "<application\\b[^>]*>", RegexOptions.IgnoreCase);
            if (appTag.Success)
            {
                string newTag = appTag.Value;
                newTag = UpsertAttribute(newTag, "android:networkSecurityConfig", "@xml/network_security_config");
                newTag = UpsertAttribute(newTag, "android:usesCleartextTraffic", "true");

                updated = updated.Substring(0, appTag.Index) + newTag + updated.Substring(appTag.Index + appTag.Length);
                File.WriteAllText(manifestPath, updated, new UTF8Encoding(false));
                log("Manifest updated with manual fallback patch.", Color.FromArgb(0, 210, 120));
                return true;
            }

            var endManifest = Regex.Match(updated, "</manifest>", RegexOptions.IgnoreCase);
            if (!endManifest.Success)
            {
                log("ERROR: Could not locate </manifest> tag for fallback patch", Color.Red);
                return false;
            }

            string appBlock = Environment.NewLine +
                              "    <application android:networkSecurityConfig=\"@xml/network_security_config\" android:usesCleartextTraffic=\"true\" />" +
                              Environment.NewLine;

            updated = updated.Insert(endManifest.Index, appBlock);
            File.WriteAllText(manifestPath, updated, new UTF8Encoding(false));
            log("Manifest had no <application>; inserted fallback block.", Color.Yellow);
            return true;
        }

        private static bool UpsertAttribute(XElement element, XName attrName, string value)
        {
            var attr = element.Attribute(attrName);
            if (attr == null)
            {
                element.SetAttributeValue(attrName, value);
                return true;
            }

            if (attr.Value != value)
            {
                attr.Value = value;
                return true;
            }

            return false;
        }

        private static string UpsertAttribute(string tag, string attrName, string attrValue)
        {
            string pattern = Regex.Escape(attrName) + "\\s*=\\s*\"[^\"]*\"";
            if (Regex.IsMatch(tag, pattern, RegexOptions.IgnoreCase))
            {
                return Regex.Replace(tag, pattern, attrName + "=\"" + attrValue + "\"", RegexOptions.IgnoreCase);
            }

            int closeSlash = tag.LastIndexOf("/>", StringComparison.Ordinal);
            if (closeSlash >= 0)
            {
                return tag.Insert(closeSlash, " " + attrName + "=\"" + attrValue + "\"");
            }

            int closeTag = tag.LastIndexOf(">", StringComparison.Ordinal);
            if (closeTag >= 0)
            {
                return tag.Insert(closeTag, " " + attrName + "=\"" + attrValue + "\"");
            }

            return tag;
        }
    }

    public class DarkProgressBar : Control
    {
        private int _value;
        private int _maximum = 100;
        private string _status = "Waiting...";

        public int Value
        {
            get { return _value; }
            set { _value = Math.Max(0, Math.Min(value, _maximum)); Invalidate(); }
        }

        public int Maximum
        {
            get { return _maximum; }
            set { _maximum = Math.Max(1, value); Invalidate(); }
        }

        public string StatusText
        {
            get { return _status; }
            set { _status = value ?? string.Empty; Invalidate(); }
        }

        public DarkProgressBar()
        {
            DoubleBuffered = true;
            Height = 30;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;

            using (var bg = new SolidBrush(Color.FromArgb(32, 32, 40)))
            {
                g.FillRoundedRect(bg, ClientRectangle, 8);
            }

            if (_maximum > 0 && _value > 0)
            {
                int w = (int)((Width - 4) * ((float)_value / _maximum));
                var fillRect = new Rectangle(2, 2, Math.Max(2, w), Height - 4);
                using (var fill = new LinearGradientBrush(fillRect, Color.FromArgb(30, 180, 255), Color.FromArgb(0, 120, 230), 0f))
                {
                    g.FillRoundedRect(fill, fillRect, 7);
                }
            }

            string text = string.IsNullOrWhiteSpace(_status) ? _value + "%" : _status;
            using (var font = new Font("Segoe UI", 9f, FontStyle.Bold))
            using (var brush = new SolidBrush(Color.White))
            {
                var sf = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };
                g.DrawString(text, font, brush, ClientRectangle, sf);
            }
        }
    }

    public static class GraphicsExt
    {
        public static void FillRoundedRect(this Graphics g, Brush brush, Rectangle rect, int radius)
        {
            using (var path = new GraphicsPath())
            {
                path.AddArc(rect.X, rect.Y, radius * 2, radius * 2, 180, 90);
                path.AddArc(rect.Right - radius * 2, rect.Y, radius * 2, radius * 2, 270, 90);
                path.AddArc(rect.Right - radius * 2, rect.Bottom - radius * 2, radius * 2, radius * 2, 0, 90);
                path.AddArc(rect.X, rect.Bottom - radius * 2, radius * 2, radius * 2, 90, 90);
                path.CloseFigure();
                g.FillPath(brush, path);
            }
        }
    }

    public class MainForm : Form
    {
        private static readonly Color Bg = Color.FromArgb(16, 18, 24);
        private static readonly Color PanelBg = Color.FromArgb(27, 30, 38);
        private static readonly Color Accent = Color.FromArgb(0, 162, 255);
        private static readonly Color Green = Color.FromArgb(0, 210, 120);
        private static readonly Color Red = Color.FromArgb(255, 87, 87);
        private static readonly Color Dim = Color.FromArgb(150, 160, 178);
        private static readonly Color ForeText = Color.FromArgb(226, 231, 240);

        private Panel dropZone;
        private Label dropLabel;
        private ListBox fileList;
        private RichTextBox logBox;
        private DarkProgressBar progress;
        private Label lblToolStatus;
        private Label lblStats;
        private CheckBox chkBackup;
        private CheckBox chkVerify;
        private CheckBox chkAutoOpen;
        private Button btnPatch;

        private Toolchain tools;
        private bool running;
        private string outputDir;
        private string keystorePath;
        private int okCount;
        private int failCount;
        private readonly Stopwatch sw = new Stopwatch();

        private static readonly string[] ValidExt = { ".apk", ".xapk", ".apkm", ".apks" };

        public MainForm()
        {
            outputDir = AppPaths.OutputDir;
            keystorePath = Path.Combine(outputDir, "debug.keystore");

            InitializeUi();
            RefreshToolStatus();
        }

        private void InitializeUi()
        {
            Text = "AI Network Security APK Patcher";
            Size = new Size(980, 760);
            MinimumSize = new Size(900, 650);
            StartPosition = FormStartPosition.CenterScreen;
            BackColor = Bg;
            ForeColor = ForeText;
            Font = new Font("Segoe UI", 9.5f);
            Icon = SystemIcons.Shield;
            AllowDrop = true;

            var title = new Label
            {
                Text = "AI Network Security APK Patcher",
                Font = new Font("Segoe UI", 17f, FontStyle.Bold),
                ForeColor = Accent,
                Location = new Point(20, 12),
                AutoSize = true
            };
            Controls.Add(title);

            var subtitle = new Label
            {
                Text = "Drop APK -> auto create XML -> auto patch AndroidManifest -> rebuild + sign",
                Font = new Font("Segoe UI", 9f),
                ForeColor = Dim,
                Location = new Point(22, 47),
                AutoSize = true
            };
            Controls.Add(subtitle);

            lblToolStatus = new Label
            {
                Location = new Point(22, 70),
                Size = new Size(920, 20),
                ForeColor = Dim,
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };
            Controls.Add(lblToolStatus);

            dropZone = new Panel
            {
                Location = new Point(20, 98),
                Size = new Size(450, 150),
                BackColor = PanelBg,
                AllowDrop = true,
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };
            dropZone.Paint += DropZone_Paint;
            dropZone.DragEnter += Any_DragEnter;
            dropZone.DragDrop += Any_DragDrop;
            dropZone.DragLeave += delegate { dropZone.BackColor = PanelBg; dropZone.Invalidate(); };
            Controls.Add(dropZone);

            dropLabel = new Label
            {
                Dock = DockStyle.Fill,
                Text = "Drop files here (.apk .xapk .apkm .apks)",
                TextAlign = ContentAlignment.MiddleCenter,
                Font = new Font("Segoe UI", 12f, FontStyle.Bold),
                ForeColor = Dim,
                BackColor = Color.Transparent
            };
            dropZone.Controls.Add(dropLabel);

            fileList = new ListBox
            {
                Location = new Point(480, 98),
                Size = new Size(480, 150),
                BackColor = PanelBg,
                ForeColor = ForeText,
                BorderStyle = BorderStyle.None,
                Font = new Font("Consolas", 9f),
                Anchor = AnchorStyles.Top | AnchorStyles.Right
            };
            Controls.Add(fileList);

            var btnBrowse = MakeButton("Browse", 480, 256, 120);
            btnBrowse.Click += BtnBrowse_Click;
            Controls.Add(btnBrowse);

            var btnRemove = MakeButton("Remove", 610, 256, 120);
            btnRemove.Click += delegate
            {
                if (fileList.SelectedIndex >= 0) fileList.Items.RemoveAt(fileList.SelectedIndex);
            };
            Controls.Add(btnRemove);

            var btnClearFiles = MakeButton("Clear Files", 740, 256, 120);
            btnClearFiles.Click += delegate { fileList.Items.Clear(); };
            Controls.Add(btnClearFiles);

            var btnOpenOutput = MakeButton("Open Output", 870, 256, 90);
            btnOpenOutput.Click += delegate
            {
                Directory.CreateDirectory(outputDir);
                Process.Start("explorer.exe", outputDir);
            };
            Controls.Add(btnOpenOutput);

            chkBackup = new CheckBox
            {
                Text = "Backup original APK",
                Location = new Point(22, 264),
                ForeColor = ForeText,
                AutoSize = true
            };
            Controls.Add(chkBackup);

            chkVerify = new CheckBox
            {
                Text = "Verify signature",
                Location = new Point(190, 264),
                ForeColor = ForeText,
                AutoSize = true,
                Checked = true
            };
            Controls.Add(chkVerify);

            chkAutoOpen = new CheckBox
            {
                Text = "Open output when finished",
                Location = new Point(330, 264),
                ForeColor = ForeText,
                AutoSize = true,
                Checked = true
            };
            Controls.Add(chkAutoOpen);

            progress = new DarkProgressBar
            {
                Location = new Point(20, 292),
                Size = new Size(940, 30),
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };
            Controls.Add(progress);

            btnPatch = new Button
            {
                Text = "PATCH NETWORK SECURITY (AI MODE)",
                Font = new Font("Segoe UI", 11.5f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                BackColor = Accent,
                ForeColor = Color.White,
                Location = new Point(20, 330),
                Size = new Size(940, 46),
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right,
                Cursor = Cursors.Hand
            };
            btnPatch.FlatAppearance.BorderSize = 0;
            btnPatch.Click += BtnPatch_Click;
            Controls.Add(btnPatch);

            logBox = new RichTextBox
            {
                Location = new Point(20, 384),
                Size = new Size(940, 300),
                BackColor = Color.FromArgb(12, 14, 20),
                ForeColor = ForeText,
                Font = new Font("Consolas", 9f),
                ReadOnly = true,
                BorderStyle = BorderStyle.None,
                ScrollBars = RichTextBoxScrollBars.Vertical,
                Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right
            };
            Controls.Add(logBox);

            var btnClearLog = MakeButton("Clear Log", 20, 692, 110);
            btnClearLog.Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
            btnClearLog.Click += delegate { logBox.Clear(); };
            Controls.Add(btnClearLog);

            lblStats = new Label
            {
                Location = new Point(520, 697),
                Size = new Size(440, 20),
                ForeColor = Dim,
                TextAlign = ContentAlignment.MiddleRight,
                Anchor = AnchorStyles.Bottom | AnchorStyles.Right
            };
            Controls.Add(lblStats);

            DragEnter += Any_DragEnter;
            DragDrop += Any_DragDrop;
        }

        private Button MakeButton(string text, int x, int y, int w)
        {
            var btn = new Button
            {
                Text = text,
                FlatStyle = FlatStyle.Flat,
                BackColor = PanelBg,
                ForeColor = ForeText,
                Size = new Size(w, 30),
                Location = new Point(x, y),
                Cursor = Cursors.Hand
            };
            btn.FlatAppearance.BorderColor = Color.FromArgb(62, 67, 82);
            return btn;
        }

        private void DropZone_Paint(object sender, PaintEventArgs e)
        {
            var rect = new Rectangle(2, 2, dropZone.Width - 5, dropZone.Height - 5);
            using (var pen = new Pen(Color.FromArgb(65, 70, 90), 2f) { DashStyle = DashStyle.Dash })
            {
                e.Graphics.DrawRectangle(pen, rect);
            }
        }

        private void Any_DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                e.Effect = DragDropEffects.Copy;
                dropZone.BackColor = Color.FromArgb(38, 44, 57);
                dropZone.Invalidate();
            }
        }

        private void Any_DragDrop(object sender, DragEventArgs e)
        {
            dropZone.BackColor = PanelBg;
            dropZone.Invalidate();
            if (!e.Data.GetDataPresent(DataFormats.FileDrop)) return;

            var files = e.Data.GetData(DataFormats.FileDrop) as string[];
            if (files != null) AddFiles(files);
        }

        private void BtnBrowse_Click(object sender, EventArgs e)
        {
            using (var dlg = new OpenFileDialog())
            {
                dlg.Filter = "Android packages|*.apk;*.xapk;*.apkm;*.apks|All files|*.*";
                dlg.Multiselect = true;
                if (dlg.ShowDialog() == DialogResult.OK) AddFiles(dlg.FileNames);
            }
        }

        private void AddFiles(IEnumerable<string> files)
        {
            foreach (var file in files)
            {
                try
                {
                    string ext = Path.GetExtension(file).ToLowerInvariant();
                    if (!ValidExt.Contains(ext)) continue;
                    if (fileList.Items.Contains(file)) continue;
                    fileList.Items.Add(file);
                }
                catch
                {
                    // Ignore malformed file path entries.
                }
            }
        }

        private void RefreshToolStatus()
        {
            tools = Toolchain.Detect();
            string status = tools.BuildStatusLine();
            lblToolStatus.Text = status;
            lblToolStatus.ForeColor = tools.IsReady ? Green : Red;
        }

        private void BtnPatch_Click(object sender, EventArgs e)
        {
            if (running) return;
            RefreshToolStatus();

            if (!tools.IsReady)
            {
                AppendLog("ERROR: " + tools.BuildStatusLine(), Red);
                AppendLog("Install required tools or place them in ./tools (see README).", Color.Yellow);
                return;
            }

            if (fileList.Items.Count == 0)
            {
                AppendLog("No files selected. Add at least one APK.", Color.Yellow);
                return;
            }

            running = true;
            btnPatch.Enabled = false;
            btnPatch.BackColor = Color.FromArgb(65, 72, 90);
            btnPatch.Text = "PATCHING...";
            okCount = 0;
            failCount = 0;
            sw.Restart();

            var queue = new List<string>();
            foreach (var item in fileList.Items) queue.Add(item.ToString());

            var worker = new BackgroundWorker();
            worker.DoWork += delegate (object sender2, DoWorkEventArgs e2) { ProcessQueue(queue); };
            worker.RunWorkerCompleted += delegate (object sender2, RunWorkerCompletedEventArgs e2)
            {
                sw.Stop();
                running = false;
                btnPatch.Enabled = true;
                btnPatch.BackColor = Accent;
                btnPatch.Text = "PATCH NETWORK SECURITY (AI MODE)";
                progress.Value = progress.Maximum;
                progress.StatusText = "Completed";
                lblStats.Text = string.Format("Patched: {0}  Failed: {1}  Time: {2:F1}s", okCount, failCount, sw.Elapsed.TotalSeconds);

                if (okCount > 0 && chkAutoOpen.Checked)
                {
                    try { Process.Start("explorer.exe", outputDir); } catch { }
                }
            };
            worker.RunWorkerAsync();
        }

        private void ProcessQueue(List<string> queue)
        {
            Directory.CreateDirectory(outputDir);
            string securityXml = SecurityConfigTemplate.Load();

            for (int i = 0; i < queue.Count; i++)
            {
                string input = queue[i];
                int basePct = (int)((float)i / Math.Max(1, queue.Count) * 100);

                AppendLog(string.Empty, ForeText);
                AppendLog("================================================", Accent);
                AppendLog(string.Format("({0}/{1}) {2}", i + 1, queue.Count, Path.GetFileName(input)), Accent);
                AppendLog("================================================", Accent);

                string workDir = Path.Combine(Path.GetTempPath(), "apk_ai_patch_" + Guid.NewGuid().ToString("N").Substring(0, 10));

                try
                {
                    if (!File.Exists(input))
                    {
                        AppendLog("ERROR: Input file not found: " + input, Red);
                        failCount++;
                        continue;
                    }

                    Directory.CreateDirectory(workDir);

                    if (chkBackup.Checked)
                    {
                        string backupDir = Path.Combine(outputDir, "backup");
                        Directory.CreateDirectory(backupDir);
                        File.Copy(input, Path.Combine(backupDir, Path.GetFileName(input)), true);
                        AppendLog("Backup created.", Dim);
                    }

                    SetProgress(basePct + 6, "Extracting");
                    string baseApk = ExtractBaseApk(input, workDir);
                    if (baseApk == null)
                    {
                        failCount++;
                        continue;
                    }

                    SetProgress(basePct + 18, "Decompiling");
                    string decompiled = Path.Combine(workDir, "decompiled");
                    var decompile = tools.RunApktool("d -s \"" + baseApk + "\" -o \"" + decompiled + "\" -f", workDir);
                    if (decompile.ExitCode != 0 || !Directory.Exists(decompiled))
                    {
                        AppendLog("ERROR: apktool decompile failed.", Red);
                        AppendLog(decompile.CombinedOutput, Dim);
                        failCount++;
                        continue;
                    }
                    AppendLog("Decompile OK.", Green);

                    SetProgress(basePct + 36, "Injecting XML");
                    if (!InjectSecurityConfig(decompiled, securityXml))
                    {
                        failCount++;
                        continue;
                    }

                    SetProgress(basePct + 52, "Patching manifest");
                    string manifestPath = Path.Combine(decompiled, "AndroidManifest.xml");
                    if (!ManifestPatcher.EnsureNetworkSecurityConfig(manifestPath, AppendLog))
                    {
                        failCount++;
                        continue;
                    }

                    SetProgress(basePct + 68, "Rebuilding");
                    string rebuiltApk = Path.Combine(workDir, "rebuilt.apk");
                    var build = tools.RunApktool("b \"" + decompiled + "\" -o \"" + rebuiltApk + "\" --use-aapt2", workDir);
                    if (!File.Exists(rebuiltApk))
                    {
                        AppendLog("Rebuild with aapt2 failed. Retrying with default build mode...", Color.Yellow);
                        build = tools.RunApktool("b \"" + decompiled + "\" -o \"" + rebuiltApk + "\"", workDir);
                    }
                    if (build.ExitCode != 0 || !File.Exists(rebuiltApk))
                    {
                        AppendLog("ERROR: apktool rebuild failed.", Red);
                        AppendLog(build.CombinedOutput, Dim);
                        failCount++;
                        continue;
                    }
                    AppendLog("Rebuild OK.", Green);

                    SetProgress(basePct + 79, "Aligning");
                    string aligned = AlignApkIfPossible(rebuiltApk, workDir);
                    if (aligned == null)
                    {
                        failCount++;
                        continue;
                    }

                    SetProgress(basePct + 90, "Signing");
                    string finalOutput = Path.Combine(outputDir, Path.GetFileNameWithoutExtension(input) + "_network_patched.apk");
                    if (!SignApk(aligned, finalOutput, workDir))
                    {
                        failCount++;
                        continue;
                    }

                    if (chkVerify.Checked)
                    {
                        VerifySignature(finalOutput, workDir);
                    }

                    AppendLog("OUTPUT: " + finalOutput, Color.FromArgb(110, 255, 150));
                    okCount++;
                }
                catch (Exception ex)
                {
                    AppendLog("ERROR: " + ex.Message, Red);
                    failCount++;
                }
                finally
                {
                    try { if (Directory.Exists(workDir)) Directory.Delete(workDir, true); } catch { }
                    SetProgress((int)((float)(i + 1) / Math.Max(1, queue.Count) * 100), "Processing");
                }
            }
        }

        private bool InjectSecurityConfig(string decompiledDir, string xmlTemplate)
        {
            try
            {
                string xmlDir = Path.Combine(decompiledDir, "res", "xml");
                Directory.CreateDirectory(xmlDir);
                string target = Path.Combine(xmlDir, "network_security_config.xml");
                File.WriteAllText(target, xmlTemplate + Environment.NewLine, new UTF8Encoding(false));
                AppendLog("network_security_config.xml written (hardcoded template).", Green);
                return true;
            }
            catch (Exception ex)
            {
                AppendLog("ERROR: Failed to write network_security_config.xml: " + ex.Message, Red);
                return false;
            }
        }

        private string ExtractBaseApk(string inputFile, string workDir)
        {
            string ext = Path.GetExtension(inputFile).ToLowerInvariant();
            if (ext == ".apk") return inputFile;

            try
            {
                string bundleDir = Path.Combine(workDir, "bundle_extract");
                ZipFile.ExtractToDirectory(inputFile, bundleDir);
                var apks = Directory.GetFiles(bundleDir, "*.apk", SearchOption.AllDirectories);
                string baseApk = apks.FirstOrDefault(a => string.Equals(Path.GetFileName(a), "base.apk", StringComparison.OrdinalIgnoreCase));
                if (baseApk == null) baseApk = apks.FirstOrDefault();

                if (baseApk == null)
                {
                    AppendLog("ERROR: No APK found in bundle: " + Path.GetFileName(inputFile), Red);
                    return null;
                }

                AppendLog("Bundle extracted, using: " + Path.GetFileName(baseApk), Green);
                return baseApk;
            }
            catch (Exception ex)
            {
                AppendLog("ERROR: Failed to extract bundle: " + ex.Message, Red);
                return null;
            }
        }

        private string AlignApkIfPossible(string rebuiltApk, string workDir)
        {
            if (tools.HasZipalign)
            {
                string aligned = Path.Combine(workDir, "aligned.apk");
                var align = CmdRunner.Run(tools.ZipalignExe, "-f 4 \"" + rebuiltApk + "\" \"" + aligned + "\"", workDir, 2 * 60 * 1000);
                if (align.ExitCode != 0 || !File.Exists(aligned))
                {
                    AppendLog("ERROR: zipalign failed.", Red);
                    AppendLog(align.CombinedOutput, Dim);
                    return null;
                }

                AppendLog("Zipalign OK.", Green);
                return aligned;
            }

            AppendLog("zipalign not found, continuing without alignment.", Color.Yellow);
            return rebuiltApk;
        }

        private bool SignApk(string inputApk, string finalOutput, string workDir)
        {
            if (!EnsureKeystore(workDir))
            {
                return false;
            }

            try
            {
                File.Copy(inputApk, finalOutput, true);
            }
            catch (Exception ex)
            {
                AppendLog("ERROR: Cannot prepare output file for signing: " + ex.Message, Red);
                return false;
            }

            if (tools.HasApksigner)
            {
                string args = string.Format(
                    "sign --ks \"{0}\" --ks-pass pass:android --ks-key-alias androiddebugkey --key-pass pass:android \"{1}\"",
                    keystorePath,
                    finalOutput);
                var sign = tools.RunApksigner(args, workDir);
                if (sign.ExitCode == 0)
                {
                    AppendLog("Signed with apksigner.", Green);
                    return true;
                }

                AppendLog("apksigner failed, trying fallback signer if available...", Color.Yellow);
                AppendLog(sign.CombinedOutput, Dim);
            }

            if (tools.HasUberSigner)
            {
                string signDir = Path.Combine(workDir, "uber_sign");
                Directory.CreateDirectory(signDir);
                string localCopy = Path.Combine(signDir, Path.GetFileName(inputApk));
                File.Copy(inputApk, localCopy, true);

                string args = "-jar \"" + tools.UberApkSignerJar + "\" --apks \"" + signDir +
                              "\" --ks \"" + keystorePath +
                              "\" --ksAlias androiddebugkey --ksPass android --ksKeyPass android --overwrite";
                var sign = CmdRunner.Run(tools.JavaExe, args, workDir, 5 * 60 * 1000);
                if (sign.ExitCode != 0)
                {
                    AppendLog("ERROR: uber-apk-signer failed.", Red);
                    AppendLog(sign.CombinedOutput, Dim);
                    return false;
                }

                var signed = Directory.GetFiles(signDir, "*signed*.apk", SearchOption.TopDirectoryOnly).FirstOrDefault();
                if (signed == null)
                {
                    AppendLog("ERROR: uber-apk-signer finished but signed APK was not found.", Red);
                    return false;
                }

                File.Copy(signed, finalOutput, true);
                AppendLog("Signed with uber-apk-signer.", Green);
                return true;
            }

            if (tools.HasJarsigner)
            {
                string args = string.Format(
                    "-keystore \"{0}\" -storepass android -keypass android \"{1}\" androiddebugkey",
                    keystorePath,
                    finalOutput);
                var sign = CmdRunner.Run(tools.JarsignerExe, args, workDir, 3 * 60 * 1000);
                if (sign.ExitCode == 0)
                {
                    AppendLog("Signed with jarsigner.", Green);
                    return true;
                }

                AppendLog("ERROR: jarsigner failed.", Red);
                AppendLog(sign.CombinedOutput, Dim);
                return false;
            }

            AppendLog("ERROR: No signer available.", Red);
            return false;
        }

        private bool EnsureKeystore(string workDir)
        {
            try
            {
                if (File.Exists(keystorePath)) return true;
                Directory.CreateDirectory(outputDir);

                string bundled = Path.Combine(AppPaths.ToolsDir, "debug.keystore");
                if (File.Exists(bundled))
                {
                    File.Copy(bundled, keystorePath, true);
                    AppendLog("Using bundled debug.keystore from tools folder.", Dim);
                    return true;
                }

                if (!tools.HasKeytool)
                {
                    AppendLog("ERROR: keytool not found and debug.keystore is missing.", Red);
                    AppendLog("Provide tools/debug.keystore or install JDK keytool.", Color.Yellow);
                    return false;
                }

                var generate = CmdRunner.Run(
                    tools.KeytoolExe,
                    "-genkey -v -keystore \"" + keystorePath + "\" -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 " +
                    "-storepass android -keypass android -dname \"CN=Debug,OU=Debug,O=Debug,L=Debug,ST=Debug,C=US\"",
                    workDir,
                    2 * 60 * 1000);

                if (generate.ExitCode != 0 || !File.Exists(keystorePath))
                {
                    AppendLog("ERROR: failed to generate debug.keystore.", Red);
                    AppendLog(generate.CombinedOutput, Dim);
                    return false;
                }

                AppendLog("Generated debug.keystore.", Green);
                return true;
            }
            catch (Exception ex)
            {
                AppendLog("ERROR: keystore setup failed: " + ex.Message, Red);
                return false;
            }
        }

        private void VerifySignature(string apkPath, string workDir)
        {
            try
            {
                if (tools.HasApksigner)
                {
                    var verify = tools.RunApksigner("verify \"" + apkPath + "\"", workDir);
                    if (verify.ExitCode == 0) AppendLog("Signature verification OK.", Green);
                    else AppendLog("Signature verification warning: " + verify.CombinedOutput, Color.Yellow);
                    return;
                }

                AppendLog("Verification skipped (apksigner not available).", Dim);
            }
            catch (Exception ex)
            {
                AppendLog("Verification warning: " + ex.Message, Color.Yellow);
            }
        }

        private void SetProgress(int pct, string status)
        {
            if (InvokeRequired)
            {
                Invoke(new Action<int, string>(SetProgress), pct, status);
                return;
            }

            progress.Value = pct;
            progress.StatusText = status + " (" + Math.Max(0, Math.Min(100, pct)) + "%)";
        }

        private void AppendLog(string message, Color color)
        {
            if (InvokeRequired)
            {
                Invoke(new Action<string, Color>(AppendLog), message, color);
                return;
            }

            logBox.SelectionStart = logBox.TextLength;
            logBox.SelectionColor = color;
            logBox.AppendText(message + Environment.NewLine);
            logBox.ScrollToCaret();
        }

        public void LoadArgs(string[] args)
        {
            if (args == null || args.Length == 0) return;
            AddFiles(args.Where(File.Exists));
        }
    }

    public static class Program
    {
        [DllImport("kernel32.dll")] private static extern bool AllocConsole();
        [DllImport("kernel32.dll")] private static extern IntPtr GetConsoleWindow();
        [DllImport("user32.dll")] private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [STAThread]
        public static void Main(string[] args)
        {
            try
            {
                AllocConsole();
                IntPtr console = GetConsoleWindow();
                if (console != IntPtr.Zero) ShowWindow(console, 0);
            }
            catch
            {
                // Non-fatal.
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            var form = new MainForm();
            form.LoadArgs(args);
            Application.Run(form);
        }
    }
}
