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
using System.Threading;
using System.Windows.Forms;

namespace APKPatcher
{
    // ───────────────────────────────────────────────
    //  Simple result class (replaces C#7 tuples)
    // ───────────────────────────────────────────────
    public class CmdResult
    {
        public int ExitCode { get; set; }
        public string Output { get; set; }
    }

    // ───────────────────────────────────────────────
    //  Patch engine — parses patch.txt and applies ops
    // ───────────────────────────────────────────────
    public class PatchEngine
    {
        public string PatchDir { get; set; }
        public Action<string, Color> Log { get; set; }
        public Action<int> SetProgress { get; set; }

        public PatchEngine(string patchDir)
        {
            PatchDir = patchDir;
        }

        private void SafeLog(string msg, Color c)
        {
            if (Log != null) Log(msg, c);
        }

        // Parse and apply patch.txt to a decompiled directory
        public bool ApplyPatch(string decompDir)
        {
            string patchFile = Path.Combine(PatchDir, "patch.txt");
            if (!File.Exists(patchFile))
            {
                SafeLog("ERROR: patch.txt not found in " + PatchDir, Color.Red);
                return false;
            }

            string[] lines = File.ReadAllLines(patchFile);
            int i = 0;

            while (i < lines.Length)
            {
                string line = lines[i].Trim();

                if (line == "[REMOVE_FILES]")
                {
                    i++;
                    string target = null;
                    while (i < lines.Length && lines[i].Trim() != "[/REMOVE_FILES]")
                    {
                        if (lines[i].Trim() == "TARGET:")
                        {
                            i++;
                            if (i < lines.Length) target = lines[i].Trim();
                        }
                        i++;
                    }
                    if (target != null)
                    {
                        string path = Path.Combine(decompDir, target.Replace('/', '\\'));
                        if (File.Exists(path))
                        {
                            File.Delete(path);
                            SafeLog("  Removed: " + target, Color.FromArgb(0, 200, 120));
                        }
                        else
                            SafeLog("  Skip remove (not found): " + target, Color.Yellow);
                    }
                }
                else if (line == "[ADD_FILES]")
                {
                    i++;
                    string source = null, target = null;
                    while (i < lines.Length && lines[i].Trim() != "[/ADD_FILES]")
                    {
                        if (lines[i].Trim() == "SOURCE:")
                        {
                            i++;
                            if (i < lines.Length) source = lines[i].Trim();
                        }
                        else if (lines[i].Trim() == "TARGET:")
                        {
                            i++;
                            if (i < lines.Length) target = lines[i].Trim();
                        }
                        i++;
                    }
                    if (source != null && target != null)
                    {
                        string srcPath = Path.Combine(PatchDir, source);
                        string tgtPath = Path.Combine(decompDir, target.Replace('/', '\\'));
                        Directory.CreateDirectory(Path.GetDirectoryName(tgtPath));
                        File.Copy(srcPath, tgtPath, true);
                        SafeLog("  Added: " + source + " -> " + target, Color.FromArgb(0, 200, 120));
                    }
                }
                else if (line == "[MATCH_REPLACE]")
                {
                    i++;
                    string target = null, matchStr = null, replaceStr = "";
                    bool isRegex = false;
                    while (i < lines.Length && lines[i].Trim() != "[/MATCH_REPLACE]")
                    {
                        string trimmed = lines[i].Trim();
                        if (trimmed == "TARGET:")
                        {
                            i++;
                            if (i < lines.Length) target = lines[i].Trim();
                        }
                        else if (trimmed == "MATCH:")
                        {
                            i++;
                            if (i < lines.Length) matchStr = lines[i]; // preserve whitespace
                        }
                        else if (trimmed == "REGEX:")
                        {
                            i++;
                            if (i < lines.Length) isRegex = lines[i].Trim() == "true";
                        }
                        else if (trimmed == "REPLACE:")
                        {
                            i++;
                            if (i < lines.Length && lines[i].Trim() != "[/MATCH_REPLACE]")
                                replaceStr = lines[i]; // preserve whitespace
                            else
                            {
                                replaceStr = "";
                                continue;
                            }
                        }
                        i++;
                    }
                    if (target != null && matchStr != null)
                    {
                        string path = Path.Combine(decompDir, target.Replace('/', '\\'));
                        if (File.Exists(path))
                        {
                            string content = File.ReadAllText(path);
                            if (isRegex)
                                content = Regex.Replace(content, matchStr, replaceStr);
                            else
                                content = content.Replace(matchStr, replaceStr);
                            File.WriteAllText(path, content);
                            string shortMatch = matchStr.Length > 45 ? matchStr.Substring(0, 45) + "..." : matchStr;
                            SafeLog("  Patched: " + target + "  (" + shortMatch.Trim() + ")", Color.FromArgb(0, 200, 120));
                        }
                        else
                            SafeLog("  Skip patch (not found): " + target, Color.Yellow);
                    }
                }
                i++;
            }
            return true;
        }
    }

    // ───────────────────────────────────────────────
    //  Tool checker — validates required CLI tools
    // ───────────────────────────────────────────────
    public static class ToolChecker
    {
        public static string FindTool(string name)
        {
            try
            {
                var psi = new ProcessStartInfo("where", name)
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                var p = Process.Start(psi);
                string output = p.StandardOutput.ReadToEnd().Trim();
                p.WaitForExit();
                if (p.ExitCode == 0 && !string.IsNullOrEmpty(output))
                    return output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)[0];
            }
            catch { }
            return null;
        }

        public static Dictionary<string, string> CheckAll()
        {
            var tools = new Dictionary<string, string>();
            foreach (var t in new[] { "apktool", "java", "keytool", "jarsigner", "zipalign", "apksigner" })
                tools[t] = FindTool(t);
            return tools;
        }
    }

    // ───────────────────────────────────────────────
    //  Process runner helper
    // ───────────────────────────────────────────────
    public static class CmdRunner
    {
        // Resolve apktool/apksigner .bat wrappers to direct java -jar calls
        // to avoid the "pause" command in .bat wrappers that hangs forever.
        private static string _apktoolJar;

        private static string FindApktoolJar()
        {
            if (_apktoolJar != null) return _apktoolJar;
            string batPath = ToolChecker.FindTool("apktool");
            if (batPath != null)
            {
                string dir = Path.GetDirectoryName(batPath);
                // Look for apktool.jar or apktool_*.jar
                foreach (var f in Directory.GetFiles(dir, "apktool*.jar"))
                {
                    _apktoolJar = f;
                    return _apktoolJar;
                }
            }
            return null;
        }

        public static CmdResult Run(string exe, string args)
        {
            string actualExe = exe;
            string actualArgs = args;

            // For apktool: bypass the .bat wrapper (which has a "pause" that hangs)
            // and call java -jar directly
            if (exe == "apktool")
            {
                string jar = FindApktoolJar();
                if (jar != null)
                {
                    actualExe = "java";
                    actualArgs = "-Xmx1024M -Duser.language=en -Dfile.encoding=UTF8 " +
                                 "-Djdk.util.zip.disableZip64ExtraFieldValidation=true " +
                                 "-Djdk.nio.zipfs.allowDotZipEntry=true " +
                                 "-jar \"" + jar + "\" " + args;
                }
            }
            // For apksigner: it's also a .bat, resolve to the .jar
            else if (exe == "apksigner")
            {
                string batPath = ToolChecker.FindTool("apksigner");
                if (batPath != null)
                {
                    string dir = Path.GetDirectoryName(batPath);
                    string libDir = Path.Combine(dir, "lib");
                    string jar = null;
                    if (Directory.Exists(libDir))
                    {
                        foreach (var f in Directory.GetFiles(libDir, "apksigner*.jar"))
                        { jar = f; break; }
                    }
                    if (jar != null)
                    {
                        actualExe = "java";
                        actualArgs = "-jar \"" + jar + "\" " + args;
                    }
                }
            }

            var psi = new ProcessStartInfo(actualExe, actualArgs)
            {
                UseShellExecute = false,
                CreateNoWindow = true
            };
            var p = Process.Start(psi);
            p.WaitForExit();
            return new CmdResult { ExitCode = p.ExitCode, Output = "" };
        }
    }

    // ───────────────────────────────────────────────
    //  Custom dark-themed controls
    // ───────────────────────────────────────────────
    public class DarkProgressBar : Control
    {
        private int _value = 0;
        private int _max = 100;
        private string _statusText = "";
        public int Value { get { return _value; } set { _value = Math.Min(value, _max); Invalidate(); } }
        public int Maximum { get { return _max; } set { _max = value; Invalidate(); } }
        public string StatusText { get { return _statusText; } set { _statusText = value; Invalidate(); } }

        public DarkProgressBar() { DoubleBuffered = true; Height = 32; }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;

            // Background
            using (var bg = new SolidBrush(Color.FromArgb(30, 30, 30)))
                g.FillRoundedRect(bg, ClientRectangle, 6);

            // Fill
            if (_value > 0 && _max > 0)
            {
                int w = (int)((Width - 4) * ((float)_value / _max));
                var fillRect = new Rectangle(2, 2, w, Height - 4);
                using (var fill = new LinearGradientBrush(fillRect, Color.FromArgb(0, 180, 255), Color.FromArgb(0, 120, 220), 0f))
                    g.FillRoundedRect(fill, fillRect, 5);
            }

            // Text
            string text = _statusText != "" ? _statusText : (_value > 0 ? _value + "%" : "Waiting...");
            using (var f = new Font("Segoe UI", 9f, FontStyle.Bold))
            using (var b = new SolidBrush(Color.White))
            {
                var sf = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };
                g.DrawString(text, f, b, ClientRectangle, sf);
            }
        }
    }

    // Extension for rounded rects
    public static class GraphicsExt
    {
        public static void FillRoundedRect(this Graphics g, Brush b, Rectangle r, int radius)
        {
            using (var path = new GraphicsPath())
            {
                path.AddArc(r.X, r.Y, radius * 2, radius * 2, 180, 90);
                path.AddArc(r.Right - radius * 2, r.Y, radius * 2, radius * 2, 270, 90);
                path.AddArc(r.Right - radius * 2, r.Bottom - radius * 2, radius * 2, radius * 2, 0, 90);
                path.AddArc(r.X, r.Bottom - radius * 2, radius * 2, radius * 2, 90, 90);
                path.CloseFigure();
                g.FillPath(b, path);
            }
        }
    }

    // ───────────────────────────────────────────────
    //  Main Form
    // ───────────────────────────────────────────────
    public class MainForm : Form
    {
        // UI controls
        private Panel dropZone;
        private Label dropLabel;
        private ListBox fileList;
        private Button btnBrowse, btnRemove, btnClearLog, btnPatchAll, btnOpenOutput, btnChangePatch;
        private RichTextBox logBox;
        private DarkProgressBar progressBar;
        private Label lblPatchDir, lblToolStatus, lblStats;
        private CheckBox chkBackup, chkVerify, chkAutoOpen;

        // State
        private string patchDir;
        private string outputDir;
        private string keystorePath;
        private bool isRunning = false;
        private int totalPatched = 0;
        private int totalFailed = 0;
        private Stopwatch sw = new Stopwatch();

        // Colors
        static readonly Color BG        = Color.FromArgb(18, 18, 22);
        static readonly Color PANEL_BG   = Color.FromArgb(28, 28, 35);
        static readonly Color ACCENT     = Color.FromArgb(0, 160, 255);
        static readonly Color GREEN      = Color.FromArgb(0, 210, 120);
        static readonly Color RED        = Color.FromArgb(255, 80, 80);
        static readonly Color FG         = Color.FromArgb(220, 220, 230);
        static readonly Color FG_DIM     = Color.FromArgb(120, 120, 140);

        public MainForm()
        {
            patchDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "PATCH");
            outputDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "PATCHED_OUTPUT");
            keystorePath = Path.Combine(patchDir, "debug.keystore");

            InitUI();
            CheckTools();
        }

        private void InitUI()
        {
            Text = "APK Patcher Pro";
            Size = new Size(820, 720);
            MinimumSize = new Size(700, 600);
            StartPosition = FormStartPosition.CenterScreen;
            BackColor = BG;
            ForeColor = FG;
            Font = new Font("Segoe UI", 9.5f);
            Icon = SystemIcons.Shield;
            AllowDrop = true;

            // ── Title bar area ──
            var lblTitle = new Label
            {
                Text = "\u26A1 APK Patcher Pro",
                Font = new Font("Segoe UI", 16f, FontStyle.Bold),
                ForeColor = ACCENT,
                Location = new Point(20, 12),
                AutoSize = true
            };
            Controls.Add(lblTitle);

            var lblVer = new Label
            {
                Text = "v2.0",
                Font = new Font("Segoe UI", 9f),
                ForeColor = FG_DIM,
                Location = new Point(230, 22),
                AutoSize = true
            };
            Controls.Add(lblVer);

            // ── Tool status ──
            lblToolStatus = new Label
            {
                Font = new Font("Segoe UI", 8.5f),
                ForeColor = FG_DIM,
                Location = new Point(20, 45),
                Size = new Size(760, 18),
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };
            Controls.Add(lblToolStatus);

            // ── Patch dir label ──
            lblPatchDir = new Label
            {
                Text = "Patch: " + patchDir,
                Font = new Font("Segoe UI", 8.5f),
                ForeColor = FG_DIM,
                Location = new Point(20, 63),
                Size = new Size(620, 18),
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };
            Controls.Add(lblPatchDir);

            btnChangePatch = new Button
            {
                Text = "Change",
                FlatStyle = FlatStyle.Flat,
                BackColor = PANEL_BG,
                ForeColor = FG_DIM,
                Size = new Size(65, 22),
                Location = new Point(720, 60),
                Anchor = AnchorStyles.Top | AnchorStyles.Right,
                Cursor = Cursors.Hand
            };
            btnChangePatch.FlatAppearance.BorderColor = Color.FromArgb(60, 60, 70);
            btnChangePatch.Click += (s, e) => ChangePatchDir();
            Controls.Add(btnChangePatch);

            // ── Drop zone ──
            dropZone = new Panel
            {
                Location = new Point(20, 90),
                Size = new Size(370, 130),
                BackColor = PANEL_BG,
                AllowDrop = true,
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };
            dropZone.Paint += DropZone_Paint;
            dropZone.DragEnter += DropZone_DragEnter;
            dropZone.DragLeave += (s, e) => { dropZone.BackColor = PANEL_BG; dropZone.Invalidate(); };
            dropZone.DragDrop += DropZone_DragDrop;
            Controls.Add(dropZone);

            dropLabel = new Label
            {
                Text = "Drop APK files here\n(APK \u2022 XAPK \u2022 APKM \u2022 APKS)",
                TextAlign = ContentAlignment.MiddleCenter,
                Font = new Font("Segoe UI", 11f),
                ForeColor = FG_DIM,
                Dock = DockStyle.Fill,
                BackColor = Color.Transparent
            };
            dropZone.Controls.Add(dropLabel);

            // ── File list ──
            fileList = new ListBox
            {
                Location = new Point(400, 90),
                Size = new Size(385, 100),
                BackColor = PANEL_BG,
                ForeColor = FG,
                BorderStyle = BorderStyle.None,
                Font = new Font("Consolas", 9f),
                Anchor = AnchorStyles.Top | AnchorStyles.Right
            };
            Controls.Add(fileList);

            // ── Buttons row for file list ──
            btnBrowse = MakeBtn("Browse", 400, 195, 120, AnchorStyles.Top | AnchorStyles.Right);
            btnBrowse.Click += BtnBrowse_Click;
            Controls.Add(btnBrowse);

            btnRemove = MakeBtn("Remove", 530, 195, 120, AnchorStyles.Top | AnchorStyles.Right);
            btnRemove.Click += (s, e) => { if (fileList.SelectedIndex >= 0) fileList.Items.RemoveAt(fileList.SelectedIndex); };
            Controls.Add(btnRemove);

            var btnClear = MakeBtn("Clear All", 660, 195, 125, AnchorStyles.Top | AnchorStyles.Right);
            btnClear.Click += (s, e) => fileList.Items.Clear();
            Controls.Add(btnClear);

            // ── Options ──
            chkBackup = new CheckBox { Text = "Backup original", Location = new Point(22, 228), ForeColor = FG, AutoSize = true, Checked = false };
            chkVerify = new CheckBox { Text = "Verify signature", Location = new Point(180, 228), ForeColor = FG, AutoSize = true, Checked = true };
            chkAutoOpen = new CheckBox { Text = "Open output folder when done", Location = new Point(350, 228), ForeColor = FG, AutoSize = true, Checked = true };
            Controls.Add(chkBackup);
            Controls.Add(chkVerify);
            Controls.Add(chkAutoOpen);

            // ── Progress bar ──
            progressBar = new DarkProgressBar
            {
                Location = new Point(20, 258),
                Size = new Size(765, 30),
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };
            Controls.Add(progressBar);

            // ── Patch button ──
            btnPatchAll = new Button
            {
                Text = "\u25B6  PATCH ALL",
                Font = new Font("Segoe UI", 12f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                BackColor = ACCENT,
                ForeColor = Color.White,
                Size = new Size(765, 44),
                Location = new Point(20, 296),
                Cursor = Cursors.Hand,
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };
            btnPatchAll.FlatAppearance.BorderSize = 0;
            btnPatchAll.Click += BtnPatchAll_Click;
            Controls.Add(btnPatchAll);

            // ── Log box ──
            logBox = new RichTextBox
            {
                Location = new Point(20, 348),
                Size = new Size(765, 275),
                BackColor = Color.FromArgb(12, 12, 16),
                ForeColor = FG,
                Font = new Font("Consolas", 9f),
                ReadOnly = true,
                BorderStyle = BorderStyle.None,
                ScrollBars = RichTextBoxScrollBars.Vertical,
                Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right
            };
            Controls.Add(logBox);

            // ── Bottom bar ──
            btnClearLog = MakeBtn("Clear Log", 20, 630, 100, AnchorStyles.Bottom | AnchorStyles.Left);
            btnClearLog.Click += (s, e) => logBox.Clear();
            Controls.Add(btnClearLog);

            btnOpenOutput = MakeBtn("Open Output", 130, 630, 120, AnchorStyles.Bottom | AnchorStyles.Left);
            btnOpenOutput.Click += (s, e) => { Directory.CreateDirectory(outputDir); Process.Start("explorer.exe", outputDir); };
            Controls.Add(btnOpenOutput);

            lblStats = new Label
            {
                Text = "",
                Font = new Font("Segoe UI", 9f),
                ForeColor = FG_DIM,
                Location = new Point(400, 634),
                Size = new Size(380, 20),
                TextAlign = ContentAlignment.MiddleRight,
                Anchor = AnchorStyles.Bottom | AnchorStyles.Right
            };
            Controls.Add(lblStats);

            // Form drag-drop forwarding
            DragEnter += DropZone_DragEnter;
            DragDrop += DropZone_DragDrop;
        }

        private Button MakeBtn(string text, int x, int y, int w, AnchorStyles anchor)
        {
            var btn = new Button
            {
                Text = text,
                FlatStyle = FlatStyle.Flat,
                BackColor = PANEL_BG,
                ForeColor = FG,
                Size = new Size(w, 28),
                Location = new Point(x, y),
                Cursor = Cursors.Hand,
                Anchor = anchor
            };
            btn.FlatAppearance.BorderColor = Color.FromArgb(60, 60, 70);
            return btn;
        }

        // ── Drag & Drop ──
        private static readonly string[] VALID_EXT = { ".apk", ".xapk", ".apkm", ".apks" };
        private void DropZone_Paint(object sender, PaintEventArgs e)
        {
            var r = new Rectangle(2, 2, dropZone.Width - 5, dropZone.Height - 5);
            using (var pen = new Pen(Color.FromArgb(60, 60, 80), 2) { DashStyle = DashStyle.Dash })
                e.Graphics.DrawRectangle(pen, r);
        }
        private void DropZone_DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                e.Effect = DragDropEffects.Copy;
                dropZone.BackColor = Color.FromArgb(35, 45, 55);
                dropZone.Invalidate();
            }
        }
        private void DropZone_DragDrop(object sender, DragEventArgs e)
        {
            dropZone.BackColor = PANEL_BG;
            dropZone.Invalidate();
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                var files = (string[])e.Data.GetData(DataFormats.FileDrop);
                AddFiles(files);
            }
        }

        private void AddFiles(IEnumerable<string> files)
        {
            foreach (var f in files)
            {
                string ext = Path.GetExtension(f).ToLower();
                if (VALID_EXT.Contains(ext) && !fileList.Items.Contains(f))
                    fileList.Items.Add(f);
            }
        }

        private void BtnBrowse_Click(object sender, EventArgs e)
        {
            using (var dlg = new OpenFileDialog())
            {
                dlg.Title = "Select APK files";
                dlg.Filter = "Android Packages|*.apk;*.xapk;*.apkm;*.apks|All Files|*.*";
                dlg.Multiselect = true;
                if (dlg.ShowDialog() == DialogResult.OK)
                    AddFiles(dlg.FileNames);
            }
        }

        private void ChangePatchDir()
        {
            using (var dlg = new FolderBrowserDialog())
            {
                dlg.Description = "Select patch directory (must contain patch.txt)";
                dlg.SelectedPath = patchDir;
                if (dlg.ShowDialog() == DialogResult.OK)
                {
                    patchDir = dlg.SelectedPath;
                    keystorePath = Path.Combine(patchDir, "debug.keystore");
                    lblPatchDir.Text = "Patch: " + patchDir;
                }
            }
        }

        // ── Tool check ──
        private void CheckTools()
        {
            var tools = ToolChecker.CheckAll();
            var missing = tools.Where(t => t.Value == null).Select(t => t.Key).ToList();
            if (missing.Count == 0)
            {
                lblToolStatus.Text = "\u2705 All tools found: apktool, java, keytool, zipalign, apksigner";
                lblToolStatus.ForeColor = GREEN;
            }
            else
            {
                lblToolStatus.Text = "\u274C Missing: " + string.Join(", ", missing);
                lblToolStatus.ForeColor = RED;
            }
        }

        // ── Logging ──
        private void AppendLog(string text, Color color)
        {
            if (InvokeRequired) { Invoke(new Action(() => AppendLog(text, color))); return; }
            logBox.SelectionStart = logBox.TextLength;
            logBox.SelectionColor = color;
            logBox.AppendText(text + "\n");
            logBox.ScrollToCaret();
        }

        private void SetProgressSafe(int val)
        {
            if (InvokeRequired) { Invoke(new Action(() => SetProgressSafe(val))); return; }
            progressBar.Value = val;
        }

        private void SetStatusSafe(string text)
        {
            if (InvokeRequired) { Invoke(new Action(() => SetStatusSafe(text))); return; }
            progressBar.StatusText = text;
        }

        // ── Main patch pipeline ──
        private void BtnPatchAll_Click(object sender, EventArgs e)
        {
            if (isRunning) return;
            if (fileList.Items.Count == 0)
            {
                AppendLog("No files added. Drag & drop or browse to add APK files.", Color.Yellow);
                return;
            }
            if (!File.Exists(Path.Combine(patchDir, "patch.txt")))
            {
                AppendLog("ERROR: patch.txt not found in " + patchDir, RED);
                return;
            }

            isRunning = true;
            btnPatchAll.Enabled = false;
            btnPatchAll.Text = "Patching...";
            btnPatchAll.BackColor = Color.FromArgb(60, 60, 70);
            totalPatched = 0;
            totalFailed = 0;
            sw.Restart();

            var files = new List<string>();
            foreach (var item in fileList.Items)
                files.Add(item.ToString());

            var worker = new BackgroundWorker();
            worker.DoWork += (ws, we) => ProcessAll(files);
            worker.RunWorkerCompleted += (ws, we) =>
            {
                sw.Stop();
                isRunning = false;
                btnPatchAll.Enabled = true;
                btnPatchAll.Text = "\u25B6  PATCH ALL";
                btnPatchAll.BackColor = ACCENT;
                lblStats.Text = string.Format("Done: {0} patched, {1} failed | {2:F1}s", totalPatched, totalFailed, sw.Elapsed.TotalSeconds);
                progressBar.StatusText = "Complete!";
                progressBar.Value = progressBar.Maximum;

                if (totalPatched > 0 && chkAutoOpen.Checked)
                    Process.Start("explorer.exe", outputDir);
            };
            worker.RunWorkerAsync();
        }

        private void ProcessAll(List<string> files)
        {
            Directory.CreateDirectory(outputDir);
            int total = files.Count;

            for (int idx = 0; idx < total; idx++)
            {
                string file = files[idx];
                string baseName = Path.GetFileNameWithoutExtension(file);
                int pctBase = (int)((float)idx / total * 100);

                AppendLog("", FG);
                AppendLog("═══════════════════════════════════════════════", ACCENT);
                AppendLog("  Processing: " + Path.GetFileName(file) + "  (" + (idx + 1) + "/" + total + ")", ACCENT);
                AppendLog("═══════════════════════════════════════════════", ACCENT);

                string workDir = Path.Combine(Path.GetTempPath(), "apkpatcher_" + Guid.NewGuid().ToString("N").Substring(0, 8));
                try
                {
                    Directory.CreateDirectory(workDir);

                    // Backup
                    if (chkBackup.Checked)
                    {
                        string backupDir = Path.Combine(outputDir, "backups");
                        Directory.CreateDirectory(backupDir);
                        File.Copy(file, Path.Combine(backupDir, Path.GetFileName(file)), true);
                        AppendLog("  Backup saved", FG_DIM);
                    }

                    // Step 1: Extract base APK
                    SetStatusSafe("Extracting... (" + (idx + 1) + "/" + total + ")");
                    SetProgressSafe(pctBase + 5);
                    string baseApk = ExtractBaseApk(file, workDir);
                    if (baseApk == null) { totalFailed++; continue; }

                    // Step 2: Decompile
                    SetStatusSafe("Decompiling... (" + (idx + 1) + "/" + total + ")");
                    SetProgressSafe(pctBase + 15);
                    string decompDir = Path.Combine(workDir, "decompiled");
                    AppendLog("[*] Decompiling with apktool...", Color.Cyan);
                    // -s = skip smali (DEX decoding) since patch only touches resources/manifest
                    CmdResult res = CmdRunner.Run("apktool", "d -s \"" + baseApk + "\" -o \"" + decompDir + "\" -f");
                    if (res.ExitCode != 0 || !Directory.Exists(decompDir) || !File.Exists(Path.Combine(decompDir, "AndroidManifest.xml")))
                    {
                        AppendLog("ERROR: apktool decompile failed! (exit=" + res.ExitCode + ")", RED);
                        totalFailed++;
                        continue;
                    }
                    AppendLog("[+] Decompiled", GREEN);

                    // Step 2.5: Flutter SSL bypass — detect and patch libflutter.so
                    bool isFlutter = false;
                    string libDir = Path.Combine(decompDir, "lib");
                    if (Directory.Exists(libDir))
                    {
                        var flutterLibs = Directory.GetFiles(libDir, "libflutter.so", SearchOption.AllDirectories);
                        if (flutterLibs.Length > 0) isFlutter = true;
                    }
                    if (isFlutter)
                    {
                        SetStatusSafe("Flutter detected! Patching SSL... (" + (idx + 1) + "/" + total + ")");
                        SetProgressSafe(pctBase + 30);
                        AppendLog("[*] Flutter app detected — patching libflutter.so for SSL bypass...", Color.Magenta);
                        string reflutterOut = Path.Combine(workDir, "release.RE.apk");
                        // Run reflutter on the original APK
                        var rfRes = CmdRunner.Run("python", "-m reflutter \"" + baseApk + "\" --no-input");
                        // reflutter outputs release.RE.apk in current dir, try to find it
                        string reApk = null;
                        foreach (var candidate in new[] {
                            Path.Combine(workDir, "release.RE.apk"),
                            Path.Combine(Environment.CurrentDirectory, "release.RE.apk"),
                            Path.Combine(Path.GetDirectoryName(baseApk), "release.RE.apk") })
                        {
                            if (File.Exists(candidate)) { reApk = candidate; break; }
                        }
                        if (reApk != null)
                        {
                            // Extract patched libflutter.so from the reflutter APK and replace in decompiled
                            try
                            {
                                string reExtract = Path.Combine(workDir, "reflutter_extract");
                                ZipFile.ExtractToDirectory(reApk, reExtract);
                                var patchedLibs = Directory.GetFiles(reExtract, "libflutter.so", SearchOption.AllDirectories);
                                foreach (var patchedLib in patchedLibs)
                                {
                                    // Get relative path like lib/arm64-v8a/libflutter.so
                                    string relPath = patchedLib.Substring(reExtract.Length + 1);
                                    string destPath = Path.Combine(decompDir, relPath);
                                    if (File.Exists(destPath))
                                    {
                                        File.Copy(patchedLib, destPath, true);
                                        AppendLog("  Flutter SSL patched: " + relPath, Color.FromArgb(0, 200, 120));
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                AppendLog("  Flutter patch warning: " + ex.Message, Color.Yellow);
                            }
                        }
                        else
                        {
                            AppendLog("  Flutter SSL patch skipped (reFlutter not available or unsupported engine)", Color.Yellow);
                        }
                    }

                    // Step 3: Apply patch
                    SetStatusSafe("Patching... (" + (idx + 1) + "/" + total + ")");
                    SetProgressSafe(pctBase + 40);
                    AppendLog("[*] Applying patches...", Color.Cyan);
                    var engine = new PatchEngine(patchDir);
                    engine.Log = delegate(string msg, Color c) { AppendLog(msg, c); };
                    if (!engine.ApplyPatch(decompDir))
                    {
                        totalFailed++;
                        continue;
                    }
                    AppendLog("[+] All patches applied", GREEN);

                    // Step 4: Rebuild
                    SetStatusSafe("Rebuilding... (" + (idx + 1) + "/" + total + ")");
                    SetProgressSafe(pctBase + 55);
                    string rebuiltApk = Path.Combine(workDir, "rebuilt.apk");
                    AppendLog("[*] Rebuilding APK...", Color.Cyan);
                    res = CmdRunner.Run("apktool", "b \"" + decompDir + "\" -o \"" + rebuiltApk + "\" --use-aapt2");
                    if (!File.Exists(rebuiltApk))
                    {
                        AppendLog("  aapt2 failed, retrying without --use-aapt2...", Color.Yellow);
                        res = CmdRunner.Run("apktool", "b \"" + decompDir + "\" -o \"" + rebuiltApk + "\"");
                        if (!File.Exists(rebuiltApk))
                        {
                            AppendLog("ERROR: Rebuild failed!", RED);
                            totalFailed++;
                            continue;
                        }
                    }
                    AppendLog("[+] Rebuilt", GREEN);

                    // Step 5: Generate keystore if needed
                    EnsureKeystore();

                    // Step 6: Zipalign
                    SetStatusSafe("Zipaligning... (" + (idx + 1) + "/" + total + ")");
                    SetProgressSafe(pctBase + 70);
                    string alignedApk = Path.Combine(workDir, "aligned.apk");
                    AppendLog("[*] Zipaligning...", Color.Cyan);
                    res = CmdRunner.Run("zipalign", "-f 4 \"" + rebuiltApk + "\" \"" + alignedApk + "\"");
                    if (!File.Exists(alignedApk))
                    {
                        AppendLog("ERROR: Zipalign failed!", RED);
                        totalFailed++;
                        continue;
                    }
                    AppendLog("[+] Zipaligned", GREEN);

                    // Step 7: Sign
                    SetStatusSafe("Signing... (" + (idx + 1) + "/" + total + ")");
                    SetProgressSafe(pctBase + 85);
                    string finalApk = Path.Combine(outputDir, baseName + "_patched.apk");
                    File.Copy(alignedApk, finalApk, true);
                    AppendLog("[*] Signing...", Color.Cyan);
                    res = CmdRunner.Run("apksigner",
                        "sign --ks \"" + keystorePath + "\" --ks-pass pass:android --ks-key-alias androiddebugkey --key-pass pass:android \"" + finalApk + "\"");
                    if (res.ExitCode != 0)
                    {
                        AppendLog("ERROR: Signing failed!", RED);
                        AppendLog(res.Output, FG_DIM);
                        totalFailed++;
                        continue;
                    }
                    AppendLog("[+] Signed", GREEN);

                    // Step 8: Verify
                    if (chkVerify.Checked)
                    {
                        SetStatusSafe("Verifying... (" + (idx + 1) + "/" + total + ")");
                        res = CmdRunner.Run("apksigner", "verify \"" + finalApk + "\"");
                        if (res.ExitCode == 0)
                            AppendLog("[+] Signature verified OK", GREEN);
                        else
                            AppendLog("[~] Signature verification warning (non-fatal)", Color.Yellow);
                    }

                    AppendLog("OUTPUT: " + finalApk, Color.FromArgb(100, 255, 150));
                    totalPatched++;
                }
                catch (Exception ex)
                {
                    AppendLog("ERROR: " + ex.Message, RED);
                    totalFailed++;
                }
                finally
                {
                    try { if (Directory.Exists(workDir)) Directory.Delete(workDir, true); } catch { }
                }

                SetProgressSafe((int)((float)(idx + 1) / total * 100));
            }
        }

        private string ExtractBaseApk(string file, string workDir)
        {
            string ext = Path.GetExtension(file).ToLower();
            if (ext == ".apk") return file;

            AppendLog("[*] Extracting split-APK bundle...", Color.Cyan);
            string extractDir = Path.Combine(workDir, "bundle");
            try
            {
                ZipFile.ExtractToDirectory(file, extractDir);
            }
            catch (Exception ex)
            {
                AppendLog("ERROR: Failed to extract bundle: " + ex.Message, RED);
                return null;
            }

            // Find base.apk or first .apk
            var apks = Directory.GetFiles(extractDir, "*.apk", SearchOption.AllDirectories);
            string baseApk = apks.FirstOrDefault(a => Path.GetFileName(a).Equals("base.apk", StringComparison.OrdinalIgnoreCase));
            if (baseApk == null) baseApk = apks.FirstOrDefault();
            if (baseApk == null)
            {
                AppendLog("ERROR: No APK found inside bundle!", RED);
                return null;
            }
            AppendLog("[+] Found: " + Path.GetFileName(baseApk), GREEN);
            return baseApk;
        }

        private void EnsureKeystore()
        {
            if (File.Exists(keystorePath)) return;
            AppendLog("[*] Generating debug keystore...", Color.Cyan);
            CmdRunner.Run("keytool",
                "-genkey -v -keystore \"" + keystorePath + "\" -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 " +
                "-storepass android -keypass android -dname \"CN=Debug,OU=Debug,O=Debug,L=Debug,ST=Debug,C=US\"");
            AppendLog("[+] Keystore created", GREEN);
        }

        // Handle files passed via command line args
        public void LoadArgs(string[] args)
        {
            if (args != null && args.Length > 0)
            {
                foreach (var a in args)
                {
                    if (File.Exists(a))
                    {
                        string ext = Path.GetExtension(a).ToLower();
                        if (VALID_EXT.Contains(ext) && !fileList.Items.Contains(a))
                            fileList.Items.Add(a);
                    }
                }
            }
        }
    }

    // ───────────────────────────────────────────────
    //  Entry point
    // ───────────────────────────────────────────────
    static class Program
    {
        [DllImport("kernel32.dll")] static extern bool AllocConsole();
        [DllImport("kernel32.dll")] static extern IntPtr GetConsoleWindow();
        [DllImport("user32.dll")] static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [STAThread]
        static void Main(string[] args)
        {
            // Allocate a hidden console so Java/apktool child processes
            // inherit valid stdin/stdout/stderr handles and don't hang.
            AllocConsole();
            IntPtr consoleWnd = GetConsoleWindow();
            if (consoleWnd != IntPtr.Zero)
                ShowWindow(consoleWnd, 0); // SW_HIDE = 0

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            var form = new MainForm();
            form.LoadArgs(args);
            Application.Run(form);
        }
    }
}
