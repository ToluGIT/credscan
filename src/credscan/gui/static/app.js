/* CredScan GUI - Vue 3 app wired to the FastAPI backend. */
const { createApp } = Vue;

createApp({
  data() {
    return {
      screen: "dashboard",
      screens: [
        { id: "dashboard", label: "dashboard", sub: "credscan status" },
        { id: "advanced", label: "advanced", sub: "history · url" },
        { id: "live", label: "live output", sub: "scan --stream" },
        { id: "report", label: "findings", sub: "report --last" },
        { id: "baseline", label: "baseline", sub: "baseline list" },
      ],
      scanPath: ".",
      minConfidencePct: 50,
      validateLive: false,
      showOptions: false,
      opts: { no_context_analysis: false, no_entropy: false },
      // advanced scans (git history, web endpoint)
      historyPath: ".",
      historyMaxCommits: 100,
      historySince: "",
      urlTarget: "",
      urlCrawl: false,
      // mode (fetched from /api/mode)
      publicMode: false,
      maxBytes: 2097152,
      maxFiles: 200,
      pasteText: "",
      uploadFiles: [],
      quickActions: [
        { glyph: "▸", label: "SCAN DIR", path: "." },
        { glyph: "◆", label: "SCAN demo/", path: "demo" },
        { glyph: "⬢", label: "SCAN src/", path: "src" },
        { glyph: "▣", label: "SCAN tests/", path: "tests" },
      ],
      fileTypes: [
        ".tf / .tfvars", "CloudFormation", ".github/workflows", ".gitlab-ci.yml",
        "Jenkinsfile", "Dockerfile", ".env", "JSON", "YAML",
        ".py / .js / .go / .java", "archives (zip/tar/jar)",
      ],
      detectCategories: [
        "AWS keys", "GCP keys", "Azure", "Stripe", "Slack", "GitHub/GitLab tokens",
        "OpenAI/Anthropic", "private keys (PEM)", "JWT", "DB connection strings",
        "passwords", "OAuth secrets",
      ],
      enginePlaceholder: "—",
      lastScanAt: "",
      busy: false,
      jobId: null,
      liveLines: [],
      findings: [],
      summary: { critical: 0, high: 0, medium: 0, low: 0 },
      prevSummary: null,  // previous scan's counts, for an honest "vs last" delta
      filesScanned: 0,
      filesFound: 0,
      baseline: [],
      sevFilter: "",
      search: "",
      clock: "",
    };
  },
  computed: {
    minConfidence() { return (this.minConfidencePct / 100).toFixed(2); },
    statusWord() { return this.busy ? "SCANNING" : (this.findings.length ? "DONE" : "READY"); },
    totalFindings() { return this.findings.length; },
    commandPreview() {
      // In public mode the input is uploaded content, not a server path.
      const target = this.publicMode ? "(uploaded content)" : ("--path " + (this.scanPath || "."));
      let c = "credscan " + target + " --min-confidence " + this.minConfidence;
      if (this.opts.no_context_analysis) c += " --no-context-analysis";
      if (this.opts.no_entropy) c += " --no-entropy";
      if (this.validateLive && !this.publicMode) c += " --validate-aws --verify";
      return c + " -o sarif";
    },
    severityCards() {
      // Bar length = this severity's share of ALL findings in the scan, so the
      // bars together read as the severity mix (HIGH 16/22 -> a long bar).
      const total = Object.values(this.summary).reduce((a, b) => a + b, 0);
      return ["critical", "high", "medium", "low"].map(k => {
        const count = this.summary[k] || 0;
        // Delta is the only status line, and only after a second scan: it
        // compares this scan to the immediately prior one. No "open"/"closed"
        // lifecycle is shown because the GUI has no close action.
        let delta = "";
        if (this.prevSummary) {
          const d = count - (this.prevSummary[k] || 0);
          delta = d > 0 ? "↑" + d + " vs last" : (d < 0 ? "↓" + (-d) + " vs last" : "no change");
        }
        return {
          key: k, label: k.toUpperCase(), count,
          pct: total ? Math.round((count / total) * 100) : 0, delta,
        };
      });
    },
    reportSummary() {
      if (!this.findings.length) return "no scan yet · run one from the dashboard";
      return this.findings.length + " findings across " + this.filesScanned + " files scanned";
    },
    progressText() {
      if (this.busy) return "▸ scanning " + this.scanPath + " ...";
      if (this.findings.length) return "█ complete · " + this.findings.length + " findings · " + this.filesScanned + " files";
      return "";
    },
    filtered() {
      const q = this.search.toLowerCase();
      return this.findings.filter(f =>
        (!this.sevFilter || f.severity === this.sevFilter) &&
        (!q || (f.type + " " + f.file).toLowerCase().includes(q))
      );
    },
  },
  methods: {
    bar(pct) {
      const n = Math.round(pct / 5);
      return "█".repeat(n) + "░".repeat(20 - n);
    },
    shortFile(p) { return (p || "").split("/").slice(-2).join("/"); },
    valClass(v) {
      const s = (v || "").toUpperCase();
      if (s.startsWith("ACTIVE")) return "val-active";
      if (s.startsWith("INVALID")) return "val-invalid";
      return "val-unknown";
    },
    valLabel(v) {
      const s = (v || "").toUpperCase();
      if (s.startsWith("ACTIVE")) return "● LIVE";
      if (s.startsWith("INVALID")) return "○ REVOKED";
      if (s.startsWith("SKIPPED")) return "skipped";
      return "unverified";
    },
    quick(qa) { this.scanPath = qa.path; this.runScan(); },
    filterBy(sev) { this.sevFilter = sev; this.screen = "report"; },
    async runScan() {
      if (this.busy) return;
      this.busy = true; this.liveLines = []; this.findings = [];
      // Remember the prior scan's counts for an honest "vs last" delta.
      if (this.lastScanAt) this.prevSummary = { ...this.summary };
      this.summary = { critical: 0, high: 0, medium: 0, low: 0 };
      this.screen = "live";
      try {
        const res = await fetch("/api/scan", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            path: this.scanPath || ".",
            min_confidence: parseFloat(this.minConfidence),
            no_context_analysis: this.opts.no_context_analysis,
            no_entropy: this.opts.no_entropy,
            validate: this.validateLive,
          }),
        });
        if (!res.ok) {
          const err = await res.json().catch(() => ({ detail: "scan failed" }));
          this.pushLine("error: " + (err.detail || res.status), "err");
          this.busy = false; return;
        }
        const { id } = await res.json();
        this.jobId = id;
        this.streamScan(id);
      } catch (e) {
        this.pushLine("error: " + e.message, "err");
        this.busy = false;
      }
    },
    onFiles(ev) {
      // A native file input replaces its selection on every pick and won't
      // re-fire for the same file. Accumulate across picks, dedupe by
      // name+size, and clear the input so re-selecting a file still registers.
      const key = f => f.name + ":" + f.size;
      const seen = new Set(this.uploadFiles.map(key));
      Array.from(ev.target.files || []).forEach(f => {
        if (!seen.has(key(f))) { this.uploadFiles.push(f); seen.add(key(f)); }
      });
      ev.target.value = "";
    },
    removeFile(i) { this.uploadFiles.splice(i, 1); },
    async runUpload() {
      if (this.busy) return;
      if (!this.pasteText.trim() && !this.uploadFiles.length) {
        alert("paste some content or choose a file first");
        return;
      }
      this.busy = true; this.liveLines = []; this.findings = [];
      // Remember the prior scan's counts for an honest "vs last" delta.
      if (this.lastScanAt) this.prevSummary = { ...this.summary };
      this.summary = { critical: 0, high: 0, medium: 0, low: 0 };
      this.screen = "live";
      try {
        const fd = new FormData();
        fd.append("min_confidence", this.minConfidence);
        fd.append("no_context_analysis", this.opts.no_context_analysis);
        fd.append("no_entropy", this.opts.no_entropy);
        if (this.pasteText.trim()) fd.append("text", this.pasteText);
        this.uploadFiles.forEach(f => fd.append("files", f));
        const res = await fetch("/api/scan/upload", { method: "POST", body: fd });
        if (!res.ok) {
          const err = await res.json().catch(() => ({ detail: "upload failed" }));
          this.pushLine("error: " + (err.detail || res.status), "err");
          this.busy = false; return;
        }
        const { id } = await res.json();
        this.jobId = id;
        this.streamScan(id);
      } catch (e) {
        this.pushLine("error: " + e.message, "err");
        this.busy = false;
      }
    },
    async runHistory() {
      if (this.busy) return;
      this.busy = true; this.liveLines = []; this.findings = [];
      // Remember the prior scan's counts for an honest "vs last" delta.
      if (this.lastScanAt) this.prevSummary = { ...this.summary };
      this.summary = { critical: 0, high: 0, medium: 0, low: 0 };
      this.screen = "live";
      try {
        const res = await fetch("/api/scan/history", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            path: this.historyPath || ".",
            max_commits: parseInt(this.historyMaxCommits, 10) || 100,
            since: this.historySince || null,
          }),
        });
        if (!res.ok) {
          const err = await res.json().catch(() => ({ detail: "history scan failed" }));
          this.pushLine("error: " + (err.detail || res.status), "err");
          this.busy = false; return;
        }
        const { id } = await res.json();
        this.jobId = id;
        this.streamScan(id);
      } catch (e) {
        this.pushLine("error: " + e.message, "err");
        this.busy = false;
      }
    },
    async runUrl() {
      if (this.busy) return;
      if (!this.urlTarget.trim()) { alert("enter a URL to scan"); return; }
      this.busy = true; this.liveLines = []; this.findings = [];
      // Remember the prior scan's counts for an honest "vs last" delta.
      if (this.lastScanAt) this.prevSummary = { ...this.summary };
      this.summary = { critical: 0, high: 0, medium: 0, low: 0 };
      this.screen = "live";
      try {
        const res = await fetch("/api/scan/url", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: this.urlTarget.trim(), crawl: this.urlCrawl }),
        });
        if (!res.ok) {
          const err = await res.json().catch(() => ({ detail: "url scan failed" }));
          this.pushLine("error: " + (err.detail || res.status), "err");
          this.busy = false; return;
        }
        const { id } = await res.json();
        this.jobId = id;
        this.streamScan(id);
      } catch (e) {
        this.pushLine("error: " + e.message, "err");
        this.busy = false;
      }
    },
    serverExport(fmt) {
      // SARIF/compliance are generated server-side (masked) from the last scan;
      // a plain GET lets the browser download the file directly.
      if (!this.jobId) { alert("run a scan first"); return; }
      window.location.href = "/api/scan/" + this.jobId + "/export?fmt=" + fmt;
    },
    streamScan(id) {
      const es = new EventSource("/api/scan/" + id + "/stream");
      es.onmessage = (ev) => {
        const txt = ev.data;
        let cls = "";
        if (/error|err:/i.test(txt)) cls = "err";
        else if (/complete|done|✓/i.test(txt)) cls = "ok";
        else if (/critical|high/i.test(txt)) cls = "warn";
        this.pushLine(txt, cls);
      };
      es.addEventListener("done", async () => {
        es.close();
        await this.loadFindings(id);
        this.busy = false;
      });
      es.onerror = () => { es.close(); this.busy = false; };
    },
    async loadFindings(id) {
      const res = await fetch("/api/scan/" + id + "/findings");
      const data = await res.json();
      this.findings = (data.findings || []).map(f => ({ ...f, _open: false }));
      this.summary = data.summary || this.summary;
      this.filesScanned = data.files_scanned || 0;
      this.filesFound = data.files_found || 0;
      this.lastScanAt = new Date().toTimeString().slice(0, 8);
    },
    pushLine(text, cls) {
      this.liveLines.push({ text, cls: cls || "" });
      this.$nextTick(() => {
        const t = this.$refs.term;
        if (t) t.scrollTop = t.scrollHeight;
      });
    },
    suppress(f) {
      this.baseline.push({
        reason: "Marked as false positive", type: f.type,
        file: f.file, line: f.line, fingerprint: f.detector,
      });
      this.findings = this.findings.filter(x => x !== f);
      this.recountSummary();
    },
    restore(i) {
      this.baseline.splice(i, 1);
    },
    recountSummary() {
      const s = { critical: 0, high: 0, medium: 0, low: 0 };
      this.findings.forEach(f => { if (s[f.severity] != null) s[f.severity]++; });
      this.summary = s;
    },
    exportData(fmt) {
      let blob;
      if (fmt === "json") {
        blob = new Blob([JSON.stringify(this.filtered, null, 2)], { type: "application/json" });
      } else {
        const rows = [["severity", "type", "file", "line", "masked", "confidence"]];
        this.filtered.forEach(f => rows.push([f.severity, f.type, f.file, f.line, f.masked, f.confidence]));
        blob = new Blob([rows.map(r => r.join(",")).join("\n")], { type: "text/csv" });
      }
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "credscan-findings." + fmt;
      a.click();
    },
    tick() {
      const d = new Date();
      this.clock = d.toTimeString().slice(0, 8);
    },
  },
  mounted() {
    this.tick();
    setInterval(this.tick, 1000);
    fetch("/api/health").then(r => r.json()).then(d => {
      if (d.status === "ok") this.enginePlaceholder = "ok";
    }).catch(() => { this.enginePlaceholder = "offline"; });
    fetch("/api/mode").then(r => r.json()).then(d => {
      this.publicMode = !!d.public;
      this.maxBytes = d.max_bytes || this.maxBytes;
      this.maxFiles = d.max_files || this.maxFiles;
    }).catch(() => {});
  },
}).mount("#app");
