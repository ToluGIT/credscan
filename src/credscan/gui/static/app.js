/* CredScan GUI - Vue 3 app wired to the FastAPI backend. */
const { createApp } = Vue;

createApp({
  data() {
    return {
      version: "1.0.1",
      engineStatus: "ENGINE ONLINE",
      screen: "dashboard",
      screens: [
        { id: "dashboard", label: "Dashboard" },
        { id: "config", label: "Scan Config" },
        { id: "live", label: "Live Output" },
        { id: "report", label: "Findings" },
        { id: "baseline", label: "Baseline" },
      ],
      scanPath: ".",
      minConfidencePct: 50,
      validateLive: false,
      opts: { no_context_analysis: false, no_entropy: false },
      quickActions: [
        { glyph: "▸", label: "SCAN DIR", path: "." },
        { glyph: "◆", label: "SCAN demo/", path: "demo" },
        { glyph: "⬢", label: "SCAN src/", path: "src" },
        { glyph: "▣", label: "SCAN tests/", path: "tests" },
      ],
      coverage: [
        { label: "paths", pct: 100 },
        { label: "git-history", pct: 100 },
        { label: "ci/cd", pct: 92 },
        { label: "dockerfiles", pct: 88 },
        { label: "web-endpoints", pct: 34 },
      ],
      busy: false,
      jobId: null,
      liveLines: [],
      findings: [],
      summary: { critical: 0, high: 0, medium: 0, low: 0 },
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
    statusWord() { return this.busy ? "● SCANNING" : (this.findings.length ? "● DONE" : "● READY"); },
    statusContext() {
      if (this.busy) return "scanning " + this.scanPath;
      if (this.findings.length) return this.filesScanned + " files · " + this.findings.length + " findings";
      return "idle · 1 worker · queue 0";
    },
    totalFindings() { return this.findings.length; },
    commandPreview() {
      let c = "credscan --path " + (this.scanPath || ".") + " --min-confidence " + this.minConfidence;
      if (this.opts.no_context_analysis) c += " --no-context-analysis";
      if (this.opts.no_entropy) c += " --no-entropy";
      if (this.validateLive) c += " --validate-aws --verify";
      return c + " -o sarif";
    },
    severityRows() {
      const colors = { critical: "#EF4444", high: "#F59E0B", medium: "#06B6D4", low: "#5C5C5C" };
      const max = Math.max(1, ...Object.values(this.summary));
      return ["critical", "high", "medium", "low"].map(k => ({
        key: k, label: k.toUpperCase(), count: this.summary[k] || 0,
        pct: Math.round(((this.summary[k] || 0) / max) * 100), color: colors[k],
      }));
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
    quick(qa) { this.scanPath = qa.path; this.runScan(); },
    filterBy(sev) { this.sevFilter = sev; this.screen = "report"; },
    resetConfig() {
      this.scanPath = "."; this.minConfidencePct = 50;
      this.validateLive = false; this.opts = { no_context_analysis: false, no_entropy: false };
    },
    async runScan() {
      if (this.busy) return;
      this.busy = true; this.liveLines = []; this.findings = [];
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
      if (d.status === "ok") this.engineStatus = "ENGINE ONLINE";
    }).catch(() => { this.engineStatus = "ENGINE OFFLINE"; });
  },
}).mount("#app");
