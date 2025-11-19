// server/index.ts
import express2 from "express";

// server/routes.ts
import { createServer } from "http";

// server/storage.ts
import { randomUUID } from "crypto";
var MemStorage = class {
  scans;
  uploadedFiles;
  vulnerabilities;
  scanProgress;
  constructor() {
    this.scans = /* @__PURE__ */ new Map();
    this.uploadedFiles = /* @__PURE__ */ new Map();
    this.vulnerabilities = /* @__PURE__ */ new Map();
    this.scanProgress = /* @__PURE__ */ new Map();
  }
  async createScan(insertScan) {
    const id = randomUUID();
    const scan = {
      status: "pending",
      totalFiles: 0,
      completedFiles: 0,
      ...insertScan,
      id,
      createdAt: /* @__PURE__ */ new Date(),
      updatedAt: /* @__PURE__ */ new Date()
    };
    this.scans.set(id, scan);
    return scan;
  }
  async getScan(id) {
    return this.scans.get(id);
  }
  async updateScan(id, updates) {
    const scan = this.scans.get(id);
    if (!scan) return void 0;
    const updatedScan = { ...scan, ...updates, updatedAt: /* @__PURE__ */ new Date() };
    this.scans.set(id, updatedScan);
    return updatedScan;
  }
  async getAllScans() {
    return Array.from(this.scans.values()).sort(
      (a, b) => b.createdAt.getTime() - a.createdAt.getTime()
    );
  }
  async createUploadedFile(insertFile) {
    const id = randomUUID();
    const file = {
      scanId: null,
      language: null,
      ...insertFile,
      id,
      createdAt: /* @__PURE__ */ new Date()
    };
    this.uploadedFiles.set(id, file);
    return file;
  }
  async getFilesByScanId(scanId) {
    return Array.from(this.uploadedFiles.values()).filter(
      (file) => file.scanId === scanId
    );
  }
  async getFile(id) {
    return this.uploadedFiles.get(id);
  }
  async createVulnerability(insertVulnerability) {
    const id = randomUUID();
    const vulnerability = {
      scanId: null,
      fileId: null,
      cweId: null,
      cveId: null,
      owaspCategory: null,
      suggestedFix: null,
      aiAnalysis: null,
      confidence: null,
      impact: null,
      exploitability: null,
      reviewed: null,
      ...insertVulnerability,
      id,
      createdAt: /* @__PURE__ */ new Date()
    };
    this.vulnerabilities.set(id, vulnerability);
    return vulnerability;
  }
  async getVulnerabilitiesByScanId(scanId) {
    return Array.from(this.vulnerabilities.values()).filter((vuln) => vuln.scanId === scanId).sort((a, b) => {
      const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
      return (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0);
    });
  }
  async getVulnerability(id) {
    return this.vulnerabilities.get(id);
  }
  async updateVulnerability(id, updates) {
    const vulnerability = this.vulnerabilities.get(id);
    if (!vulnerability) return void 0;
    const updatedVulnerability = { ...vulnerability, ...updates };
    this.vulnerabilities.set(id, updatedVulnerability);
    return updatedVulnerability;
  }
  async createScanProgress(insertProgress) {
    const id = randomUUID();
    const progress = {
      scanId: null,
      message: null,
      ...insertProgress,
      id,
      updatedAt: /* @__PURE__ */ new Date()
    };
    this.scanProgress.set(id, progress);
    return progress;
  }
  async getScanProgressByScanId(scanId) {
    return Array.from(this.scanProgress.values()).filter(
      (progress) => progress.scanId === scanId
    );
  }
  async updateScanProgress(scanId, stage, updates) {
    const existingProgress = Array.from(this.scanProgress.values()).find(
      (p) => p.scanId === scanId && p.stage === stage
    );
    if (!existingProgress) return void 0;
    const updatedProgress = { ...existingProgress, ...updates, updatedAt: /* @__PURE__ */ new Date() };
    this.scanProgress.set(existingProgress.id, updatedProgress);
    return updatedProgress;
  }
};
var storage = new MemStorage();

// shared/schema.ts
import { sql } from "drizzle-orm";
import { pgTable, text, varchar, integer, timestamp, boolean } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";
var scans = pgTable("scans", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  status: text("status").notNull().default("pending"),
  // pending, scanning, completed, failed
  totalFiles: integer("total_files").default(0),
  completedFiles: integer("completed_files").default(0),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow()
});
var uploadedFiles = pgTable("uploaded_files", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  scanId: varchar("scan_id").references(() => scans.id),
  filename: text("filename").notNull(),
  filepath: text("filepath").notNull(),
  size: integer("size").notNull(),
  language: text("language"),
  createdAt: timestamp("created_at").defaultNow()
});
var vulnerabilities = pgTable("vulnerabilities", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  scanId: varchar("scan_id").references(() => scans.id),
  fileId: varchar("file_id").references(() => uploadedFiles.id),
  filename: text("filename").notNull(),
  lineNumber: integer("line_number").notNull(),
  vulnerabilityType: text("vulnerability_type").notNull(),
  severity: text("severity").notNull(),
  // critical, high, medium, low
  cweId: text("cwe_id"),
  cveId: text("cve_id"),
  owaspCategory: text("owasp_category"),
  description: text("description").notNull(),
  codeSnippet: text("code_snippet").notNull(),
  suggestedFix: text("suggested_fix"),
  aiAnalysis: text("ai_analysis"),
  aiModelUsed: text("ai_model_used"),
  confidence: integer("confidence").default(0),
  // 0-100
  detectionTool: text("detection_tool").notNull(),
  impact: text("impact"),
  exploitability: text("exploitability"),
  reviewed: boolean("reviewed").default(false),
  createdAt: timestamp("created_at").defaultNow()
});
var scanProgress = pgTable("scan_progress", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  scanId: varchar("scan_id").references(() => scans.id),
  stage: text("stage").notNull(),
  // static_analysis, ai_analysis, cve_mapping
  status: text("status").notNull(),
  // pending, running, completed, failed
  message: text("message"),
  updatedAt: timestamp("updated_at").defaultNow()
});
var insertScanSchema = createInsertSchema(scans).omit({
  id: true,
  createdAt: true,
  updatedAt: true
});
var insertUploadedFileSchema = createInsertSchema(uploadedFiles).omit({
  id: true,
  createdAt: true
});
var insertVulnerabilitySchema = createInsertSchema(vulnerabilities).omit({
  id: true,
  createdAt: true
});
var insertScanProgressSchema = createInsertSchema(scanProgress).omit({
  id: true,
  updatedAt: true
});
var scanResultSchema = z.object({
  scan: z.object({
    id: z.string(),
    status: z.string(),
    totalFiles: z.number(),
    completedFiles: z.number(),
    createdAt: z.string()
  }),
  vulnerabilities: z.array(z.object({
    id: z.string(),
    filename: z.string(),
    lineNumber: z.number(),
    vulnerabilityType: z.string(),
    severity: z.string(),
    cweId: z.string().nullable(),
    cveId: z.string().nullable(),
    description: z.string(),
    confidence: z.number(),
    detectionTool: z.string()
  })),
  progress: z.array(z.object({
    stage: z.string(),
    status: z.string(),
    message: z.string().nullable()
  }))
});

// server/routes.ts
import multer from "multer";
import path from "path";
import fs from "fs";
import { spawn } from "child_process";
import { fileURLToPath } from "url";
import { dirname } from "path";
var __filename = fileURLToPath(import.meta.url);
var __dirname = dirname(__filename);
var multerStorage = multer.diskStorage({
  destination: function(req, file, cb) {
    cb(null, "uploads/");
  },
  filename: function(req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname);
    cb(null, file.fieldname + "-" + uniqueSuffix + ext);
  }
});
var upload = multer({
  storage: multerStorage,
  limits: {
    fileSize: 50 * 1024 * 1024
    // 50MB limit
  }
});
async function registerRoutes(app2) {
  app2.post("/api/scans", async (req, res) => {
    try {
      const scanData = insertScanSchema.parse(req.body);
      const scan = await storage.createScan(scanData);
      await storage.createScanProgress({
        scanId: scan.id,
        stage: "static_analysis",
        status: "pending",
        message: "Preparing static analysis..."
      });
      await storage.createScanProgress({
        scanId: scan.id,
        stage: "ai_analysis",
        status: "pending",
        message: "Waiting for static analysis completion..."
      });
      await storage.createScanProgress({
        scanId: scan.id,
        stage: "cve_mapping",
        status: "pending",
        message: "Waiting for vulnerability detection..."
      });
      res.json(scan);
    } catch (error) {
      res.status(400).json({ error: "Invalid scan data" });
    }
  });
  app2.post("/api/scans/:scanId/upload", upload.array("files", 10), async (req, res) => {
    try {
      const { scanId } = req.params;
      const files = req.files;
      console.log("Upload request received for scan:", scanId);
      console.log("Files received:", files?.length || 0);
      console.log("Request files:", req.files);
      if (!files || files.length === 0) {
        console.log("No files in request");
        return res.status(400).json({ error: "No files uploaded" });
      }
      const scan = await storage.getScan(scanId);
      if (!scan) {
        return res.status(404).json({ error: "Scan not found" });
      }
      const uploadedFiles2 = [];
      for (const file of files) {
        const language = getLanguageFromExtension(file.originalname);
        const uploadedFile = await storage.createUploadedFile({
          scanId,
          filename: file.originalname,
          filepath: file.path,
          size: file.size,
          language
        });
        uploadedFiles2.push(uploadedFile);
      }
      await storage.updateScan(scanId, {
        totalFiles: uploadedFiles2.length,
        status: "ready"
      });
      res.json({ files: uploadedFiles2 });
    } catch (error) {
      console.error("File upload error:", error);
      res.status(500).json({ error: "File upload failed" });
    }
  });
  app2.post("/api/scans/:scanId/start", async (req, res) => {
    try {
      const { scanId } = req.params;
      const scan = await storage.getScan(scanId);
      if (!scan) {
        return res.status(404).json({ error: "Scan not found" });
      }
      await storage.updateScan(scanId, { status: "scanning" });
      startScanningProcess(scanId);
      res.json({ message: "Scan started", scanId });
    } catch (error) {
      console.error("Start scan error:", error);
      res.status(500).json({ error: "Failed to start scan" });
    }
  });
  app2.get("/api/scans/:scanId", async (req, res) => {
    try {
      const { scanId } = req.params;
      const scan = await storage.getScan(scanId);
      if (!scan) {
        return res.status(404).json({ error: "Scan not found" });
      }
      const vulnerabilities2 = await storage.getVulnerabilitiesByScanId(scanId);
      const progress = await storage.getScanProgressByScanId(scanId);
      const result = {
        scan: {
          id: scan.id,
          status: scan.status,
          totalFiles: scan.totalFiles || 0,
          completedFiles: scan.completedFiles || 0,
          createdAt: scan.createdAt?.toISOString() || ""
        },
        vulnerabilities: vulnerabilities2.map((v) => ({
          id: v.id,
          filename: v.filename,
          lineNumber: v.lineNumber,
          vulnerabilityType: v.vulnerabilityType,
          severity: v.severity,
          cweId: v.cweId,
          cveId: v.cveId,
          description: v.description,
          confidence: v.confidence || 0,
          detectionTool: v.detectionTool
        })),
        progress: progress.map((p) => ({
          stage: p.stage,
          status: p.status,
          message: p.message
        }))
      };
      res.json(result);
    } catch (error) {
      console.error("Get scan error:", error);
      res.status(500).json({ error: "Failed to get scan results" });
    }
  });
  app2.get("/api/vulnerabilities/:vulnerabilityId", async (req, res) => {
    try {
      const { vulnerabilityId } = req.params;
      const vulnerability = await storage.getVulnerability(vulnerabilityId);
      if (!vulnerability) {
        return res.status(404).json({ error: "Vulnerability not found" });
      }
      res.json(vulnerability);
    } catch (error) {
      console.error("Get vulnerability error:", error);
      res.status(500).json({ error: "Failed to get vulnerability details" });
    }
  });
  app2.patch("/api/vulnerabilities/:vulnerabilityId/review", async (req, res) => {
    try {
      const { vulnerabilityId } = req.params;
      const updated = await storage.updateVulnerability(vulnerabilityId, {
        reviewed: true
      });
      if (!updated) {
        return res.status(404).json({ error: "Vulnerability not found" });
      }
      res.json(updated);
    } catch (error) {
      console.error("Review vulnerability error:", error);
      res.status(500).json({ error: "Failed to mark vulnerability as reviewed" });
    }
  });
  app2.post("/api/scans/:scanId/report", async (req, res) => {
    try {
      const { scanId } = req.params;
      const { format, sections, severityFilter } = req.body;
      const scan = await storage.getScan(scanId);
      if (!scan) {
        return res.status(404).json({ error: "Scan not found" });
      }
      const vulnerabilities2 = await storage.getVulnerabilitiesByScanId(scanId);
      const reportData = {
        scan,
        vulnerabilities: vulnerabilities2,
        format: format || "pdf",
        sections: sections || ["executive_summary", "vulnerability_details", "ai_recommendations"],
        severityFilter: severityFilter || "all"
      };
      const config = {
        format: format || "pdf",
        sections: sections || ["executive_summary", "vulnerability_details", "ai_recommendations"],
        severityFilter: severityFilter || "all",
        includeCode: req.body.includeCode !== false
      };
      const pythonResult = await runPythonReportGenerator(scanId, scan, vulnerabilities2, config);
      if (pythonResult.reportPath) {
        const filename = path.basename(pythonResult.reportPath);
        res.json({
          reportId: `report_${scanId}_${Date.now()}`,
          downloadUrl: `/api/reports/download/${scanId}`,
          filename,
          format: config.format,
          generatedAt: (/* @__PURE__ */ new Date()).toISOString()
        });
      } else {
        console.error("Report generator failed", pythonResult.stderr);
        res.status(500).json({ error: "Report generation failed", details: pythonResult.stderr || pythonResult.stdout });
      }
    } catch (error) {
      console.error("Generate report error:", error);
      res.status(500).json({ error: "Failed to generate report" });
    }
  });
  app2.get("/api/reports/download/:scanId", async (req, res) => {
    try {
      const { scanId } = req.params;
      const reportsDir = path.join(__dirname, "..", "reports");
      if (!fs.existsSync(reportsDir)) return res.status(404).json({ error: "No reports available" });
      const files = fs.readdirSync(reportsDir).filter((f) => f.startsWith(`security_report_${scanId}_`));
      if (!files || files.length === 0) return res.status(404).json({ error: "Report not found" });
      files.sort();
      const fileToSend = files[files.length - 1];
      const fullPath = path.join(reportsDir, fileToSend);
      return res.sendFile(fullPath);
    } catch (err) {
      console.error("Report download error:", err);
      return res.status(500).json({ error: "Failed to download report" });
    }
  });
  app2.get("/api/scans", async (req, res) => {
    try {
      const scans2 = await storage.getAllScans();
      res.json(scans2);
    } catch (error) {
      console.error("Get scans error:", error);
      res.status(500).json({ error: "Failed to get scans" });
    }
  });
  app2.post("/api/scans/:scanId/debug-run", async (req, res) => {
    try {
      const { scanId } = req.params;
      const scan = await storage.getScan(scanId);
      if (!scan) return res.status(404).json({ error: "Scan not found" });
      const files = await storage.getFilesByScanId(scanId);
      if (!files || files.length === 0) return res.status(400).json({ error: "No uploaded files found for this scan" });
      const filePaths = files.map((f) => f.filepath);
      const raw = await runPythonScannerRaw(scanId, filePaths);
      let parsed = [];
      try {
        if (raw.stdout && raw.stdout.trim().length > 0) {
          parsed = JSON.parse(raw.stdout);
        } else if (raw.stderr && raw.stderr.trim().length > 0) {
          parsed = JSON.parse(raw.stderr);
        }
      } catch (e) {
      }
      res.json({ success: true, raw, parsed });
    } catch (error) {
      console.error("Debug-run error:", error);
      res.status(500).json({ success: false, error: String(error) });
    }
  });
  const httpServer = createServer(app2);
  return httpServer;
}
function getLanguageFromExtension(filename) {
  const ext = path.extname(filename).toLowerCase();
  const languageMap = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".java": "java",
    ".cpp": "cpp",
    ".c": "c",
    ".cs": "csharp",
    ".rb": "ruby",
    ".php": "php",
    ".go": "go",
    ".rs": "rust"
  };
  return languageMap[ext] || "unknown";
}
async function runPythonScanner(scanId, filePaths) {
  return new Promise((resolve, reject) => {
    const pythonScript = path.join(__dirname, "services", "scanner.py");
    const args = [pythonScript, scanId, ...filePaths];
    console.log(`Running Python scanner: python ${args.join(" ")}`);
    const pythonProcess = spawn("python", args);
    let stdout = "";
    let stderr = "";
    pythonProcess.stdout.on("data", (data) => {
      stdout += data.toString();
    });
    pythonProcess.stderr.on("data", (data) => {
      stderr += data.toString();
      console.error("Scanner stderr:", data.toString());
    });
    pythonProcess.on("close", (code) => {
      if (code === 0) {
        try {
          const results = JSON.parse(stdout);
          console.log("Scanner results parsed:", results.length, "vulnerabilities");
          resolve(results);
        } catch (error) {
          console.error("Failed to parse scanner output:", stdout);
          reject(new Error(`Failed to parse scanner output: ${error}`));
        }
      } else {
        console.error(`Scanner process exited with code ${code}`);
        console.error("Scanner stderr:", stderr);
        reject(new Error(`Scanner failed with exit code ${code}: ${stderr}`));
      }
    });
    pythonProcess.on("error", (error) => {
      console.error("Failed to start scanner:", error);
      reject(error);
    });
  });
}
async function runPythonScannerRaw(scanId, filePaths) {
  return new Promise((resolve, reject) => {
    const pythonScript = path.join(__dirname, "services", "scanner.py");
    const args = [pythonScript, scanId, ...filePaths];
    console.log(`Running Python scanner (raw): python ${args.join(" ")}`);
    const pythonProcess = spawn("python", args);
    let stdout = "";
    let stderr = "";
    let exitCode = null;
    pythonProcess.stdout.on("data", (data) => {
      const s = data.toString();
      stdout += s;
      console.log("scanner stdout chunk:", s);
    });
    pythonProcess.stderr.on("data", (data) => {
      const s = data.toString();
      stderr += s;
      console.error("scanner stderr chunk:", s);
    });
    pythonProcess.on("close", (code) => {
      exitCode = code;
      resolve({ code: exitCode, stdout, stderr });
    });
    pythonProcess.on("error", (error) => {
      console.error("Failed to start scanner (raw):", error);
      reject(error);
    });
  });
}
async function runPythonReportGenerator(scanId, scan, vulnerabilities2, config) {
  return new Promise((resolve, reject) => {
    const pythonScript = path.join(__dirname, "services", "report_generator.py");
    const args = [pythonScript, JSON.stringify({ scan, vulnerabilities: vulnerabilities2 }), JSON.stringify(config)];
    console.log(`Running Python report generator: python ${args.join(" ")}`);
    const pythonProcess = spawn("python", args);
    let stdout = "";
    let stderr = "";
    let exitCode = null;
    pythonProcess.stdout.on("data", (data) => {
      const s = data.toString();
      stdout += s;
      console.log("report stdout chunk:", s);
    });
    pythonProcess.stderr.on("data", (data) => {
      const s = data.toString();
      stderr += s;
      console.error("report stderr chunk:", s);
    });
    pythonProcess.on("close", (code) => {
      exitCode = code;
      let reportPath = void 0;
      try {
        if (stdout && stdout.trim().length > 0) {
          const parsed = JSON.parse(stdout);
          reportPath = parsed.report_path || parsed.reportPath || parsed.report_path || void 0;
        }
      } catch (e) {
      }
      resolve({ code: exitCode, stdout, stderr, reportPath });
    });
    pythonProcess.on("error", (error) => {
      console.error("Failed to start report generator:", error);
      reject(error);
    });
  });
}
async function startScanningProcess(scanId) {
  try {
    console.log("Starting scanning process for scan:", scanId);
    const files = await storage.getFilesByScanId(scanId);
    if (files.length === 0) {
      throw new Error("No files to scan");
    }
    await storage.updateScanProgress(scanId, "static_analysis", {
      status: "running",
      message: "Running Semgrep and Bandit analysis..."
    });
    const filePaths = files.map((f) => f.filepath);
    const scanResults = await runPythonScanner(scanId, filePaths);
    console.log(`Scanner found ${scanResults.length} vulnerabilities`);
    for (const result of scanResults) {
      const file = files.find((f) => f.filename === result.filename || path.basename(f.filepath) === result.filename);
      await storage.createVulnerability({
        scanId,
        fileId: file?.id || null,
        filename: result.filename,
        lineNumber: result.line_number || 0,
        vulnerabilityType: result.vulnerability_type,
        severity: result.severity,
        cweId: result.cwe_id || "",
        owaspCategory: "",
        description: result.description,
        codeSnippet: result.code_snippet || "",
        suggestedFix: "",
        aiAnalysis: "",
        confidence: result.confidence || 85,
        detectionTool: result.detection_tool,
        impact: "",
        exploitability: "",
        reviewed: false
      });
    }
    await storage.updateScanProgress(scanId, "static_analysis", {
      status: "completed",
      message: `Static analysis completed - found ${scanResults.length} vulnerabilities`
    });
    await storage.updateScanProgress(scanId, "ai_analysis", {
      status: "running",
      message: "Analyzing with AI models..."
    });
    await new Promise((resolve) => setTimeout(resolve, 2e3));
    await addAIAnalysisToVulnerabilities(scanId);
    await storage.updateScanProgress(scanId, "ai_analysis", {
      status: "completed",
      message: "AI analysis completed"
    });
    await storage.updateScanProgress(scanId, "cve_mapping", {
      status: "running",
      message: "Mapping to CVE database..."
    });
    await new Promise((resolve) => setTimeout(resolve, 1e3));
    await storage.updateScanProgress(scanId, "cve_mapping", {
      status: "completed",
      message: "CVE mapping completed"
    });
    await storage.updateScan(scanId, {
      status: "completed",
      completedFiles: files.length
    });
    console.log("Scanning process completed for scan:", scanId);
  } catch (error) {
    console.error("Scanning process error:", error);
    await storage.updateScan(scanId, { status: "failed" });
    await storage.updateScanProgress(scanId, "static_analysis", {
      status: "failed",
      message: `Scan failed: ${error instanceof Error ? error.message : "Unknown error"}`
    });
  }
}
async function addAIAnalysisToVulnerabilities(scanId) {
  const vulnerabilities2 = await storage.getVulnerabilitiesByScanId(scanId);
  console.log("Adding AI analysis to", vulnerabilities2.length, "vulnerabilities");
  for (const vuln of vulnerabilities2) {
    try {
      const pythonScript = path.join(__dirname, "services", "ai_analyzer.py");
      const args = [pythonScript, JSON.stringify(vuln)];
      console.log(`Running AI analyzer: python ${args.join(" ")}`);
      const pythonProcess = spawn("python", args);
      let stdout = "";
      let stderr = "";
      pythonProcess.stdout.on("data", (data) => {
        stdout += data.toString();
      });
      pythonProcess.stderr.on("data", (data) => {
        stderr += data.toString();
        console.error("AI stderr:", data.toString());
      });
      const exitCode = await new Promise((resolve) => {
        pythonProcess.on("close", (code) => resolve(code ?? 0));
      });
      if (exitCode === 0) {
        try {
          const analysisResult = JSON.parse(stdout || "{}");
          await storage.updateVulnerability(vuln.id, {
            aiAnalysis: analysisResult.ai_analysis || vuln.aiAnalysis || "",
            suggestedFix: analysisResult.suggested_fix || vuln.suggestedFix || "",
            confidence: analysisResult.confidence || vuln.confidence || 80,
            aiModelUsed: analysisResult.ai_model_used || vuln.aiModelUsed || "unknown"
          });
        } catch (e) {
          console.error("Failed to parse AI analyzer output:", e, stdout, stderr);
        }
      } else {
        console.error("AI analyzer exited with code", exitCode, "stderr:", stderr);
      }
    } catch (err) {
      console.error("Error running AI analysis for vuln", vuln.id, err);
    }
  }
}

// server/vite.ts
import express from "express";
import fs2 from "fs";
import path3 from "path";
import { createServer as createViteServer, createLogger } from "vite";

// vite.config.ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path2 from "path";
import runtimeErrorOverlay from "@replit/vite-plugin-runtime-error-modal";
var vite_config_default = defineConfig({
  plugins: [
    react(),
    runtimeErrorOverlay(),
    ...process.env.NODE_ENV !== "production" && process.env.REPL_ID !== void 0 ? [
      await import("@replit/vite-plugin-cartographer").then(
        (m) => m.cartographer()
      )
    ] : []
  ],
  resolve: {
    alias: {
      "@": path2.resolve(import.meta.dirname, "client", "src"),
      "@shared": path2.resolve(import.meta.dirname, "shared"),
      "@assets": path2.resolve(import.meta.dirname, "attached_assets")
    }
  },
  root: path2.resolve(import.meta.dirname, "client"),
  build: {
    outDir: path2.resolve(import.meta.dirname, "dist/public"),
    emptyOutDir: true
  },
  server: {
    fs: {
      strict: true,
      deny: ["**/.*"]
    }
  }
});

// server/vite.ts
import { nanoid } from "nanoid";
var viteLogger = createLogger();
function log(message, source = "express") {
  const formattedTime = (/* @__PURE__ */ new Date()).toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true
  });
  console.log(`${formattedTime} [${source}] ${message}`);
}
async function setupVite(app2, server) {
  const serverOptions = {
    middlewareMode: true,
    hmr: { server },
    allowedHosts: true
  };
  const vite = await createViteServer({
    ...vite_config_default,
    configFile: false,
    customLogger: {
      ...viteLogger,
      error: (msg, options) => {
        viteLogger.error(msg, options);
        process.exit(1);
      }
    },
    server: serverOptions,
    appType: "custom"
  });
  app2.use(vite.middlewares);
  app2.use("*", async (req, res, next) => {
    const url = req.originalUrl;
    try {
      const clientTemplate = path3.resolve(
        import.meta.dirname,
        "..",
        "client",
        "index.html"
      );
      let template = await fs2.promises.readFile(clientTemplate, "utf-8");
      template = template.replace(
        `src="/src/main.tsx"`,
        `src="/src/main.tsx?v=${nanoid()}"`
      );
      const page = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(page);
    } catch (e) {
      vite.ssrFixStacktrace(e);
      next(e);
    }
  });
}
function serveStatic(app2) {
  const distPath = path3.resolve(import.meta.dirname, "public");
  if (!fs2.existsSync(distPath)) {
    throw new Error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`
    );
  }
  app2.use(express.static(distPath));
  app2.use("*", (_req, res) => {
    res.sendFile(path3.resolve(distPath, "index.html"));
  });
}

// server/index.ts
var app = express2();
app.use(express2.json());
app.use(express2.urlencoded({ extended: false }));
app.use((req, res, next) => {
  const start = Date.now();
  const path4 = req.path;
  let capturedJsonResponse = void 0;
  const originalResJson = res.json;
  res.json = function(bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };
  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path4.startsWith("/api")) {
      let logLine = `${req.method} ${path4} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }
      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "\u2026";
      }
      log(logLine);
    }
  });
  next();
});
(async () => {
  const server = await registerRoutes(app);
  app.use((err, _req, res, _next) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";
    res.status(status).json({ message });
    throw err;
  });
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }
  const port = parseInt(process.env.PORT || "3000", 10);
  server.on("error", (err) => {
    if (err && err.code === "EADDRINUSE") {
      log(`port ${port} is in use (EADDRINUSE). Attempting fallback bind to 127.0.0.1:${port}...`);
      server.listen({ port, host: "127.0.0.1" }, () => {
        log(`serving on port ${port} (127.0.0.1 fallback)`);
      }).on("error", (err2) => {
        log(`failed to bind to 127.0.0.1:${port}: ${err2?.message || err2}`);
        log("Please ensure no other process is using the port (use `netstat -ano | findstr :3000`), then retry.");
        process.exit(1);
      });
      return;
    }
    throw err;
  });
  server.listen({ port }, () => {
    log(`serving on port ${port}`);
  });
})();
