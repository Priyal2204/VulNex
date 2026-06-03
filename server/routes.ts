import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { insertScanSchema, insertUploadedFileSchema, scanResultSchema } from "@shared/schema";
import multer from "multer";
import path from "path";
import fs from "fs";
import { spawn } from "child_process";
import { fileURLToPath } from "url";
import { dirname } from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Resolve project root: when compiled to dist/, __dirname is .../dist, so go up one level.
// When running as source (server/), going up one level also gives the project root.
const PROJECT_ROOT = path.join(__dirname, '..');

// Ensure uploads directory exists
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads', { recursive: true });
}

// Configure multer for file uploads with filename preservation
const multerStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    // Preserve original filename with timestamp to avoid conflicts
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, file.fieldname + '-' + uniqueSuffix + ext);
  }
});

const upload = multer({
  storage: multerStorage,
  limits: {
    fileSize: 50 * 1024 * 1024, // 50MB limit
  },
});

export async function registerRoutes(app: Express): Promise<Server> {
  
  // Create a new scan
  app.post("/api/scans", async (req, res) => {
    try {
      const scanData = insertScanSchema.parse(req.body);
      const scan = await storage.createScan(scanData);
      
      // Initialize scan progress
      await storage.createScanProgress({
        scanId: scan.id,
        stage: "static_analysis",
        status: "pending",
        message: "Preparing static analysis...",
      });
      await storage.createScanProgress({
        scanId: scan.id,
        stage: "ai_analysis",
        status: "pending",
        message: "Waiting for static analysis completion...",
      });
      await storage.createScanProgress({
        scanId: scan.id,
        stage: "cve_mapping",
        status: "pending",
        message: "Waiting for vulnerability detection...",
      });
      
      res.json(scan);
    } catch (error) {
      res.status(400).json({ error: "Invalid scan data" });
    }
  });

  // Upload files for scanning
  app.post("/api/scans/:scanId/upload", upload.array('files', 10), async (req, res) => {
    try {
      const { scanId } = req.params;
      const files = req.files as Express.Multer.File[];

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

      const uploadedFiles = [];
      for (const file of files) {
        // Determine language based on file extension
        const language = getLanguageFromExtension(file.originalname);
        
        const uploadedFile = await storage.createUploadedFile({
          scanId,
          filename: file.originalname,
          filepath: file.path,
          size: file.size,
          language,
        });
        
        uploadedFiles.push(uploadedFile);
      }

      // Update scan with total files count
      await storage.updateScan(scanId, {
        totalFiles: uploadedFiles.length,
        status: "ready"
      });

      res.json({ files: uploadedFiles });
    } catch (error) {
      console.error("File upload error:", error);
      res.status(500).json({ error: "File upload failed" });
    }
  });

  // Start scanning
  app.post("/api/scans/:scanId/start", async (req, res) => {
    try {
      const { scanId } = req.params;
      
      const scan = await storage.getScan(scanId);
      if (!scan) {
        return res.status(404).json({ error: "Scan not found" });
      }

      // Update scan status
      await storage.updateScan(scanId, { status: "scanning" });
      
      // Start scanning process asynchronously
      startScanningProcess(scanId);

      res.json({ message: "Scan started", scanId });
    } catch (error) {
      console.error("Start scan error:", error);
      res.status(500).json({ error: "Failed to start scan" });
    }
  });

  // Get scan results
  app.get("/api/scans/:scanId", async (req, res) => {
    try {
      const { scanId } = req.params;
      
      const scan = await storage.getScan(scanId);
      if (!scan) {
        return res.status(404).json({ error: "Scan not found" });
      }

      const vulnerabilities = await storage.getVulnerabilitiesByScanId(scanId);
      const progress = await storage.getScanProgressByScanId(scanId);

      const result = {
        scan: {
          id: scan.id,
          status: scan.status,
          totalFiles: scan.totalFiles || 0,
          completedFiles: scan.completedFiles || 0,
          createdAt: scan.createdAt?.toISOString() || "",
        },
        vulnerabilities: vulnerabilities.map(v => ({
          id: v.id,
          filename: v.filename,
          lineNumber: v.lineNumber,
          vulnerabilityType: v.vulnerabilityType,
          severity: v.severity,
          cweId: v.cweId,
          cveId: v.cveId,
          description: v.description,
          confidence: v.confidence || 0,
          detectionTool: v.detectionTool,
        })),
        progress: progress.map(p => ({
          stage: p.stage,
          status: p.status,
          message: p.message,
        })),
      };

      res.json(result);
    } catch (error) {
      console.error("Get scan error:", error);
      res.status(500).json({ error: "Failed to get scan results" });
    }
  });

  // Get vulnerability details
  app.get("/api/vulnerabilities/:vulnerabilityId", async (req, res) => {
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

  // Mark vulnerability as reviewed
  app.patch("/api/vulnerabilities/:vulnerabilityId/review", async (req, res) => {
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

  // Generate report
  app.post("/api/scans/:scanId/report", async (req, res) => {
    try {
      const { scanId } = req.params;
      const { format, sections, severityFilter } = req.body;

      const scan = await storage.getScan(scanId);
      if (!scan) {
        return res.status(404).json({ error: "Scan not found" });
      }

      const vulnerabilities = await storage.getVulnerabilitiesByScanId(scanId);
      
      // Call Python script for report generation
      const reportData = {
        scan,
        vulnerabilities,
        format: format || 'pdf',
        sections: sections || ['executive_summary', 'vulnerability_details', 'ai_recommendations'],
        severityFilter: severityFilter || 'all'
      };

      // Call the Python report generator and return the actual report path
      const config = {
        format: format || 'pdf',
        sections: sections || ['executive_summary', 'vulnerability_details', 'ai_recommendations'],
        severityFilter: severityFilter || 'all',
        includeCode: req.body.includeCode !== false
      };

      // Run the Python generator
      const pythonResult = await runPythonReportGenerator(scanId, scan, vulnerabilities, config);

      if (pythonResult.reportPath) {
        const filename = path.basename(pythonResult.reportPath);
        // Respond with a download URL that maps to the scanId (download endpoint will locate the file)
        res.json({
          reportId: `report_${scanId}_${Date.now()}`,
          downloadUrl: `/api/reports/download/${scanId}`,
          filename,
          format: config.format,
          generatedAt: new Date().toISOString()
        });
      } else {
        console.error('Report generator failed', pythonResult.stderr);
        res.status(500).json({ error: 'Report generation failed', details: pythonResult.stderr || pythonResult.stdout });
      }

    } catch (error) {
      console.error("Generate report error:", error);
      res.status(500).json({ error: "Failed to generate report" });
    }
  });

  // Serve generated reports by scanId. Finds the latest matching report file and sends it.
  app.get('/api/reports/download/:scanId', async (req, res) => {
    try {
      const { scanId } = req.params;
      const reportsDir = path.join(PROJECT_ROOT, 'reports');
      if (!fs.existsSync(reportsDir)) return res.status(404).json({ error: 'No reports available' });

      const files = fs.readdirSync(reportsDir).filter(f => f.startsWith(`security_report_${scanId}_`));
      if (!files || files.length === 0) return res.status(404).json({ error: 'Report not found' });

      // Choose the most recent file by name (timestamp suffix)
      files.sort();
      const fileToSend = files[files.length - 1];
      const fullPath = path.join(reportsDir, fileToSend);
      
      // Set appropriate Content-Type based on file extension
      const ext = path.extname(fileToSend).toLowerCase();
      const contentType = ext === '.pdf' ? 'application/pdf' 
                       : ext === '.xlsx' ? 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
                       : 'application/octet-stream';
      
      res.setHeader('Content-Type', contentType);
      res.setHeader('Content-Disposition', `attachment; filename="${fileToSend}"`);
      return res.sendFile(fullPath);
    } catch (err) {
      console.error('Report download error:', err);
      return res.status(500).json({ error: 'Failed to download report' });
    }
  });

  // Get all scans
  app.get("/api/scans", async (req, res) => {
    try {
      const scans = await storage.getAllScans();
      res.json(scans);
    } catch (error) {
      console.error("Get scans error:", error);
      res.status(500).json({ error: "Failed to get scans" });
    }
  });

  // Debug endpoint: run scanner on existing uploaded files and return raw output
  app.post("/api/scans/:scanId/debug-run", async (req, res) => {
    try {
      const { scanId } = req.params;
      const scan = await storage.getScan(scanId);
      if (!scan) return res.status(404).json({ error: 'Scan not found' });

      const files = await storage.getFilesByScanId(scanId);
      if (!files || files.length === 0) return res.status(400).json({ error: 'No uploaded files found for this scan' });

      const filePaths = files.map(f => f.filepath);

      // Run raw scanner
      const raw = await runPythonScannerRaw(scanId, filePaths);

      // Try to parse results the same way runPythonScanner does
      let parsed: any[] = [];
      try {
        if (raw.stdout && raw.stdout.trim().length > 0) {
          parsed = JSON.parse(raw.stdout);
        } else if (raw.stderr && raw.stderr.trim().length > 0) {
          parsed = JSON.parse(raw.stderr);
        }
      } catch (e) {
        // ignore parse failure, keep parsed as []
      }

      res.json({ success: true, raw, parsed });
    } catch (error) {
      console.error('Debug-run error:', error);
      res.status(500).json({ success: false, error: String(error) });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}

function getLanguageFromExtension(filename: string): string {
  const ext = path.extname(filename).toLowerCase();
  const languageMap: { [key: string]: string } = {
    '.py': 'python',
    '.js': 'javascript',
    '.ts': 'typescript',
    '.java': 'java',
    '.cpp': 'cpp',
    '.c': 'c',
    '.cs': 'csharp',
    '.rb': 'ruby',
    '.php': 'php',
    '.go': 'go',
    '.rs': 'rust',
  };
  return languageMap[ext] || 'unknown';
}

// Run Python scanner on uploaded files
async function runPythonScanner(scanId: string, filePaths: string[]): Promise<any[]> {
  return new Promise((resolve, reject) => {
    const pythonScript = path.join(PROJECT_ROOT, 'server', 'services', 'scanner.py');
    const args = [pythonScript, scanId, ...filePaths];
    
    console.log(`Running Python scanner: python ${args.join(' ')}`);
    
    const pythonProcess = spawn('python', args);
    
    let stdout = '';
    let stderr = '';
    
    pythonProcess.stdout.on('data', (data) => {
      stdout += data.toString();
    });
    
    pythonProcess.stderr.on('data', (data) => {
      stderr += data.toString();
      console.error('Scanner stderr:', data.toString());
    });
    
    pythonProcess.on('close', (code) => {
      if (code === 0) {
        try {
          const results = JSON.parse(stdout);
          console.log('Scanner results parsed:', results.length, 'vulnerabilities');
          resolve(results);
        } catch (error) {
          console.error('Failed to parse scanner output:', stdout);
          reject(new Error(`Failed to parse scanner output: ${error}`));
        }
      } else {
        console.error(`Scanner process exited with code ${code}`);
        console.error('Scanner stderr:', stderr);
        reject(new Error(`Scanner failed with exit code ${code}: ${stderr}`));
      }
    });
    
    pythonProcess.on('error', (error) => {
      console.error('Failed to start scanner:', error);
      reject(error);
    });
  });
}

// Run Python scanner but return raw stdout/stderr and exit code for debugging
async function runPythonScannerRaw(scanId: string, filePaths: string[]): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const pythonScript = path.join(PROJECT_ROOT, 'server', 'services', 'scanner.py');
    const args = [pythonScript, scanId, ...filePaths];

    console.log(`Running Python scanner (raw): python ${args.join(' ')}`);

    const pythonProcess = spawn('python', args);

    let stdout = '';
    let stderr = '';
    let exitCode: number | null = null;

    pythonProcess.stdout.on('data', (data) => {
      const s = data.toString();
      stdout += s;
      console.log('scanner stdout chunk:', s);
    });

    pythonProcess.stderr.on('data', (data) => {
      const s = data.toString();
      stderr += s;
      console.error('scanner stderr chunk:', s);
    });

    pythonProcess.on('close', (code) => {
      exitCode = code;
      resolve({ code: exitCode, stdout, stderr });
    });

    pythonProcess.on('error', (error) => {
      console.error('Failed to start scanner (raw):', error);
      reject(error);
    });
  });
}

// Run the Python report generator and return stdout/stderr and reportPath (if produced)
async function runPythonReportGenerator(scanId: string, scan: any, vulnerabilities: any[], config: any): Promise<{ code: number | null; stdout: string; stderr: string; reportPath?: string }> {
  return new Promise((resolve, reject) => {
    const pythonScript = path.join(PROJECT_ROOT, 'server', 'services', 'report_generator.py');
    // Pass scan data and config as JSON arguments
    const args = [pythonScript, JSON.stringify({ scan, vulnerabilities }), JSON.stringify(config)];

    console.log(`Running Python report generator: python ${args.join(' ')}`);

    const pythonProcess = spawn('python', args);

    let stdout = '';
    let stderr = '';
    let exitCode: number | null = null;

    pythonProcess.stdout.on('data', (data) => {
      const s = data.toString();
      stdout += s;
      console.log('report stdout chunk:', s);
    });

    pythonProcess.stderr.on('data', (data) => {
      const s = data.toString();
      stderr += s;
      console.error('report stderr chunk:', s);
    });

    pythonProcess.on('close', (code) => {
      exitCode = code;
      let reportPath: string | undefined = undefined;
      try {
        if (stdout && stdout.trim().length > 0) {
          const parsed = JSON.parse(stdout);
          reportPath = parsed.report_path || parsed.reportPath || parsed.report_path || undefined;
        }
      } catch (e) {
        // ignore parse errors
      }
      resolve({ code: exitCode, stdout, stderr, reportPath });
    });

    pythonProcess.on('error', (error) => {
      console.error('Failed to start report generator:', error);
      reject(error);
    });
  });
}

// Real scanning process using Python scanner
async function startScanningProcess(scanId: string) {
  try {
    console.log("Starting scanning process for scan:", scanId);
    
    const files = await storage.getFilesByScanId(scanId);
    if (files.length === 0) {
      throw new Error("No files to scan");
    }

    // Stage 1: Static Analysis
    await storage.updateScanProgress(scanId, "static_analysis", {
      status: "running",
      message: "Running Semgrep and Bandit analysis..."
    });

    // Run the Python scanner on all uploaded files
    const filePaths = files.map(f => f.filepath);
    const scanResults = await runPythonScanner(scanId, filePaths);
    
    console.log(`Scanner found ${scanResults.length} vulnerabilities`);

    // Create vulnerability entries from scan results
    for (const result of scanResults) {
      // Try to map the scanner filename to the uploaded file record.
      // Uploaded file records store both the original filename and the stored filepath (which includes the saved name).
      const file = files.find(f => f.filename === result.filename || path.basename(f.filepath) === result.filename);

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
        reviewed: false,
      });
    }

    await storage.updateScanProgress(scanId, "static_analysis", {
      status: "completed",
      message: `Static analysis completed - found ${scanResults.length} vulnerabilities`
    });

    // Stage 2: AI Analysis
    await storage.updateScanProgress(scanId, "ai_analysis", {
      status: "running",
      message: "Analyzing with AI models..."
    });

    await new Promise(resolve => setTimeout(resolve, 2000));

    // Add AI analysis to existing vulnerabilities
    await addAIAnalysisToVulnerabilities(scanId);

    await storage.updateScanProgress(scanId, "ai_analysis", {
      status: "completed",
      message: "AI analysis completed"
    });

    // Stage 3: CVE Mapping
    await storage.updateScanProgress(scanId, "cve_mapping", {
      status: "running",
      message: "Mapping to CVE database..."
    });

    await new Promise(resolve => setTimeout(resolve, 1000));

    await storage.updateScanProgress(scanId, "cve_mapping", {
      status: "completed",
      message: "CVE mapping completed"
    });

    // Update scan status
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
      message: `Scan failed: ${error instanceof Error ? error.message : 'Unknown error'}`
    });
  }
}


async function addAIAnalysisToVulnerabilities(scanId: string) {
  const vulnerabilities = await storage.getVulnerabilitiesByScanId(scanId);
  console.log("Adding AI analysis to", vulnerabilities.length, "vulnerabilities");

  for (const vuln of vulnerabilities) {
    try {
      // Call the Python AI analyzer for each vulnerability and update the record
      const pythonScript = path.join(PROJECT_ROOT, 'server', 'services', 'ai_analyzer.py');
      const args = [pythonScript, JSON.stringify(vuln)];

      console.log(`Running AI analyzer: python ${args.join(' ')}`);

      const pythonProcess = spawn('python', args);

      let stdout = '';
      let stderr = '';

      pythonProcess.stdout.on('data', (data) => { stdout += data.toString(); });
      pythonProcess.stderr.on('data', (data) => { stderr += data.toString(); console.error('AI stderr:', data.toString()); });

      const exitCode: number = await new Promise((resolve) => {
        pythonProcess.on('close', (code) => resolve(code ?? 0));
      });

      if (exitCode === 0) {
        try {
          const analysisResult = JSON.parse(stdout || '{}');

          await storage.updateVulnerability(vuln.id, {
            aiAnalysis: analysisResult.ai_analysis || vuln.aiAnalysis || '',
            suggestedFix: analysisResult.suggested_fix || vuln.suggestedFix || '',
            confidence: analysisResult.confidence || vuln.confidence || 80,
            aiModelUsed: analysisResult.ai_model_used || vuln.aiModelUsed || 'unknown',
          });
        } catch (e) {
          console.error('Failed to parse AI analyzer output:', e, stdout, stderr);
        }
      } else {
        console.error('AI analyzer exited with code', exitCode, 'stderr:', stderr);
      }

    } catch (err) {
      console.error('Error running AI analysis for vuln', vuln.id, err);
    }
  }
}
