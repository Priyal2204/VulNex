import { 
  type Scan, 
  type InsertScan,
  type UploadedFile,
  type InsertUploadedFile,
  type Vulnerability,
  type InsertVulnerability,
  type ScanProgress,
  type InsertScanProgress
} from "@shared/schema";
import { randomUUID } from "crypto";

export interface IStorage {
  // Scans
  createScan(scan: InsertScan): Promise<Scan>;
  getScan(id: string): Promise<Scan | undefined>;
  updateScan(id: string, updates: Partial<Scan>): Promise<Scan | undefined>;
  getAllScans(): Promise<Scan[]>;

  // Files
  createUploadedFile(file: InsertUploadedFile): Promise<UploadedFile>;
  getFilesByScanId(scanId: string): Promise<UploadedFile[]>;
  getFile(id: string): Promise<UploadedFile | undefined>;

  // Vulnerabilities
  createVulnerability(vulnerability: InsertVulnerability): Promise<Vulnerability>;
  getVulnerabilitiesByScanId(scanId: string): Promise<Vulnerability[]>;
  getVulnerability(id: string): Promise<Vulnerability | undefined>;
  updateVulnerability(id: string, updates: Partial<Vulnerability>): Promise<Vulnerability | undefined>;

  // Scan Progress
  createScanProgress(progress: InsertScanProgress): Promise<ScanProgress>;
  getScanProgressByScanId(scanId: string): Promise<ScanProgress[]>;
  updateScanProgress(scanId: string, stage: string, updates: Partial<ScanProgress>): Promise<ScanProgress | undefined>;
}

export class MemStorage implements IStorage {
  private scans: Map<string, Scan>;
  private uploadedFiles: Map<string, UploadedFile>;
  private vulnerabilities: Map<string, Vulnerability>;
  private scanProgress: Map<string, ScanProgress>;

  constructor() {
    this.scans = new Map();
    this.uploadedFiles = new Map();
    this.vulnerabilities = new Map();
    this.scanProgress = new Map();
  }

  async createScan(insertScan: InsertScan): Promise<Scan> {
    const id = randomUUID();
    const scan: Scan = {
      status: "pending",
      totalFiles: 0,
      completedFiles: 0,
      ...insertScan,
      id,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.scans.set(id, scan);
    return scan;
  }

  async getScan(id: string): Promise<Scan | undefined> {
    return this.scans.get(id);
  }

  async updateScan(id: string, updates: Partial<Scan>): Promise<Scan | undefined> {
    const scan = this.scans.get(id);
    if (!scan) return undefined;
    
    const updatedScan = { ...scan, ...updates, updatedAt: new Date() };
    this.scans.set(id, updatedScan);
    return updatedScan;
  }

  async getAllScans(): Promise<Scan[]> {
    return Array.from(this.scans.values()).sort(
      (a, b) => b.createdAt!.getTime() - a.createdAt!.getTime()
    );
  }

  async createUploadedFile(insertFile: InsertUploadedFile): Promise<UploadedFile> {
    const id = randomUUID();
    const file: UploadedFile = {
      scanId: null,
      language: null,
      ...insertFile,
      id,
      createdAt: new Date(),
    };
    this.uploadedFiles.set(id, file);
    return file;
  }

  async getFilesByScanId(scanId: string): Promise<UploadedFile[]> {
    return Array.from(this.uploadedFiles.values()).filter(
      file => file.scanId === scanId
    );
  }

  async getFile(id: string): Promise<UploadedFile | undefined> {
    return this.uploadedFiles.get(id);
  }

  async createVulnerability(insertVulnerability: InsertVulnerability): Promise<Vulnerability> {
    const id = randomUUID();
    const vulnerability: Vulnerability = {
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
      createdAt: new Date(),
    };
    this.vulnerabilities.set(id, vulnerability);
    return vulnerability;
  }

  async getVulnerabilitiesByScanId(scanId: string): Promise<Vulnerability[]> {
    return Array.from(this.vulnerabilities.values())
      .filter(vuln => vuln.scanId === scanId)
      .sort((a, b) => {
        const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
        return (severityOrder[b.severity as keyof typeof severityOrder] || 0) - 
               (severityOrder[a.severity as keyof typeof severityOrder] || 0);
      });
  }

  async getVulnerability(id: string): Promise<Vulnerability | undefined> {
    return this.vulnerabilities.get(id);
  }

  async updateVulnerability(id: string, updates: Partial<Vulnerability>): Promise<Vulnerability | undefined> {
    const vulnerability = this.vulnerabilities.get(id);
    if (!vulnerability) return undefined;
    
    const updatedVulnerability = { ...vulnerability, ...updates };
    this.vulnerabilities.set(id, updatedVulnerability);
    return updatedVulnerability;
  }

  async createScanProgress(insertProgress: InsertScanProgress): Promise<ScanProgress> {
    const id = randomUUID();
    const progress: ScanProgress = {
      scanId: null,
      message: null,
      ...insertProgress,
      id,
      updatedAt: new Date(),
    };
    this.scanProgress.set(id, progress);
    return progress;
  }

  async getScanProgressByScanId(scanId: string): Promise<ScanProgress[]> {
    return Array.from(this.scanProgress.values()).filter(
      progress => progress.scanId === scanId
    );
  }

  async updateScanProgress(scanId: string, stage: string, updates: Partial<ScanProgress>): Promise<ScanProgress | undefined> {
    const existingProgress = Array.from(this.scanProgress.values()).find(
      p => p.scanId === scanId && p.stage === stage
    );
    
    if (!existingProgress) return undefined;
    
    const updatedProgress = { ...existingProgress, ...updates, updatedAt: new Date() };
    this.scanProgress.set(existingProgress.id, updatedProgress);
    return updatedProgress;
  }
}

export const storage = new MemStorage();
