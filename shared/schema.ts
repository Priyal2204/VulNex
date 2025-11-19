import { sql } from "drizzle-orm";
import { pgTable, text, varchar, integer, timestamp, jsonb, boolean } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const scans = pgTable("scans", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  status: text("status").notNull().default("pending"), // pending, scanning, completed, failed
  totalFiles: integer("total_files").default(0),
  completedFiles: integer("completed_files").default(0),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const uploadedFiles = pgTable("uploaded_files", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  scanId: varchar("scan_id").references(() => scans.id),
  filename: text("filename").notNull(),
  filepath: text("filepath").notNull(),
  size: integer("size").notNull(),
  language: text("language"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const vulnerabilities = pgTable("vulnerabilities", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  scanId: varchar("scan_id").references(() => scans.id),
  fileId: varchar("file_id").references(() => uploadedFiles.id),
  filename: text("filename").notNull(),
  lineNumber: integer("line_number").notNull(),
  vulnerabilityType: text("vulnerability_type").notNull(),
  severity: text("severity").notNull(), // critical, high, medium, low
  cweId: text("cwe_id"),
  cveId: text("cve_id"),
  owaspCategory: text("owasp_category"),
  description: text("description").notNull(),
  codeSnippet: text("code_snippet").notNull(),
  suggestedFix: text("suggested_fix"),
  aiAnalysis: text("ai_analysis"),
  aiModelUsed: text("ai_model_used"),
  confidence: integer("confidence").default(0), // 0-100
  detectionTool: text("detection_tool").notNull(),
  impact: text("impact"),
  exploitability: text("exploitability"),
  reviewed: boolean("reviewed").default(false),
  createdAt: timestamp("created_at").defaultNow(),
});

export const scanProgress = pgTable("scan_progress", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  scanId: varchar("scan_id").references(() => scans.id),
  stage: text("stage").notNull(), // static_analysis, ai_analysis, cve_mapping
  status: text("status").notNull(), // pending, running, completed, failed
  message: text("message"),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const insertScanSchema = createInsertSchema(scans).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertUploadedFileSchema = createInsertSchema(uploadedFiles).omit({
  id: true,
  createdAt: true,
});

export const insertVulnerabilitySchema = createInsertSchema(vulnerabilities).omit({
  id: true,
  createdAt: true,
});

export const insertScanProgressSchema = createInsertSchema(scanProgress).omit({
  id: true,
  updatedAt: true,
});

export type InsertScan = z.infer<typeof insertScanSchema>;
export type InsertUploadedFile = z.infer<typeof insertUploadedFileSchema>;
export type InsertVulnerability = z.infer<typeof insertVulnerabilitySchema>;
export type InsertScanProgress = z.infer<typeof insertScanProgressSchema>;

export type Scan = typeof scans.$inferSelect;
export type UploadedFile = typeof uploadedFiles.$inferSelect;
export type Vulnerability = typeof vulnerabilities.$inferSelect;
export type ScanProgress = typeof scanProgress.$inferSelect;

// API Response Types
export const scanResultSchema = z.object({
  scan: z.object({
    id: z.string(),
    status: z.string(),
    totalFiles: z.number(),
    completedFiles: z.number(),
    createdAt: z.string(),
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
    detectionTool: z.string(),
  })),
  progress: z.array(z.object({
    stage: z.string(),
    status: z.string(),
    message: z.string().nullable(),
  })),
});

export type ScanResult = z.infer<typeof scanResultSchema>;
