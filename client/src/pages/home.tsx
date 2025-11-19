import { useState } from "react";
import Header from "@/components/header";
import FileUpload from "@/components/file-upload";
import ScanProgress from "@/components/scan-progress";
import VulnerabilityTable from "@/components/vulnerability-table";
import VulnerabilityDetail from "@/components/vulnerability-detail";
import ReportGenerator from "@/components/report-generator";

export default function Home() {
  const [currentScanId, setCurrentScanId] = useState<string | null>(null);
  const [selectedVulnerabilityId, setSelectedVulnerabilityId] = useState<string | null>(null);
  const [showReportGenerator, setShowReportGenerator] = useState(false);

  const handleScanStart = (scanId: string) => {
    setCurrentScanId(scanId);
    setSelectedVulnerabilityId(null); // Clear any selected vulnerability
  };

  const handleVulnerabilitySelect = (vulnerabilityId: string) => {
    setSelectedVulnerabilityId(vulnerabilityId);
  };

  const handleCloseVulnerabilityDetail = () => {
    setSelectedVulnerabilityId(null);
  };

  return (
    <div className="min-h-screen bg-background text-foreground">
      <Header />
      
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* File Upload Section */}
        <FileUpload onScanStart={handleScanStart} />
        
        {/* Scan Progress - Only show if we have an active scan */}
        {currentScanId && (
          <ScanProgress scanId={currentScanId} />
        )}
        
        {/* Vulnerability Table - Only show if we have scan results */}
        {currentScanId && (
          <VulnerabilityTable 
            scanId={currentScanId} 
            onVulnerabilitySelect={handleVulnerabilitySelect}
          />
        )}
        
        {/* Vulnerability Detail - Only show when a vulnerability is selected */}
        {selectedVulnerabilityId && (
          <VulnerabilityDetail 
            vulnerabilityId={selectedVulnerabilityId}
            onClose={handleCloseVulnerabilityDetail}
          />
        )}
        
        {/* Report Generator - Only show if we have scan results */}
        {currentScanId && (
          <ReportGenerator scanId={currentScanId} />
        )}
      </main>
    </div>
  );
}
