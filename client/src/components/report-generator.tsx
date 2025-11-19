import { useState } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Download, FileText, Eye } from "lucide-react";
import { useMutation } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";

interface ReportGeneratorProps {
  scanId: string;
}

interface ReportConfig {
  format: 'pdf' | 'excel';
  sections: string[];
  severityFilter: string;
  includeCode: boolean;
}

export default function ReportGenerator({ scanId }: ReportGeneratorProps) {
  const [config, setConfig] = useState<ReportConfig>({
    format: 'pdf',
    sections: ['executive_summary', 'vulnerability_details', 'ai_recommendations'],
    severityFilter: 'all',
    includeCode: false,
  });

  const { toast } = useToast();

  const generateReportMutation = useMutation({
    mutationFn: async (reportConfig: ReportConfig) => {
      const response = await apiRequest("POST", `/api/scans/${scanId}/report`, reportConfig);
      const result = await response.json();
      
      // Now fetch the actual report file
      if (result.downloadUrl) {
        const fileResponse = await fetch(result.downloadUrl);
        if (!fileResponse.ok) throw new Error('Failed to download report');
        const blob = await fileResponse.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = result.filename || `security-report-${scanId}.${config.format}`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        return result;
      }
      throw new Error('No download URL provided');
    },
    onSuccess: (result) => {
      toast({
        title: "Report generated successfully",
        description: `Your ${config.format.toUpperCase()} report has been downloaded.`,
      });
    },
    onError: (error) => {
      console.error('Report generation failed:', error);
      toast({
        title: "Report generation failed",
        description: error instanceof Error ? error.message : "Failed to generate report",
        variant: "destructive",
      });
    }
  });

  const handleSectionChange = (section: string, checked: boolean) => {
    setConfig(prev => ({
      ...prev,
      sections: checked 
        ? [...prev.sections, section]
        : prev.sections.filter(s => s !== section)
    }));
  };

  const handleFormatChange = (format: 'pdf' | 'excel') => {
    setConfig(prev => ({ ...prev, format }));
  };

  const handleSeverityFilterChange = (severityFilter: string) => {
    setConfig(prev => ({ ...prev, severityFilter }));
  };

  const handleGenerateReport = () => {
    generateReportMutation.mutate(config);
  };

  const getPreviewContent = (): JSX.Element => {
    const currentDate = new Date().toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    });

    return (
      <div className="space-y-3">
        <div className="font-medium">VulNex Security Report</div>
        <div className="text-muted-foreground">Generated: {currentDate}</div>
        <div className="border-t border-border pt-3">
          <div className="font-medium mb-2">Executive Summary</div>
          <div className="text-muted-foreground text-xs">
            • Total Files Scanned: {config.sections.includes('executive_summary') ? 'Included' : 'Not included'}<br/>
            • Severity Filter: {config.severityFilter}<br/>
            • Code Snippets: {config.includeCode ? 'Included' : 'Not included'}
          </div>
        </div>
        {config.sections.includes('vulnerability_details') && (
          <div className="border-t border-border pt-3">
            <div className="font-medium mb-2">Vulnerability Details</div>
            <div className="text-muted-foreground text-xs">
              • Full vulnerability analysis<br/>
              • Code context and location<br/>
              • Severity and impact details
            </div>
          </div>
        )}
        {config.sections.includes('ai_recommendations') && (
          <div className="border-t border-border pt-3">
            <div className="font-medium mb-2">AI Recommendations</div>
            <div className="text-muted-foreground text-xs">
              • Detailed mitigation strategies<br/>
              • Code fix suggestions<br/>
              • Best practice recommendations
            </div>
          </div>
        )}
      </div>
    );
  };

  return (
    <Card data-testid="report-generator-card">
      <CardContent className="p-6">
        <h2 className="text-lg font-semibold text-foreground mb-4">Generate Security Report</h2>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Report Options */}
          <div>
            <h3 className="font-medium text-foreground mb-3">Report Configuration</h3>
            <div className="space-y-4">
              {/* Report Format */}
              <div>
                <Label className="text-sm mb-2 block">Report Format</Label>
                <RadioGroup 
                  defaultValue={config.format}
                  onValueChange={value => handleFormatChange(value as 'pdf' | 'excel')}
                  className="flex gap-4"
                >
                  <div className="flex items-center space-x-2">
                    <RadioGroupItem value="pdf" id="pdf" />
                    <Label htmlFor="pdf">PDF</Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <RadioGroupItem value="excel" id="excel" />
                    <Label htmlFor="excel">Excel</Label>
                  </div>
                </RadioGroup>
              </div>

              {/* Report Sections */}
              <div>
                <Label className="text-sm mb-2 block">Include Sections</Label>
                <div className="space-y-2">
                  <div className="flex items-center space-x-2">
                    <Checkbox 
                      id="executive-summary"
                      checked={config.sections.includes('executive_summary')}
                      onCheckedChange={(checked) => handleSectionChange('executive_summary', checked as boolean)}
                    />
                    <Label htmlFor="executive-summary" className="text-sm">Executive Summary</Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Checkbox 
                      id="vulnerability-details"
                      checked={config.sections.includes('vulnerability_details')}
                      onCheckedChange={(checked) => handleSectionChange('vulnerability_details', checked as boolean)}
                    />
                    <Label htmlFor="vulnerability-details" className="text-sm">Vulnerability Details</Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Checkbox 
                      id="ai-recommendations"
                      checked={config.sections.includes('ai_recommendations')}
                      onCheckedChange={(checked) => handleSectionChange('ai_recommendations', checked as boolean)}
                    />
                    <Label htmlFor="ai-recommendations" className="text-sm">AI Recommendations</Label>
                  </div>
                </div>
              </div>

              {/* Severity Filter */}
              <div>
                <Label htmlFor="severity-filter" className="text-sm mb-2 block">Severity Filter</Label>
                <Select value={config.severityFilter} onValueChange={handleSeverityFilterChange}>
                  <SelectTrigger id="severity-filter">
                    <SelectValue placeholder="Select severity level" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Severities</SelectItem>
                    <SelectItem value="critical">Critical Only</SelectItem>
                    <SelectItem value="high">High & Above</SelectItem>
                    <SelectItem value="medium">Medium & Above</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {/* Include Code */}
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="include-code" 
                  checked={config.includeCode}
                  onCheckedChange={(checked) => setConfig(prev => ({ ...prev, includeCode: checked as boolean }))}
                />
                <Label htmlFor="include-code" className="text-sm">Include code snippets in report</Label>
              </div>
            </div>
          </div>
          
          {/* Report Preview */}
          <div>
            <h3 className="font-medium text-foreground mb-3">Report Preview</h3>
            <div className="bg-muted border border-border rounded-lg p-4 h-64 overflow-y-auto">
              {getPreviewContent()}
            </div>
          </div>
        </div>
        
        <div className="mt-6 flex justify-end space-x-4">
          <Button 
            variant="outline"
            className="border-border text-foreground hover:bg-muted"
            data-testid="button-preview"
          >
            <Eye className="mr-2 h-4 w-4" />
            Preview Full Report
          </Button>
          <Button 
            onClick={handleGenerateReport}
            disabled={generateReportMutation.isPending || config.sections.length === 0}
            className="bg-accent hover:bg-accent/90 text-accent-foreground"
            data-testid="button-generate"
          >
            {generateReportMutation.isPending ? (
              <>
                <div className="mr-2 h-4 w-4 animate-spin rounded-full border-2 border-background border-t-transparent" />
                Generating...
              </>
            ) : (
              <>
                <Download className="mr-2 h-4 w-4" />
                Generate & Download
              </>
            )}
          </Button>
        </div>

        {/* Configuration Summary */}
        <div className="mt-4 p-3 bg-secondary/50 rounded-md">
          <div className="text-xs text-muted-foreground">
            <strong>Current Configuration:</strong> {config.format.toUpperCase()} format, 
            {config.sections.length} section(s), {config.severityFilter} severity filter
            {config.includeCode && ', with code snippets'}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}