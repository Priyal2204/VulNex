import { Card, CardContent } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { CheckCircle, Loader2, Clock } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import type { ScanResult } from "@shared/schema";

interface ScanProgressProps {
  scanId: string;
}

export default function ScanProgress({ scanId }: ScanProgressProps) {
  const { data: scanResult, isLoading } = useQuery<ScanResult>({
    queryKey: ['/api/scans', scanId],
    refetchInterval: 2000, // Poll every 2 seconds
    enabled: !!scanId,
  });

  if (isLoading || !scanResult) {
    return (
      <Card className="mb-8">
        <CardContent className="p-6">
          <div className="flex items-center justify-center py-8">
            <Loader2 className="h-8 w-8 animate-spin text-primary" />
            <span className="ml-2 text-muted-foreground">Loading scan progress...</span>
          </div>
        </CardContent>
      </Card>
    );
  }

  const { scan, progress } = scanResult;
  
  // Calculate overall progress
  const completedStages = progress.filter(p => p.status === "completed").length;
  const totalStages = progress.length;
  const overallProgress = totalStages > 0 ? (completedStages / totalStages) * 100 : 0;

  const getStageIcon = (status: string) => {
    switch (status) {
      case "completed":
        return <CheckCircle className="h-5 w-5 text-green-600" />;
      case "running":
        return <Loader2 className="h-5 w-5 text-blue-600 animate-spin" />;
      default:
        return <Clock className="h-5 w-5 text-gray-400" />;
    }
  };

  const getStageStyle = (status: string) => {
    switch (status) {
      case "completed":
        return "bg-green-50 border-green-200";
      case "running":
        return "bg-blue-50 border-blue-200";
      default:
        return "bg-gray-50 border-gray-200";
    }
  };

  const getStageTextColor = (status: string) => {
    switch (status) {
      case "completed":
        return "text-green-800";
      case "running":
        return "text-blue-800";
      default:
        return "text-gray-600";
    }
  };

  const getStageName = (stage: string) => {
    const stageNames = {
      static_analysis: "Static Analysis",
      ai_analysis: "AI Analysis", 
      cve_mapping: "CVE Mapping"
    };
    return stageNames[stage as keyof typeof stageNames] || stage;
  };

  return (
    <Card className="mb-8" data-testid="scan-progress-card">
      <CardContent className="p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-foreground">Scanning Progress</h2>
          <span className="text-sm text-muted-foreground" data-testid="text-progress-files">
            {scan.completedFiles}/{scan.totalFiles} files completed
          </span>
        </div>
        
        <div className="space-y-4">
          {/* Progress Bar */}
          <div className="w-full">
            <div className="flex justify-between items-center mb-2">
              <span className="text-sm font-medium text-foreground">Overall Progress</span>
              <span className="text-sm text-muted-foreground">{Math.round(overallProgress)}%</span>
            </div>
            <Progress 
              value={overallProgress} 
              className="w-full" 
              data-testid="progress-overall"
            />
          </div>
          
          {/* Scanner Status */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {progress.map((stage) => (
              <div 
                key={stage.stage}
                className={`flex items-center space-x-3 p-3 border rounded-md ${getStageStyle(stage.status)}`}
                data-testid={`stage-${stage.stage}`}
              >
                {getStageIcon(stage.status)}
                <div>
                  <p className={`text-sm font-medium ${getStageTextColor(stage.status)}`}>
                    {getStageName(stage.stage)}
                  </p>
                  <p className={`text-xs ${getStageTextColor(stage.status)} opacity-75`}>
                    {stage.message}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
