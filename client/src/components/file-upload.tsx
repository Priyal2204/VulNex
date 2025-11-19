import { useState, useCallback } from "react";
import { CloudUpload, X, FileText, Upload } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";

interface UploadedFile {
  id: string;
  filename: string;
  size: number;
  language?: string;
}

interface FileUploadProps {
  onScanStart: (scanId: string) => void;
}

export default function FileUpload({ onScanStart }: FileUploadProps) {
  const [files, setFiles] = useState<UploadedFile[]>([]);
  const [isDragging, setIsDragging] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [scanId, setScanId] = useState<string | null>(null);
  const { toast } = useToast();

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const droppedFiles = Array.from(e.dataTransfer.files);
    handleFiles(droppedFiles);
  }, []);

  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      const selectedFiles = Array.from(e.target.files);
      handleFiles(selectedFiles);
    }
  }, []);

  const handleFiles = async (fileList: File[]) => {
    if (fileList.length === 0) return;

    setIsUploading(true);
    setUploadProgress(0);

    try {
      // Create scan first
      const scanResponse = await apiRequest("POST", "/api/scans", {
        status: "preparing",
        totalFiles: fileList.length,
        completedFiles: 0,
      });
      
      const scan = await scanResponse.json();
      setScanId(scan.id);

      // Upload files
      const formData = new FormData();
      fileList.forEach((file) => {
        formData.append('files', file);
      });

      console.log("Uploading files:", fileList.length);
      console.log("FormData entries:", Array.from(formData.entries()));

      const uploadResponse = await fetch(`/api/scans/${scan.id}/upload`, {
        method: 'POST',
        body: formData,
      });

      if (!uploadResponse.ok) {
        const errorResult = await uploadResponse.json();
        throw new Error(errorResult.error || 'Upload failed');
      }

      const uploadResult = await uploadResponse.json();

      setFiles(uploadResult.files);
      setUploadProgress(100);
      
      toast({
        title: "Files uploaded successfully",
        description: `${fileList.length} file(s) ready for scanning`,
      });

    } catch (error) {
      console.error("Upload error:", error);
      toast({
        title: "Upload failed",
        description: "There was an error uploading your files. Please try again.",
        variant: "destructive",
      });
    } finally {
      setIsUploading(false);
    }
  };

  const removeFile = (fileId: string) => {
    setFiles(files.filter(f => f.id !== fileId));
  };

  const startScan = async () => {
    if (!scanId || files.length === 0) return;

    try {
      await apiRequest("POST", `/api/scans/${scanId}/start`);
      onScanStart(scanId);
      
      toast({
        title: "Scan started",
        description: "Security analysis is now in progress",
      });
    } catch (error) {
      console.error("Start scan error:", error);
      toast({
        title: "Failed to start scan",
        description: "There was an error starting the security scan",
        variant: "destructive",
      });
    }
  };

  const getFileIcon = (filename: string) => {
    const ext = filename.split('.').pop()?.toLowerCase();
    // In a real app, you'd have different icons for different file types
    return <FileText className="w-5 h-5 text-blue-600" />;
  };

  return (
    <Card className="mb-8">
      <CardContent className="p-6">
        <h2 className="text-lg font-semibold text-foreground mb-4">Upload Code Files</h2>
        
        {/* Upload Area */}
        <div
          className={`upload-area border-2 border-dashed rounded-lg p-8 text-center ${
            isDragging ? 'border-primary bg-primary/5' : 'border-border'
          }`}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          data-testid="upload-area"
        >
          <div className="space-y-4">
            <CloudUpload className="mx-auto h-12 w-12 text-muted-foreground" />
            <div>
              <p className="text-foreground font-medium">Drop your code files here or click to browse</p>
              <p className="text-muted-foreground text-sm">Supports single files, multiple files, or ZIP archives</p>
            </div>
            <div className="flex flex-wrap justify-center gap-2 text-xs text-muted-foreground">
              {['.py', '.js', '.java', '.cpp', '.zip', '+more'].map((ext) => (
                <span key={ext} className="bg-secondary px-2 py-1 rounded">
                  {ext}
                </span>
              ))}
            </div>
            <div>
              <input
                type="file"
                multiple
                onChange={handleFileSelect}
                className="hidden"
                id="file-upload"
                accept=".py,.js,.ts,.java,.cpp,.c,.cs,.rb,.php,.go,.rs,.zip"
                data-testid="input-file"
              />
              <Button asChild className="bg-primary hover:bg-primary/90 text-primary-foreground">
                <label htmlFor="file-upload" className="cursor-pointer">
                  <Upload className="mr-2 h-4 w-4" />
                  Select Files
                </label>
              </Button>
            </div>
          </div>
        </div>

        {/* Upload Progress */}
        {isUploading && (
          <div className="mt-6">
            <div className="flex justify-between items-center mb-2">
              <span className="text-sm font-medium">Uploading files...</span>
              <span className="text-sm text-muted-foreground">{uploadProgress}%</span>
            </div>
            <Progress value={uploadProgress} className="w-full" />
          </div>
        )}

        {/* Uploaded Files List */}
        {files.length > 0 && (
          <div className="mt-6">
            <h3 className="font-medium text-foreground mb-3" data-testid="text-uploaded-files">
              Uploaded Files ({files.length})
            </h3>
            <div className="space-y-2">
              {files.map((file) => (
                <div 
                  key={file.id} 
                  className="flex items-center justify-between p-3 bg-secondary rounded-md"
                  data-testid={`file-item-${file.id}`}
                >
                  <div className="flex items-center space-x-3">
                    {getFileIcon(file.filename)}
                    <span className="font-mono text-sm">{file.filename}</span>
                    <span className="text-xs text-muted-foreground">
                      {(file.size / 1024).toFixed(1)} KB
                    </span>
                    {file.language && (
                      <span className="text-xs text-muted-foreground capitalize">
                        {file.language}
                      </span>
                    )}
                  </div>
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => removeFile(file.id)}
                    className="text-muted-foreground hover:text-destructive"
                    data-testid={`button-remove-${file.id}`}
                  >
                    <X className="h-4 w-4" />
                  </Button>
                </div>
              ))}
            </div>
            
            {/* Scan Button */}
            <div className="mt-6 flex justify-end">
              <Button 
                onClick={startScan}
                className="bg-accent hover:bg-accent/90 text-accent-foreground"
                disabled={files.length === 0}
                data-testid="button-start-scan"
              >
                <CloudUpload className="mr-2 h-4 w-4" />
                Start Security Scan
              </Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
