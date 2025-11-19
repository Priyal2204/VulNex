import { Shield, HelpCircle, Settings, CheckCircle, Upload, Search, FileCode, Download } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { useState } from "react";

export default function Header() {
  const [helpOpen, setHelpOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);

  return (
    <header className="bg-card border-b border-border">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center py-4">
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-2">
              <Shield className="text-primary text-2xl" />
              <h1 className="text-xl font-bold text-foreground">VulNex</h1>
            </div>
            <span className="text-sm text-muted-foreground">Vulnerability Detection Tool</span>
          </div>
          <div className="flex items-center space-x-4">
            <Dialog open={helpOpen} onOpenChange={setHelpOpen}>
              <DialogTrigger asChild>
                <Button 
                  variant="ghost" 
                  size="icon"
                  className="text-muted-foreground hover:text-foreground"
                  data-testid="button-help"
                >
                  <HelpCircle className="h-5 w-5" />
                </Button>
              </DialogTrigger>
              <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
                <DialogHeader>
                  <DialogTitle className="text-2xl">Help & Documentation</DialogTitle>
                  <DialogDescription>
                    Learn how to use VulNex to scan your code for security vulnerabilities
                  </DialogDescription>
                </DialogHeader>
                <div className="space-y-6 pt-4">
                  <div>
                    <h3 className="font-semibold text-lg mb-2 flex items-center gap-2">
                      <Upload className="h-5 w-5 text-primary" />
                      Getting Started
                    </h3>
                    <p className="text-muted-foreground text-sm">
                      Upload your code files using the drag-and-drop interface or click to browse. VulNex supports multiple programming languages including Python, JavaScript, TypeScript, Java, and more.
                    </p>
                  </div>
                  
                  <div>
                    <h3 className="font-semibold text-lg mb-2 flex items-center gap-2">
                      <Search className="h-5 w-5 text-primary" />
                      Security Scanning Process
                    </h3>
                    <div className="space-y-2 text-sm text-muted-foreground">
                      <div className="flex items-start gap-2">
                        <CheckCircle className="h-4 w-4 mt-0.5 text-green-500" />
                        <div>
                          <strong>Static Analysis:</strong> Runs Bandit and Semgrep scanners to detect common security vulnerabilities in your code
                        </div>
                      </div>
                      <div className="flex items-start gap-2">
                        <CheckCircle className="h-4 w-4 mt-0.5 text-green-500" />
                        <div>
                          <strong>AI Analysis:</strong> Uses AI models to provide enhanced explanations and context for detected vulnerabilities
                        </div>
                      </div>
                      <div className="flex items-start gap-2">
                        <CheckCircle className="h-4 w-4 mt-0.5 text-green-500" />
                        <div>
                          <strong>CVE Mapping:</strong> Maps vulnerabilities to CWE database for standardized classification
                        </div>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h3 className="font-semibold text-lg mb-2 flex items-center gap-2">
                      <FileCode className="h-5 w-5 text-primary" />
                      Supported File Types
                    </h3>
                    <div className="flex flex-wrap gap-2 text-sm">
                      {['.py', '.js', '.ts', '.java', '.cpp', '.c', '.cs', '.rb', '.php', '.go', '.rs'].map(ext => (
                        <span key={ext} className="bg-muted px-3 py-1 rounded-md">{ext}</span>
                      ))}
                    </div>
                  </div>

                  <div>
                    <h3 className="font-semibold text-lg mb-2 flex items-center gap-2">
                      <Download className="h-5 w-5 text-primary" />
                      Generating Reports
                    </h3>
                    <p className="text-muted-foreground text-sm">
                      After scanning completes, you can generate comprehensive security reports in PDF or Excel format. Reports include vulnerability details, severity ratings, AI-powered recommendations, and suggested fixes.
                    </p>
                  </div>
                </div>
              </DialogContent>
            </Dialog>

            <Dialog open={settingsOpen} onOpenChange={setSettingsOpen}>
              <DialogTrigger asChild>
                <Button 
                  variant="ghost" 
                  size="icon"
                  className="text-muted-foreground hover:text-foreground"
                  data-testid="button-settings"
                >
                  <Settings className="h-5 w-5" />
                </Button>
              </DialogTrigger>
              <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
                <DialogHeader>
                  <DialogTitle className="text-2xl">Settings & Configuration</DialogTitle>
                  <DialogDescription>
                    Configure your VulNex scanning preferences
                  </DialogDescription>
                </DialogHeader>
                <div className="space-y-6 pt-4">
                  <div>
                    <h3 className="font-semibold text-lg mb-3">Scan Configuration</h3>
                    <div className="space-y-3 text-sm">
                      <div className="flex items-center justify-between p-3 bg-muted rounded-lg">
                        <div>
                          <div className="font-medium">Maximum File Size</div>
                          <div className="text-muted-foreground text-xs">Current limit: 50MB per file</div>
                        </div>
                      </div>
                      <div className="flex items-center justify-between p-3 bg-muted rounded-lg">
                        <div>
                          <div className="font-medium">Supported Scanners</div>
                          <div className="text-muted-foreground text-xs">Bandit (Python) & Semgrep (Multi-language)</div>
                        </div>
                      </div>
                      <div className="flex items-center justify-between p-3 bg-muted rounded-lg">
                        <div>
                          <div className="font-medium">AI-Powered Analysis</div>
                          <div className="text-muted-foreground text-xs">Enhanced with HuggingFace models</div>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h3 className="font-semibold text-lg mb-3">About VulNex</h3>
                    <div className="text-sm text-muted-foreground space-y-2">
                      <p>
                        VulNex is an AI-powered security vulnerability detection tool that combines traditional static analysis with advanced machine learning models to identify security issues in your code.
                      </p>
                      <p>
                        The tool provides detailed vulnerability reports, AI-generated fix suggestions, and maps findings to industry-standard CWE classifications.
                      </p>
                    </div>
                  </div>

                  <div>
                    <h3 className="font-semibold text-lg mb-3">Security & Privacy</h3>
                    <div className="text-sm text-muted-foreground space-y-2">
                      <p>
                        Your uploaded files are analyzed locally and are not permanently stored. All API keys and credentials are managed securely through environment variables.
                      </p>
                    </div>
                  </div>
                </div>
              </DialogContent>
            </Dialog>
          </div>
        </div>
      </div>
    </header>
  );
}
