# Overview

This is a full-stack security vulnerability detection tool called "VulNex" that combines static analysis with AI-powered vulnerability assessment. The application allows users to upload code files for security scanning, provides real-time progress tracking, displays vulnerability findings with detailed analysis, and generates comprehensive security reports. It integrates multiple security scanners (Bandit for Python, Semgrep for multi-language support) with AI models from HuggingFace to provide enhanced vulnerability explanations and fix suggestions.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Frontend Architecture
The client uses React with TypeScript in a modern single-page application setup. The UI is built with shadcn/ui components providing a comprehensive design system with Radix UI primitives and Tailwind CSS for styling. The application uses Wouter for client-side routing and TanStack Query for state management and API communication. The component structure follows a modular approach with dedicated components for file upload, scan progress tracking, vulnerability display, and report generation.

## Backend Architecture
The server is built with Express.js and TypeScript, providing RESTful API endpoints for scan management, file uploads, and report generation. The architecture uses a storage abstraction layer with an in-memory implementation for development, allowing easy migration to persistent storage. The system spawns Python child processes for security scanning, integrating multiple security tools including Bandit for Python-specific vulnerabilities and Semgrep for broader language support.

## Data Storage Design
The application uses Drizzle ORM with PostgreSQL for production database management. The schema defines four main entities: scans (tracking overall scan status), uploaded files (storing file metadata), vulnerabilities (detailed vulnerability findings), and scan progress (real-time progress tracking). The in-memory storage implementation provides the same interface for development and testing scenarios.

## Security Scanning Pipeline
The scanning process operates in three stages: static analysis using traditional security tools, AI-powered analysis for enhanced explanations and fix suggestions, and CVE mapping for vulnerability classification. Each stage reports progress independently, allowing for granular status tracking and user feedback during long-running scans.

## AI Integration Strategy
The system integrates with HuggingFace models for AI-powered vulnerability analysis. The Python-based AI analyzer service uses multiple model endpoints for code analysis, vulnerability detection, and fix generation. The architecture supports fallback mechanisms and configurable API keys for different deployment environments.

## Report Generation System
The application includes a sophisticated report generator that creates both PDF and Excel formats. The Python-based service uses ReportLab for PDF generation and openpyxl for Excel reports, with support for customizable report sections, severity filtering, and executive summaries tailored for different stakeholder audiences.

## File Processing Architecture
File uploads are handled through Multer middleware with configurable size limits and storage locations. The system supports multiple programming languages with automatic language detection, enabling appropriate scanner selection and analysis customization based on file types.

# External Dependencies

## Database Services
- **Neon Database**: PostgreSQL hosting service configured through Drizzle ORM
- **Environment-based Configuration**: DATABASE_URL environment variable for database connection management

## AI and Machine Learning
- **HuggingFace API**: Multiple model endpoints for code analysis and vulnerability detection
- **Microsoft CodeBERT**: Primary model for code understanding and vulnerability classification
- **BigCode StarCoder**: Text generation model for fix suggestions and code improvements

## Security Analysis Tools
- **Bandit**: Python-specific security vulnerability scanner for identifying common security issues
- **Semgrep**: Multi-language static analysis tool for pattern-based vulnerability detection
- **Custom Scanner Integration**: Extensible architecture supporting additional security tools

## Document Generation
- **ReportLab**: Python library for PDF generation with custom styling and layout capabilities
- **OpenPyXL**: Excel file generation library for structured vulnerability reports and data export

## Development and Build Tools
- **Vite**: Frontend build tool with React plugin and development server capabilities
- **Replit Integration**: Development environment plugins for debugging and deployment support
- **ESBuild**: Server-side bundling for production builds with Node.js compatibility

## UI and Styling Framework
- **shadcn/ui**: Component library built on Radix UI primitives providing accessible, customizable components
- **Radix UI**: Unstyled, accessible UI primitives for complex interactive components
- **Tailwind CSS**: Utility-first CSS framework with custom design system integration
- **Lucide React**: Icon library providing consistent iconography throughout the application