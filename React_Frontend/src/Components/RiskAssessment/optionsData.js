// Platform options
export const platformOptions = [
  { value: "web_only", label: "Web Only" },
  { value: "web_mobile", label: "Web & Mobile" },
  { value: "web_desktop", label: "Web & Desktop" },
  { value: "all", label: "All Platforms" },
];

// Tech stack options
export const techStackOptions = {
  frontend: [
    { value: "react", label: "React" },
    { value: "angular", label: "Angular" },
    { value: "vue", label: "Vue.js" },
    { value: "vanilla", label: "Vanilla JS/HTML/CSS" },
    { value: "other", label: "Other" },
  ],
  backend: [
    { value: "node", label: "Node.js" },
    { value: "python", label: "Python" },
    { value: "java", label: "Java" },
    { value: "dotnet", label: ".NET" },
    { value: "php", label: "PHP" },
    { value: "other", label: "Other" },
  ],
  database: [
    { value: "mysql", label: "MySQL" },
    { value: "postgres", label: "PostgreSQL" },
    { value: "mongodb", label: "MongoDB" },
    { value: "oracle", label: "Oracle" },
    { value: "sqlserver", label: "SQL Server" },
    { value: "other", label: "Other" },
  ],
};

// Application type options
export const appTypeOptions = [
  { value: 1, label: "Web Application" },
  { value: 2, label: "Mobile Application" },
  { value: 3, label: "Desktop Application" },
  { value: 4, label: "API Service" },
  { value: 5, label: "Microservice" },
  { value: 6, label: "Other" },
];

// Security and risk options
export const dataSecurityOptions = ['minimal', 'basic', 'standard', 'advanced'];
export const sensitiveDataOptions = ['none', 'pii', 'financial', 'health', 'multiple'];
export const thirdPartyOptions = ['none', 'few', 'many', 'critical'];
export const errorHandlingOptions = ['minimal', 'basic', 'comprehensive', 'advanced'];
export const userInputOptions = ['none', 'text_only', 'limited_files', 'extensive_files'];
export const monitoringOptions = ['minimal', 'basic', 'standard', 'comprehensive'];
export const legacyDependenciesOptions = ['none', 'minor', 'major', 'critical'];
export const architectureOptions = [
  { value: "monolith", label: "Monolith" },
  { value: "client_server", label: "Client Server" },
  { value: "microservices", label: "Microservices" },
  { value: "serverless", label: "Serverless" },
  { value: "hybrid", label: "Hybrid" },
];
export const hostingOptions = [
  { value: "on_premise", label: "On Premise" },
  { value: "aws", label: "AWS" },
  { value: "azure", label: "Azure" },
  { value: "gcp", label: "GCP" },
  { value: "other_cloud", label: "Other Cloud" },
  { value: "hybrid", label: "Hybrid" },
];