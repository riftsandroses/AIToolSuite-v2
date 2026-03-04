import React, { useState } from 'react';
import {
    Box,
    Button,
    TextField,
    Typography,
    Stepper,
    Step,
    StepLabel,
    Card,
    CardContent,
    Grid,
    MenuItem,
    FormControl,
    InputLabel,
    Select,
    Chip,
    OutlinedInput,
    Divider,
    Alert,
    useTheme,
    useMediaQuery
} from '@mui/material';
import {
    CloudUpload as CloudUploadIcon,
    NavigateNext as NavigateNextIcon,
    NavigateBefore as NavigateBeforeIcon,
    Send as SendIcon
} from '@mui/icons-material';

const AssessmentForm = ({ onSubmit, initialData = {}, isLoading = false }) => {
    const [activeStep, setActiveStep] = useState(0);
    const [formData, setFormData] = useState(initialData);
    const [architectureDiagram, setArchitectureDiagram] = useState(null);
    const [errors, setErrors] = useState({});

    // Theme helpers
    const theme = useTheme();
    const isMobile = useMediaQuery(theme.breakpoints.down('sm'));

    const sections = [
        'Business Context',
        'Data & Compliance',
        'Application Details',
        'Technical Stack',
        'Infrastructure',
        'Security Controls',
        'Dev & Ops' // Shortened for mobile
    ];

    // Common Styles
    const inputSx = {
        '& .MuiInputLabel-root': { color: 'gray.400' },
        '& .MuiOutlinedInput-root': {
            color: 'white',
            '& fieldset': { borderColor: '#4b5563' }, // gray-600
            '&:hover fieldset': { borderColor: '#9ca3af' }, // gray-400
            '&.Mui-focused fieldset': { borderColor: '#3b82f6' } // blue-500
        },
        '& .MuiSelect-icon': { color: 'gray.400' },
        '& .MuiInputBase-input': { color: 'white' }
    };

    const menuProps = {
        PaperProps: {
            sx: {
                bgcolor: '#1f2937', // gray-800
                color: 'white',
                border: '1px solid #374151',
                '& .MuiMenuItem-root': {
                    '&:hover': { bgcolor: '#374151' }, // gray-700
                    '&.Mui-selected': { bgcolor: '#2563eb !important', color: 'white' } // blue-600
                }
            }
        }
    };

    const handleInputChange = (e) => {
        const { name, value } = e.target;
        setFormData(prev => ({ ...prev, [name]: value }));
        // Clear error for this field
        if (errors[name]) {
            setErrors(prev => ({ ...prev, [name]: '' }));
        }
    };

    const handleMultiSelectChange = (name, value) => {
        setFormData(prev => ({ ...prev, [name]: value }));
    };

    const handleFileChange = (e) => {
        const file = e.target.files[0];
        if (file) {
            setArchitectureDiagram(file);
            setErrors(prev => ({ ...prev, architecture_diagram: '' }));
        }
    };

    const handleNext = () => {
        setActiveStep(prev => prev + 1);
        window.scrollTo(0, 0);
    };

    const handleBack = () => {
        setActiveStep(prev => prev - 1);
        window.scrollTo(0, 0);
    };

    const handleSubmit = () => {
        // Validate required field
        if (!architectureDiagram && !formData.architecture_diagram) { // Check if already exists in formData (for edit mode) or new file
            // Actually, for edit mode we might not need to re-upload. 
            // Logic: if initialData has it, strict check usually not needed, but here we enforce it if missing.
            // Simplification: if no file and no existing url/string, error.
            if (!architectureDiagram && !initialData.architecture_diagram) {
                setErrors({ architecture_diagram: 'Architecture diagram is required' });
                setActiveStep(2); // Go to Application Details section
                return;
            }
        }

        // Prepare FormData
        const submitData = new FormData();

        // Add architecture diagram
        if (architectureDiagram) {
            submitData.append('architecture_diagram', architectureDiagram);
        }

        // Add all other fields (only if they have values)
        Object.entries(formData).forEach(([key, value]) => {
            if (value !== '' && value !== null && value !== undefined && key !== 'architecture_diagram') {
                // Handle arrays
                if (Array.isArray(value)) {
                    value.forEach(item => submitData.append(key, item));
                } else {
                    submitData.append(key, value);
                }
            }
        });

        onSubmit(submitData);
    };

    const renderBusinessContext = () => (
        <Grid container spacing={3}>
            <Grid item xs={12}>
                <TextField
                    fullWidth label="Application Purpose" name="application_purpose"
                    value={formData.application_purpose || ''} onChange={handleInputChange}
                    multiline rows={3} sx={inputSx}
                />
            </Grid>
            <Grid item xs={12}>
                <TextField
                    fullWidth label="Business Objectives" name="business_objectives"
                    value={formData.business_objectives || ''} onChange={handleInputChange}
                    multiline rows={3} sx={inputSx}
                />
            </Grid>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>Business Criticality</InputLabel>
                    <Select
                        name="business_criticality" value={formData.business_criticality || ''}
                        onChange={handleInputChange} label="Business Criticality" MenuProps={menuProps}
                    >
                        <MenuItem value="low">Low</MenuItem>
                        <MenuItem value="medium">Medium</MenuItem>
                        <MenuItem value="high">High</MenuItem>
                        <MenuItem value="critical">Critical</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>Business Impact Tier</InputLabel>
                    <Select
                        name="business_impact_tier" value={formData.business_impact_tier || ''}
                        onChange={handleInputChange} label="Business Impact Tier" MenuProps={menuProps}
                    >
                        <MenuItem value="tier_1">Tier 1 - Mission Critical</MenuItem>
                        <MenuItem value="tier_2">Tier 2 - Business Critical</MenuItem>
                        <MenuItem value="tier_3">Tier 3 - Important</MenuItem>
                        <MenuItem value="tier_4">Tier 4 - Support</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12}>
                <TextField
                    fullWidth label="Impact of Failure" name="impact_of_failure"
                    value={formData.impact_of_failure || ''} onChange={handleInputChange}
                    multiline rows={2} sx={inputSx}
                />
            </Grid>
            <Grid item xs={12} md={6}>
                <TextField
                    fullWidth label="Stakeholders" name="stakeholders"
                    value={formData.stakeholders || ''} onChange={handleInputChange} sx={inputSx}
                />
            </Grid>
            <Grid item xs={12} md={6}>
                <TextField
                    fullWidth label="System Owners" name="system_owners"
                    value={formData.system_owners || ''} onChange={handleInputChange} sx={inputSx}
                />
            </Grid>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>Peak User Load</InputLabel>
                    <Select
                        name="peak_user_load" value={formData.peak_user_load || ''}
                        onChange={handleInputChange} label="Peak User Load" MenuProps={menuProps}
                    >
                        <MenuItem value="low">Low (&lt;1K)</MenuItem>
                        <MenuItem value="medium">Medium (1K-10K)</MenuItem>
                        <MenuItem value="high">High (10K-100K)</MenuItem>
                        <MenuItem value="very_high">Very High (&gt;100K)</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
                <TextField
                    fullWidth label="Expected User Base" name="expected_user_base"
                    value={formData.expected_user_base || ''} onChange={handleInputChange}
                    placeholder="e.g., 50000" sx={inputSx}
                />
            </Grid>
        </Grid>
    );

    const renderDataCompliance = () => (
        <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>Data Sensitivity</InputLabel>
                    <Select
                        name="data_sensitivity" value={formData.data_sensitivity || ''}
                        onChange={handleInputChange} label="Data Sensitivity" MenuProps={menuProps}
                    >
                        <MenuItem value="public">Public</MenuItem>
                        <MenuItem value="internal">Internal</MenuItem>
                        <MenuItem value="confidential">Confidential</MenuItem>
                        <MenuItem value="restricted">Restricted</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>Data Classification Levels</InputLabel>
                    <Select
                        multiple name="data_classification_levels"
                        value={formData.data_classification_levels || []}
                        onChange={(e) => handleMultiSelectChange('data_classification_levels', e.target.value)}
                        input={<OutlinedInput label="Data Classification Levels" />}
                        MenuProps={menuProps}
                        renderValue={(selected) => (
                            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                                {selected.map((value) => <Chip key={value} label={value} size="small" sx={{ bgcolor: '#374151', color: 'white' }} />)}
                            </Box>
                        )}
                    >
                        <MenuItem value="public">Public</MenuItem>
                        <MenuItem value="internal">Internal</MenuItem>
                        <MenuItem value="confidential">Confidential</MenuItem>
                        <MenuItem value="pii">PII</MenuItem>
                        <MenuItem value="phi">PHI</MenuItem>
                        <MenuItem value="pci">PCI</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>Regulatory Requirements</InputLabel>
                    <Select
                        multiple name="regulatory_requirements"
                        value={formData.regulatory_requirements || []}
                        onChange={(e) => handleMultiSelectChange('regulatory_requirements', e.target.value)}
                        input={<OutlinedInput label="Regulatory Requirements" />}
                        MenuProps={menuProps}
                        renderValue={(selected) => (
                            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                                {selected.map((value) => <Chip key={value} label={value} size="small" sx={{ bgcolor: '#374151', color: 'white' }} />)}
                            </Box>
                        )}
                    >
                        <MenuItem value="gdpr">GDPR</MenuItem>
                        <MenuItem value="hipaa">HIPAA</MenuItem>
                        <MenuItem value="pci_dss">PCI DSS</MenuItem>
                        <MenuItem value="sox">SOX</MenuItem>
                        <MenuItem value="ccpa">CCPA</MenuItem>
                        <MenuItem value="iso_27001">ISO 27001</MenuItem>
                        <MenuItem value="nist">NIST</MenuItem>
                        <MenuItem value="fedramp">FedRAMP</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12}>
                <TextField
                    fullWidth label="Compliance Requirements" name="compliance_requirements"
                    value={formData.compliance_requirements || ''} onChange={handleInputChange}
                    multiline rows={2} sx={inputSx}
                />
            </Grid>
            <Grid item xs={12} md={6}>
                <TextField
                    fullWidth label="Data Retention Period (days)" name="data_retention_period"
                    value={formData.data_retention_period || ''} onChange={handleInputChange}
                    type="number" sx={inputSx}
                />
            </Grid>
            <Grid item xs={12} md={6}>
                <TextField
                    fullWidth label="Data Residency Requirements" name="data_residency_requirements"
                    value={formData.data_residency_requirements || ''} onChange={handleInputChange} sx={inputSx}
                />
            </Grid>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>Disaster Recovery Plan</InputLabel>
                    <Select
                        name="disaster_recovery_plan" value={formData.disaster_recovery_plan || ''}
                        onChange={handleInputChange} label="Disaster Recovery Plan" MenuProps={menuProps}
                    >
                        <MenuItem value="none">None</MenuItem>
                        <MenuItem value="basic">Basic</MenuItem>
                        <MenuItem value="partial">Partial</MenuItem>
                        <MenuItem value="comprehensive">Comprehensive</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>Backup Strategy</InputLabel>
                    <Select
                        name="backup_strategy" value={formData.backup_strategy || ''}
                        onChange={handleInputChange} label="Backup Strategy" MenuProps={menuProps}
                    >
                        <MenuItem value="none">None</MenuItem>
                        <MenuItem value="daily">Daily</MenuItem>
                        <MenuItem value="weekly">Weekly</MenuItem>
                        <MenuItem value="real_time">Real-time</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
        </Grid>
    );

    const renderApplicationDetails = () => (
        <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>Application Type</InputLabel>
                    <Select
                        name="application_type" value={formData.application_type || ''}
                        onChange={handleInputChange} label="Application Type" MenuProps={menuProps}
                    >
                        <MenuItem value="web">Web Application</MenuItem>
                        <MenuItem value="mobile">Mobile Application</MenuItem>
                        <MenuItem value="desktop">Desktop Application</MenuItem>
                        <MenuItem value="api">API/Service</MenuItem>
                        <MenuItem value="hybrid">Hybrid</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>Usage Model</InputLabel>
                    <Select
                        name="usage_model" value={formData.usage_model || ''}
                        onChange={handleInputChange} label="Usage Model" MenuProps={menuProps}
                    >
                        <MenuItem value="internal">Internal Use Only</MenuItem>
                        <MenuItem value="external">External/Public</MenuItem>
                        <MenuItem value="b2b">B2B</MenuItem>
                        <MenuItem value="b2c">B2C</MenuItem>
                        <MenuItem value="hybrid">Hybrid</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>Deployment Model</InputLabel>
                    <Select
                        name="deployment_model" value={formData.deployment_model || ''}
                        onChange={handleInputChange} label="Deployment Model" MenuProps={menuProps}
                    >
                        <MenuItem value="on_premise">On-Premise</MenuItem>
                        <MenuItem value="cloud">Cloud</MenuItem>
                        <MenuItem value="hybrid">Hybrid Cloud</MenuItem>
                        <MenuItem value="saas">SaaS</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>Architecture Pattern</InputLabel>
                    <Select
                        name="architecture_pattern" value={formData.architecture_pattern || ''}
                        onChange={handleInputChange} label="Architecture Pattern" MenuProps={menuProps}
                    >
                        <MenuItem value="monolithic">Monolithic</MenuItem>
                        <MenuItem value="microservices">Microservices</MenuItem>
                        <MenuItem value="serverless">Serverless</MenuItem>
                        <MenuItem value="soa">SOA</MenuItem>
                        <MenuItem value="event_driven">Event-Driven</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12}>
                <Button
                    variant="outlined"
                    component="label"
                    fullWidth
                    startIcon={<CloudUploadIcon />}
                    color={architectureDiagram ? 'success' : errors.architecture_diagram ? 'error' : 'primary'}
                    sx={{
                        height: 56,
                        borderStyle: 'dashed',
                        borderColor: errors.architecture_diagram ? '#ef4444' : '#4b5563',
                        color: architectureDiagram ? '#4ade80' : 'gray.400',
                        '&:hover': {
                            borderColor: '#60a5fa',
                            bgcolor: 'rgba(59, 130, 246, 0.05)'
                        }
                    }}
                >
                    {architectureDiagram ? architectureDiagram.name : 'Upload Architecture Diagram *'}
                    <input
                        type="file"
                        hidden
                        accept="image/*,.pdf"
                        onChange={handleFileChange}
                    />
                </Button>
                {errors.architecture_diagram && (
                    <Typography variant="caption" color="error" sx={{ mt: 0.5, display: 'block' }}>
                        {errors.architecture_diagram}
                    </Typography>
                )}
            </Grid>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>External Dependencies</InputLabel>
                    <Select
                        name="external_dependencies" value={formData.external_dependencies || ''}
                        onChange={handleInputChange} label="External Dependencies" MenuProps={menuProps}
                    >
                        <MenuItem value="none">None</MenuItem>
                        <MenuItem value="minimal">Minimal</MenuItem>
                        <MenuItem value="moderate">Moderate</MenuItem>
                        <MenuItem value="extensive">Extensive</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>Integration Complexity</InputLabel>
                    <Select
                        name="integration_complexity" value={formData.integration_complexity || ''}
                        onChange={handleInputChange} label="Integration Complexity" MenuProps={menuProps}
                    >
                        <MenuItem value="low">Low</MenuItem>
                        <MenuItem value="medium">Medium</MenuItem>
                        <MenuItem value="high">High</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12}>
                <TextField
                    fullWidth label="Third Party Integrations" name="third_party_integrations"
                    value={formData.third_party_integrations || ''} onChange={handleInputChange}
                    multiline rows={2}
                    placeholder="List third-party services, APIs, or integrations"
                    sx={inputSx}
                />
            </Grid>
        </Grid>
    );

    const renderTechnicalStack = () => (
        <Grid container spacing={3}>
            <Grid item xs={12}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>Programming Languages</InputLabel>
                    <Select
                        multiple name="programming_languages"
                        value={formData.programming_languages || []}
                        onChange={(e) => handleMultiSelectChange('programming_languages', e.target.value)}
                        input={<OutlinedInput label="Programming Languages" />}
                        MenuProps={menuProps}
                        renderValue={(selected) => (
                            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                                {selected.map((value) => <Chip key={value} label={value} size="small" sx={{ bgcolor: '#374151', color: 'white' }} />)}
                            </Box>
                        )}
                    >
                        <MenuItem value="javascript">JavaScript</MenuItem>
                        <MenuItem value="typescript">TypeScript</MenuItem>
                        <MenuItem value="python">Python</MenuItem>
                        <MenuItem value="java">Java</MenuItem>
                        <MenuItem value="csharp">C#</MenuItem>
                        <MenuItem value="go">Go</MenuItem>
                        <MenuItem value="ruby">Ruby</MenuItem>
                        <MenuItem value="php">PHP</MenuItem>
                        <MenuItem value="swift">Swift</MenuItem>
                        <MenuItem value="kotlin">Kotlin</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12}>
                <TextField
                    fullWidth label="Frameworks & Versions" name="frameworks_versions"
                    value={formData.frameworks_versions || ''} onChange={handleInputChange}
                    placeholder="e.g., React 18.2, Django 4.1" sx={inputSx}
                />
            </Grid>
            <Grid item xs={12}>
                <TextField
                    fullWidth label="Libraries & Packages" name="libraries_packages"
                    value={formData.libraries_packages || ''} onChange={handleInputChange}
                    multiline rows={2} sx={inputSx}
                />
            </Grid>
            <Grid item xs={12}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>Databases</InputLabel>
                    <Select
                        multiple name="databases"
                        value={formData.databases || []}
                        onChange={(e) => handleMultiSelectChange('databases', e.target.value)}
                        input={<OutlinedInput label="Databases" />}
                        MenuProps={menuProps}
                        renderValue={(selected) => (
                            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                                {selected.map((value) => <Chip key={value} label={value} size="small" sx={{ bgcolor: '#374151', color: 'white' }} />)}
                            </Box>
                        )}
                    >
                        <MenuItem value="postgresql">PostgreSQL</MenuItem>
                        <MenuItem value="mysql">MySQL</MenuItem>
                        <MenuItem value="mongodb">MongoDB</MenuItem>
                        <MenuItem value="redis">Redis</MenuItem>
                        <MenuItem value="mssql">Microsoft SQL Server</MenuItem>
                        <MenuItem value="oracle">Oracle</MenuItem>
                        <MenuItem value="dynamodb">DynamoDB</MenuItem>
                        <MenuItem value="cassandra">Cassandra</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
                <TextField
                    fullWidth label="Software Version" name="software_version"
                    value={formData.software_version || ''} onChange={handleInputChange} sx={inputSx}
                />
            </Grid>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>Legacy Dependencies</InputLabel>
                    <Select
                        name="legacy_dependencies" value={formData.legacy_dependencies || ''}
                        onChange={handleInputChange} label="Legacy Dependencies" MenuProps={menuProps}
                    >
                        <MenuItem value="none">None</MenuItem>
                        <MenuItem value="minimal">Minimal</MenuItem>
                        <MenuItem value="moderate">Moderate</MenuItem>
                        <MenuItem value="extensive">Extensive</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12}>
                <TextField
                    fullWidth label="Deprecated Components" name="deprecated_components"
                    value={formData.deprecated_components || ''} onChange={handleInputChange}
                    multiline rows={2} sx={inputSx}
                />
            </Grid>
        </Grid>
    );

    const renderInfrastructure = () => (
        <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>Hosting Environment</InputLabel>
                    <Select
                        name="hosting_environment" value={formData.hosting_environment || ''}
                        onChange={handleInputChange} label="Hosting Environment" MenuProps={menuProps}
                    >
                        <MenuItem value="aws">AWS</MenuItem>
                        <MenuItem value="azure">Azure</MenuItem>
                        <MenuItem value="gcp">Google Cloud Platform</MenuItem>
                        <MenuItem value="on_premise">On-Premise</MenuItem>
                        <MenuItem value="hybrid">Hybrid</MenuItem>
                        <MenuItem value="other">Other</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>Cloud Services</InputLabel>
                    <Select
                        multiple name="cloud_services"
                        value={formData.cloud_services || []}
                        onChange={(e) => handleMultiSelectChange('cloud_services', e.target.value)}
                        input={<OutlinedInput label="Cloud Services" />}
                        MenuProps={menuProps}
                        renderValue={(selected) => (
                            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                                {selected.map((value) => <Chip key={value} label={value} size="small" sx={{ bgcolor: '#374151', color: 'white' }} />)}
                            </Box>
                        )}
                    >
                        <MenuItem value="ec2">EC2</MenuItem>
                        <MenuItem value="s3">S3</MenuItem>
                        <MenuItem value="rds">RDS</MenuItem>
                        <MenuItem value="lambda">Lambda</MenuItem>
                        <MenuItem value="azure_vm">Azure VM</MenuItem>
                        <MenuItem value="azure_blob">Azure Blob Storage</MenuItem>
                        <MenuItem value="gcp_compute">GCP Compute Engine</MenuItem>
                        <MenuItem value="k8s">Kubernetes</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12}>
                <TextField
                    fullWidth label="Network Architecture" name="network_architecture"
                    value={formData.network_architecture || ''} onChange={handleInputChange}
                    multiline rows={2} sx={inputSx}
                />
            </Grid>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>Deployment Patterns</InputLabel>
                    <Select
                        name="deployment_patterns" value={formData.deployment_patterns || ''}
                        onChange={handleInputChange} label="Deployment Patterns" MenuProps={menuProps}
                    >
                        <MenuItem value="continuous">Continuous Deployment</MenuItem>
                        <MenuItem value="staged">Staged Rollout</MenuItem>
                        <MenuItem value="blue_green">Blue-Green</MenuItem>
                        <MenuItem value="canary">Canary</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>Load Balancing</InputLabel>
                    <Select
                        name="load_balancing" value={formData.load_balancing || ''}
                        onChange={handleInputChange} label="Load Balancing" MenuProps={menuProps}
                    >
                        <MenuItem value="none">None</MenuItem>
                        <MenuItem value="basic">Basic</MenuItem>
                        <MenuItem value="advanced">Advanced</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>Auto Scaling</InputLabel>
                    <Select
                        name="auto_scaling" value={formData.auto_scaling || ''}
                        onChange={handleInputChange} label="Auto Scaling" MenuProps={menuProps}
                    >
                        <MenuItem value="none">None</MenuItem>
                        <MenuItem value="manual">Manual</MenuItem>
                        <MenuItem value="automatic">Automatic</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>Containerization</InputLabel>
                    <Select
                        name="containerization" value={formData.containerization || ''}
                        onChange={handleInputChange} label="Containerization" MenuProps={menuProps}
                    >
                        <MenuItem value="none">None</MenuItem>
                        <MenuItem value="docker">Docker</MenuItem>
                        <MenuItem value="kubernetes">Kubernetes</MenuItem>
                        <MenuItem value="other">Other</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
        </Grid>
    );

    const renderSecurityControls = () => (
        <Grid container spacing={3}>
            <Grid item xs={12}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>Authentication Mechanisms</InputLabel>
                    <Select
                        multiple name="authentication_mechanisms"
                        value={formData.authentication_mechanisms || []}
                        onChange={(e) => handleMultiSelectChange('authentication_mechanisms', e.target.value)}
                        input={<OutlinedInput label="Authentication Mechanisms" />}
                        MenuProps={menuProps}
                        renderValue={(selected) => (
                            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                                {selected.map((value) => <Chip key={value} label={value} size="small" sx={{ bgcolor: '#374151', color: 'white' }} />)}
                            </Box>
                        )}
                    >
                        <MenuItem value="password">Username/Password</MenuItem>
                        <MenuItem value="mfa">Multi-Factor Authentication</MenuItem>
                        <MenuItem value="oauth">OAuth</MenuItem>
                        <MenuItem value="saml">SAML</MenuItem>
                        <MenuItem value="biometric">Biometric</MenuItem>
                        <MenuItem value="api_key">API Key</MenuItem>
                        <MenuItem value="jwt">JWT</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>Authorization Model</InputLabel>
                    <Select
                        name="authorization_model" value={formData.authorization_model || ''}
                        onChange={handleInputChange} label="Authorization Model" MenuProps={menuProps}
                    >
                        <MenuItem value="rbac">RBAC (Role-Based)</MenuItem>
                        <MenuItem value="abac">ABAC (Attribute-Based)</MenuItem>
                        <MenuItem value="dac">DAC (Discretionary)</MenuItem>
                        <MenuItem value="mac">MAC (Mandatory)</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>Session Management</InputLabel>
                    <Select
                        name="session_management" value={formData.session_management || ''}
                        onChange={handleInputChange} label="Session Management" MenuProps={menuProps}
                    >
                        <MenuItem value="none">None</MenuItem>
                        <MenuItem value="basic">Basic</MenuItem>
                        <MenuItem value="advanced">Advanced</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>Encryption at Rest</InputLabel>
                    <Select
                        name="encryption_at_rest" value={formData.encryption_at_rest || ''}
                        onChange={handleInputChange} label="Encryption at Rest" MenuProps={menuProps}
                    >
                        <MenuItem value="none">None</MenuItem>
                        <MenuItem value="basic">Basic</MenuItem>
                        <MenuItem value="advanced">Advanced (AES-256+)</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>Encryption in Transit</InputLabel>
                    <Select
                        name="encryption_in_transit" value={formData.encryption_in_transit || ''}
                        onChange={handleInputChange} label="Encryption in Transit" MenuProps={menuProps}
                    >
                        <MenuItem value="none">None</MenuItem>
                        <MenuItem value="tls_1_2">TLS 1.2</MenuItem>
                        <MenuItem value="tls_1_3">TLS 1.3</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>Input Validation</InputLabel>
                    <Select
                        name="input_validation" value={formData.input_validation || ''}
                        onChange={handleInputChange} label="Input Validation" MenuProps={menuProps}
                    >
                        <MenuItem value="none">None</MenuItem>
                        <MenuItem value="basic">Basic</MenuItem>
                        <MenuItem value="comprehensive">Comprehensive</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>Output Encoding</InputLabel>
                    <Select
                        name="output_encoding" value={formData.output_encoding || ''}
                        onChange={handleInputChange} label="Output Encoding" MenuProps={menuProps}
                    >
                        <MenuItem value="none">None</MenuItem>
                        <MenuItem value="basic">Basic</MenuItem>
                        <MenuItem value="comprehensive">Comprehensive</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>Security Testing</InputLabel>
                    <Select
                        name="security_testing" value={formData.security_testing || ''}
                        onChange={handleInputChange} label="Security Testing" MenuProps={menuProps}
                    >
                        <MenuItem value="none">None</MenuItem>
                        <MenuItem value="manual">Manual</MenuItem>
                        <MenuItem value="automated">Automated</MenuItem>
                        <MenuItem value="both">Both Manual & Automated</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>Vulnerability Scanning</InputLabel>
                    <Select
                        name="vulnerability_scanning" value={formData.vulnerability_scanning || ''}
                        onChange={handleInputChange} label="Vulnerability Scanning" MenuProps={menuProps}
                    >
                        <MenuItem value="none">None</MenuItem>
                        <MenuItem value="periodic">Periodic</MenuItem>
                        <MenuItem value="continuous">Continuous</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>WAF Implementation</InputLabel>
                    <Select
                        name="waf_implementation" value={formData.waf_implementation || ''}
                        onChange={handleInputChange} label="WAF Implementation" MenuProps={menuProps}
                    >
                        <MenuItem value="none">None</MenuItem>
                        <MenuItem value="basic">Basic</MenuItem>
                        <MenuItem value="advanced">Advanced</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>IDS/IPS</InputLabel>
                    <Select
                        name="ids_ips" value={formData.ids_ips || ''}
                        onChange={handleInputChange} label="IDS/IPS" MenuProps={menuProps}
                    >
                        <MenuItem value="none">None</MenuItem>
                        <MenuItem value="ids">IDS Only</MenuItem>
                        <MenuItem value="ips">IPS Only</MenuItem>
                        <MenuItem value="both">Both IDS & IPS</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
        </Grid>
    );

    const renderDevOps = () => (
        <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>SDLC Methodology</InputLabel>
                    <Select
                        name="sdlc_methodology" value={formData.sdlc_methodology || ''}
                        onChange={handleInputChange} label="SDLC Methodology" MenuProps={menuProps}
                    >
                        <MenuItem value="agile">Agile</MenuItem>
                        <MenuItem value="waterfall">Waterfall</MenuItem>
                        <MenuItem value="devops">DevOps</MenuItem>
                        <MenuItem value="hybrid">Hybrid</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>CI/CD Pipeline</InputLabel>
                    <Select
                        name="ci_cd_pipeline" value={formData.ci_cd_pipeline || ''}
                        onChange={handleInputChange} label="CI/CD Pipeline" MenuProps={menuProps}
                    >
                        <MenuItem value="none">None</MenuItem>
                        <MenuItem value="basic">Basic</MenuItem>
                        <MenuItem value="advanced">Advanced</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>Code Review Process</InputLabel>
                    <Select
                        name="code_review_process" value={formData.code_review_process || ''}
                        onChange={handleInputChange} label="Code Review Process" MenuProps={menuProps}
                    >
                        <MenuItem value="none">None</MenuItem>
                        <MenuItem value="manual">Manual</MenuItem>
                        <MenuItem value="automated">Automated</MenuItem>
                        <MenuItem value="both">Both</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>Testing Coverage</InputLabel>
                    <Select
                        name="testing_coverage" value={formData.testing_coverage || ''}
                        onChange={handleInputChange} label="Testing Coverage" MenuProps={menuProps}
                    >
                        <MenuItem value="none">None/Low (&lt;25%)</MenuItem>
                        <MenuItem value="basic">Basic (25-50%)</MenuItem>
                        <MenuItem value="good">Good (50-75%)</MenuItem>
                        <MenuItem value="comprehensive">Comprehensive (&gt;75%)</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>Logging & Monitoring</InputLabel>
                    <Select
                        name="logging_monitoring" value={formData.logging_monitoring || ''}
                        onChange={handleInputChange} label="Logging & Monitoring" MenuProps={menuProps}
                    >
                        <MenuItem value="none">None</MenuItem>
                        <MenuItem value="basic">Basic</MenuItem>
                        <MenuItem value="advanced">Advanced</MenuItem>
                        <MenuItem value="comprehensive">Comprehensive</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>Incident Response Plan</InputLabel>
                    <Select
                        name="incident_response_plan" value={formData.incident_response_plan || ''}
                        onChange={handleInputChange} label="Incident Response Plan" MenuProps={menuProps}
                    >
                        <MenuItem value="none">None</MenuItem>
                        <MenuItem value="basic">Basic</MenuItem>
                        <MenuItem value="documented">Documented</MenuItem>
                        <MenuItem value="tested">Tested & Documented</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>Error Handling Strategy</InputLabel>
                    <Select
                        name="error_handling_strategy" value={formData.error_handling_strategy || ''}
                        onChange={handleInputChange} label="Error Handling Strategy" MenuProps={menuProps}
                    >
                        <MenuItem value="none">None</MenuItem>
                        <MenuItem value="basic">Basic</MenuItem>
                        <MenuItem value="comprehensive">Comprehensive</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={inputSx}>
                    <InputLabel>Change Management Process</InputLabel>
                    <Select
                        name="change_management_process" value={formData.change_management_process || ''}
                        onChange={handleInputChange} label="Change Management Process" MenuProps={menuProps}
                    >
                        <MenuItem value="none">None</MenuItem>
                        <MenuItem value="informal">Informal</MenuItem>
                        <MenuItem value="formal">Formal</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={12}>
                <TextField
                    fullWidth label="Additional Notes" name="additional_notes"
                    value={formData.additional_notes || ''} onChange={handleInputChange}
                    multiline rows={4}
                    placeholder="Any additional context or information about the application"
                    sx={inputSx}
                />
            </Grid>
        </Grid>
    );

    const getSectionContent = () => {
        switch (activeStep) {
            case 0: return renderBusinessContext();
            case 1: return renderDataCompliance();
            case 2: return renderApplicationDetails();
            case 3: return renderTechnicalStack();
            case 4: return renderInfrastructure();
            case 5: return renderSecurityControls();
            case 6: return renderDevOps();
            default: return null;
        }
    };

    return (
        <Box sx={{ maxWidth: 1000, mx: 'auto', pb: 4 }}>
            <Alert
                severity="info"
                sx={{
                    mb: 4,
                    bgcolor: '#1e3a8a', // blue-900 
                    color: '#bfdbfe', // blue-200
                    border: '1px solid #1d4ed8',
                    '& .MuiAlert-icon': { color: '#60a5fa' }
                }}
            >
                Only the architecture diagram is required. All other fields are optional but recommended for a comprehensive assessment.
            </Alert>

            <Stepper activeStep={activeStep} alternativeLabel sx={{ mb: 6 }}>
                {sections.map((label) => (
                    <Step key={label} sx={{
                        '& .MuiStepLabel-label': { color: 'gray.500', '&.Mui-active': { color: 'white', fontWeight: 600 }, '&.Mui-completed': { color: '#10b981' } },
                        '& .MuiStepIcon-root': { color: 'gray.700', '&.Mui-active': { color: '#2563eb' }, '&.Mui-completed': { color: '#10b981' } }
                    }}>
                        <StepLabel>{label}</StepLabel>
                    </Step>
                ))}
            </Stepper>

            <Card sx={{ bgcolor: '#1f2937', border: '1px solid #374151', borderRadius: 2 }}>
                <CardContent sx={{ p: 4 }}>
                    <Typography variant="h5" sx={{ color: 'white', mb: 1, fontWeight: 600 }}>
                        {sections[activeStep]}
                    </Typography>
                    <Divider sx={{ mb: 4, borderColor: '#374151' }} />

                    <Box sx={{ minHeight: 400 }}>
                        {getSectionContent()}
                    </Box>
                </CardContent>
            </Card>

            <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 4 }}>
                <Button
                    disabled={activeStep === 0}
                    onClick={handleBack}
                    startIcon={<NavigateBeforeIcon />}
                    sx={{ color: 'gray.300', '&:disabled': { color: 'gray.700' } }}
                >
                    Back
                </Button>
                <Box>
                    {activeStep === sections.length - 1 ? (
                        <Button
                            variant="contained"
                            onClick={handleSubmit}
                            disabled={isLoading}
                            startIcon={<SendIcon />}
                            sx={{ bgcolor: '#2563eb', '&:hover': { bgcolor: '#1d4ed8' } }}
                        >
                            {isLoading ? 'Submitting...' : 'Submit Assessment'}
                        </Button>
                    ) : (
                        <Button
                            variant="contained"
                            onClick={handleNext}
                            endIcon={<NavigateNextIcon />}
                            sx={{ bgcolor: '#2563eb', '&:hover': { bgcolor: '#1d4ed8' } }}
                        >
                            Next
                        </Button>
                    )}
                </Box>
            </Box>
        </Box>
    );
};

export default AssessmentForm;
