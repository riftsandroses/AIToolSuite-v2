import React from "react";
import {
    Box,
    Typography,
    Chip,
    LinearProgress,
    linearProgressClasses,
    Paper,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    List,
    ListItem,
    ListItemIcon,
    ListItemText,
    Divider,
} from "@mui/material";
import { styled } from "@mui/material/styles";
import AssessmentIcon from "@mui/icons-material/Assessment";
import WarningAmberIcon from "@mui/icons-material/WarningAmber";
import CheckCircleOutlineIcon from "@mui/icons-material/CheckCircleOutline";
import SecurityIcon from "@mui/icons-material/Security"; // For MITRE
import RiskChip from "./RiskChip"; // We'll reuse your existing RiskChip

// --- Static Demo Data for "Superfast Bank Data Mining Tool" ---
const staticAssessmentData = {
    application_name: "Superfast Bank - Data Miner",
    risk_score: 82, // Hardcoded score for "High Risk"
    vulnerabilities: [
        {
            id: 1,
            component: "pandas",
            version: "1.5.3",
            cve: "CVE-2024-34341",
            severity: "High",
            summary: "Arbitrary file read vulnerability via crafted Excel files.",
        },
        {
            id: 2,
            component: "psycopg2-binary",
            version: "2.9.1",
            cve: "CVE-2022-31101",
            severity: "Medium",
            summary: "SQL injection vulnerability in 'format_binary' function.",
        },
        {
            id: 3,
            component: "Django",
            version: "4.1.7",
            cve: "CVE-2023-46695",
            severity: "Low",
            summary: "Potential Denial-of-Service (DoS) in 'intcomma' template filter.",
        },
    ],
    mitigations: [
        {
            id: 1,
            recommendation: "Upgrade 'pandas' library",
            details:
                "Upgrade pandas from v1.5.3 to v2.2.2 or later to patch the arbitrary file read vulnerability (CVE-2024-34341).",
        },
        {
            id: 2,
            recommendation: "Upgrade PostgreSQL Driver",
            details:
                "Upgrade 'psycopg2-binary' from v2.9.1 to v2.9.4 or later to mitigate the SQL injection risk (CVE-2022-31101).",
        },
        {
            id: 3,
            recommendation: "Implement Strict Query Parameterization",
            details:
                "Rely on Django's ORM and avoid raw SQL queries where possible. All user-controlled inputs must be parameterized.",
        },
    ],
    mitreSoTRisks: [
        {
            id: "SoT-1",
            risk: "Using Vulnerable Components",
            example:
                "The tool's core dependency, `pandas` v1.5.3, has a known 'High' severity vulnerability (CVE-2024-34341).",
            mitigation:
                "Implement a Software Bill of Materials (SBOM) and integrate continuous vulnerability scanning (e.g., Snyk, Dependabot) into the CI/CD pipeline.",
        },
        {
            id: "SoT-3",
            risk: "Compromised Build Process",
            example:
                "The build pipeline pulls dependencies directly from the public PyPI repository without verifying package signatures or hashes.",
            mitigation:
                "Use a private artifact repository (e.g., Artifactory, Nexus) as a proxy. Enforce dependency hash-checking in `requirements.txt`.",
        },
        {
            id: "SoT-5",
            risk: "Insufficient Dependency Management",
            example:
                "The `requirements.txt` file contains several unpinned dependencies (e.g., `numpy>=1.20`), leading to non-deterministic builds.",
            mitigation:
                "Pin all dependencies to specific, vetted versions (e.g., `pandas==2.2.2`). Use tools like `pip-compile` or `Poetry` to manage lock files.",
        },
    ],
};
// --- End of Static Data ---

const BorderLinearProgress = styled(LinearProgress)(
    ({ theme, componentcolor }) => ({
        height: 15,
        borderRadius: 7,
        [`&.${linearProgressClasses.colorPrimary}`]: {
            backgroundColor:
                theme.palette.grey[theme.palette.mode === "light" ? 300 : 800],
        },
        [`& .${linearProgressClasses.bar}`]: {
            borderRadius: 7,
            backgroundColor: theme.palette[componentcolor]
                ? theme.palette[componentcolor].main
                : theme.palette.primary.main,
        },
    })
);

const StaticRiskAnalysis = () => {
    const riskScore = staticAssessmentData.risk_score;

    const getRiskSeverity = (score) => {
        if (score > 70) return "error";
        if (score > 40) return "warning";
        return "success";
    };

    const getRiskLabelText = (score) => {
        if (score > 70) return "High Risk";
        if (score > 40) return "Medium Risk";
        return "Low Risk";
    };

    const currentRiskSeverity = getRiskSeverity(riskScore);
    const currentRiskLabel = getRiskLabelText(riskScore);

    return (
        <Box sx={{ p: 3 }}>
            <Typography variant="h5" component="h4" sx={{ mb: 3, fontWeight: 600 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <AssessmentIcon />
                    Risk Analysis for: {staticAssessmentData.application_name}
                </Box>
            </Typography>

            {/* --- Overall Score (Same as before) --- */}
            <Typography
                variant="h6"
                component="h5"
                sx={{ mt: 2, mb: 2, fontWeight: 500 }}
            >
                Overall Risk Score
            </Typography>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                <Typography
                    variant="h2"
                    component="span"
                    sx={{ color: `${currentRiskSeverity}.main`, fontWeight: "bold" }}
                >
                    {riskScore?.toFixed(0) || 0}
                </Typography>
                <Chip
                    label={currentRiskLabel}
                    color={currentRiskSeverity}
                    sx={{ fontWeight: "medium" }}
                />
            </Box>
            <BorderLinearProgress
                variant="determinate"
                value={riskScore}
                componentcolor={currentRiskSeverity}
            />
            <Typography
                variant="body2"
                sx={{ mt: 1, mb: 4, color: `${currentRiskSeverity}.main` }}
            >
                {`Based on the provided information, this application is considered ${currentRiskLabel.toLowerCase()}.`}
            </Typography>

            <Divider sx={{ my: 4 }} />

            {/* --- Vulnerable Components Section --- */}
            <Typography
                variant="h6"
                component="h5"
                sx={{ mt: 2, mb: 2, fontWeight: 500, display: "flex", alignItems: "center" }}
            >
                <WarningAmberIcon color="error" sx={{ mr: 1 }} />
                Vulnerable Components Identified
            </Typography>
            <TableContainer component={Paper} variant="outlined">
                <Table sx={{ minWidth: 650 }} aria-label="vulnerability table">
                    <TableHead sx={{ bgcolor: "action.hover" }}>
                        <TableRow>
                            <TableCell>Severity</TableCell>
                            <TableCell>Component</TableCell>
                            <TableCell>Version</TableCell>
                            <TableCell>Identifier</TableCell>
                            <TableCell>Summary</TableCell>
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        {staticAssessmentData.vulnerabilities.map((vuln) => (
                            <TableRow key={vuln.id}>
                                <TableCell>
                                    <RiskChip
                                        label={vuln.severity}
                                        risklevel={vuln.severity}
                                        size="small"
                                    />
                                </TableCell>
                                <TableCell>{vuln.component}</TableCell>
                                <TableCell>{vuln.version}</TableCell>
                                <TableCell>{vuln.cve}</TableCell>
                                <TableCell>{vuln.summary}</TableCell>
                            </TableRow>
                        ))}
                    </TableBody>
                </Table>
            </TableContainer>

            {/* --- NEW: OSRA Risks (MITRE SoT Framework) --- */}
            <Typography
                variant="h6"
                component="h5"
                sx={{ mt: 5, mb: 2, fontWeight: 500, display: "flex", alignItems: "center" }}
            >
                <SecurityIcon color="primary" sx={{ mr: 1 }} />
                OSRA Risks
            </Typography>
            <TableContainer component={Paper} variant="outlined">
                <Table sx={{ minWidth: 650 }} aria-label="mitre sot table">
                    <TableHead sx={{ bgcolor: "action.hover" }}>
                        <TableRow>
                            <TableCell>SoT Risk</TableCell>
                            <TableCell>Example in Context</TableCell>
                            <TableCell>Suggested Mitigation</TableCell>
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        {staticAssessmentData.mitreSoTRisks.map((risk) => (
                            <TableRow key={risk.id}>
                                <TableCell sx={{ fontWeight: 500 }}>{risk.risk}</TableCell>
                                <TableCell>{risk.example}</TableCell>
                                <TableCell>{risk.mitigation}</TableCell>
                            </TableRow>
                        ))}
                    </TableBody>
                </Table>
            </TableContainer>
            {/* --- END OF NEW SECTION --- */}


            {/* --- Suggested Mitigations Section --- */}
            <Typography
                variant="h6"
                component="h5"
                sx={{ mt: 5, mb: 2, fontWeight: 500, display: "flex", alignItems: "center" }}
            >
                <CheckCircleOutlineIcon color="success" sx={{ mr: 1 }} />
                Suggested Mitigations
            </Typography>
            <Paper variant="outlined">
                <List disablePadding>
                    {staticAssessmentData.mitigations.map((item, index) => (
                        <React.Fragment key={item.id}>
                            <ListItem alignItems="flex-start">
                                <ListItemIcon sx={{ minWidth: 40, mt: 0.5 }}>
                                    <CheckCircleOutlineIcon color="success" fontSize="small" />
                                </ListItemIcon>
                                <ListItemText
                                    primary={
                                        <Typography variant="body1" sx={{ fontWeight: 500 }}>
                                            {item.recommendation}
                                        </Typography>
                                    }
                                    secondary={item.details}
                                />
                            </ListItem>
                            {index < staticAssessmentData.mitigations.length - 1 && (
                                <Divider component="li" />
                            )}
                        </React.Fragment>
                    ))}
                </List>
            </Paper>
        </Box>
    );
};

export default StaticRiskAnalysis;