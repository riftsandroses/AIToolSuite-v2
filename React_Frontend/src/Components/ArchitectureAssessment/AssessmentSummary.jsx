import React from 'react';
import {
    Card,
    CardContent,
    Typography,
    Box,
    LinearProgress,
    Chip,
    Grid,
    Stack,
    Divider
} from '@mui/material';
import {
    Assessment as AssessmentIcon,
    TrendingUp as TrendingUpIcon,
    Security as SecurityIcon,
    Warning as WarningIcon
} from '@mui/icons-material';

const AssessmentSummary = ({ assessment }) => {
    const getRiskLevel = (score) => {
        if (score >= 70) return { level: 'High', color: 'error' };
        if (score >= 40) return { level: 'Medium', color: 'warning' };
        return { level: 'Low', color: 'success' };
    };

    const getStatusColor = (status) => {
        switch (status?.toLowerCase()) {
            case 'completed':
                return 'success';
            case 'processing':
                return 'info';
            case 'failed':
                return 'error';
            case 'pending':
                return 'warning';
            default:
                return 'default';
        }
    };

    const riskInfo = getRiskLevel(assessment.overall_risk_score || 0);
    const vulnerabilitySummary = assessment.vulnerability_summary || {};

    return (
        <Card sx={{ mb: 3 }}>
            <CardContent>
                {/* Header */}
                <Box display="flex" alignItems="center" mb={3}>
                    <AssessmentIcon color="primary" sx={{ fontSize: 32, mr: 2 }} />
                    <Box flex={1}>
                        <Typography variant="h5" gutterBottom>
                            {assessment.application_purpose || 'Architecture Assessment'}
                        </Typography>
                        <Stack direction="row" spacing={1}>
                            <Chip
                                label={assessment.status || 'Unknown'}
                                color={getStatusColor(assessment.status)}
                                size="small"
                            />
                            <Chip
                                label={`Created: ${new Date(assessment.created_at).toLocaleDateString()}`}
                                size="small"
                                variant="outlined"
                            />
                        </Stack>
                    </Box>
                </Box>

                <Divider sx={{ my: 2 }} />

                {/* Risk Score Section */}
                <Box mb={3}>
                    <Typography variant="h6" gutterBottom>
                        Overall Risk Score
                    </Typography>
                    <Box display="flex" alignItems="center" mb={1}>
                        <Typography
                            variant="h3"
                            color={`${riskInfo.color}.main`}
                            sx={{ mr: 2, fontWeight: 'bold' }}
                        >
                            {assessment.overall_risk_score || 0}
                        </Typography>
                        <Chip
                            label={`${riskInfo.level} Risk`}
                            color={riskInfo.color}
                            icon={<TrendingUpIcon />}
                        />
                    </Box>
                    <LinearProgress
                        variant="determinate"
                        value={assessment.overall_risk_score || 0}
                        color={riskInfo.color}
                        sx={{ height: 10, borderRadius: 5 }}
                    />
                    {assessment.risk_reasoning && (
                        <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
                            {assessment.risk_reasoning.substring(0, 300)}
                            {assessment.risk_reasoning.length > 300 && '...'}
                        </Typography>
                    )}
                </Box>

                <Divider sx={{ my: 2 }} />

                {/* Vulnerability Summary */}
                <Box>
                    <Typography variant="h6" gutterBottom display="flex" alignItems="center">
                        <SecurityIcon sx={{ mr: 1 }} />
                        Vulnerability Summary
                    </Typography>
                    <Grid container spacing={2}>
                        <Grid item xs={6} sm={4} md={2.4}>
                            <Card variant="outlined" sx={{ textAlign: 'center', p: 2 }}>
                                <Typography variant="h4" fontWeight="bold">
                                    {vulnerabilitySummary.total || 0}
                                </Typography>
                                <Typography variant="body2" color="text.secondary">
                                    Total
                                </Typography>
                            </Card>
                        </Grid>
                        <Grid item xs={6} sm={4} md={2.4}>
                            <Card variant="outlined" sx={{ textAlign: 'center', p: 2, bgcolor: 'error.dark' }}>
                                <Typography variant="h4" fontWeight="bold" color="white">
                                    {vulnerabilitySummary.critical || 0}
                                </Typography>
                                <Typography variant="body2" color="white">
                                    Critical
                                </Typography>
                            </Card>
                        </Grid>
                        <Grid item xs={6} sm={4} md={2.4}>
                            <Card variant="outlined" sx={{ textAlign: 'center', p: 2, bgcolor: 'error.main' }}>
                                <Typography variant="h4" fontWeight="bold" color="white">
                                    {vulnerabilitySummary.high || 0}
                                </Typography>
                                <Typography variant="body2" color="white">
                                    High
                                </Typography>
                            </Card>
                        </Grid>
                        <Grid item xs={6} sm={4} md={2.4}>
                            <Card variant="outlined" sx={{ textAlign: 'center', p: 2, bgcolor: 'warning.main' }}>
                                <Typography variant="h4" fontWeight="bold" color="white">
                                    {vulnerabilitySummary.medium || 0}
                                </Typography>
                                <Typography variant="body2" color="white">
                                    Medium
                                </Typography>
                            </Card>
                        </Grid>
                        <Grid item xs={6} sm={4} md={2.4}>
                            <Card variant="outlined" sx={{ textAlign: 'center', p: 2, bgcolor: 'info.main' }}>
                                <Typography variant="h4" fontWeight="bold" color="white">
                                    {vulnerabilitySummary.low || 0}
                                </Typography>
                                <Typography variant="body2" color="white">
                                    Low
                                </Typography>
                            </Card>
                        </Grid>
                    </Grid>
                </Box>

                {/* Additional Metadata */}
                {(assessment.business_objectives || assessment.stakeholders || assessment.compliance_requirements) && (
                    <>
                        <Divider sx={{ my: 2 }} />
                        <Box>
                            <Typography variant="h6" gutterBottom>
                                Business Context
                            </Typography>
                            {assessment.business_objectives && (
                                <Typography variant="body2" color="text.secondary" paragraph>
                                    <strong>Objectives:</strong> {assessment.business_objectives}
                                </Typography>
                            )}
                            {assessment.stakeholders && (
                                <Typography variant="body2" color="text.secondary" paragraph>
                                    <strong>Stakeholders:</strong> {assessment.stakeholders}
                                </Typography>
                            )}
                            {assessment.system_owners && (
                                <Typography variant="body2" color="text.secondary" paragraph>
                                    <strong>System Owners:</strong> {assessment.system_owners}
                                </Typography>
                            )}
                            {assessment.compliance_requirements && (
                                <Typography variant="body2" color="text.secondary">
                                    <strong>Compliance:</strong> {assessment.compliance_requirements}
                                </Typography>
                            )}
                        </Box>
                    </>
                )}
            </CardContent>
        </Card>
    );
};

export default AssessmentSummary;
