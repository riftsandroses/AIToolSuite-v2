import React, { useState, useEffect } from 'react';
import {
    Grid,
    Card,
    CardContent,
    Typography,
    Box,
    CircularProgress,
    Button,
    LinearProgress
} from '@mui/material';
import {
    Shield,
    AlertTriangle,
    CheckCircle,
    Activity,
    Plus,
    Target,
    Layers
} from 'lucide-react';
import { getStatistics } from '../../../api/architectureAssessmentService';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, PieChart, Pie } from 'recharts';

const StatCard = ({ title, value, icon: Icon, color, subtext }) => (
    <Card sx={{ height: '100%', bgcolor: '#1f2937', color: 'white', border: '1px solid #374151' }}>
        <CardContent>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
                <Box sx={{ p: 1.5, borderRadius: 2, bgcolor: `${color}20` }}>
                    <Icon color={color} size={24} />
                </Box>
                {subtext && (
                    <Typography variant="caption" sx={{ color: 'gray.400' }}>
                        {subtext}
                    </Typography>
                )}
            </Box>
            <Typography variant="h4" sx={{ fontWeight: 'bold', mb: 1 }}>
                {value}
            </Typography>
            <Typography variant="body2" sx={{ color: 'gray.400' }}>
                {title}
            </Typography>
        </CardContent>
    </Card>
);

const AssessmentDashboard = ({ onCreateNew }) => {
    const [stats, setStats] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        loadStats();
    }, []);

    const loadStats = async () => {
        try {
            const data = await getStatistics();
            setStats(data);
        } catch (error) {
            console.error("Failed to load statistics", error);
        } finally {
            setLoading(false);
        }
    };

    if (loading) {
        return (
            <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh', bgcolor: '#111827' }}>
                <CircularProgress />
            </Box>
        );
    }

    if (!stats) return null;

    const riskData = [
        { name: 'High Risk', value: stats.assessments.high_risk, color: '#ef4444' },
        { name: 'Medium Risk', value: stats.assessments.medium_risk, color: '#f59e0b' },
        { name: 'Low Risk', value: stats.assessments.low_risk, color: '#10b981' }
    ];

    const vulnData = [
        { name: 'Critical', value: stats.vulnerabilities.critical, color: '#991b1b' },
        { name: 'High', value: stats.vulnerabilities.high, color: '#ef4444' },
        { name: 'Fixed', value: stats.vulnerabilities.fixed, color: '#10b981' },
        { name: 'Open', value: stats.vulnerabilities.open, color: '#3b82f6' }
    ];

    return (
        <Box sx={{ p: 4, bgcolor: '#111827', minHeight: '100vh', color: 'white' }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 4 }}>
                <div>
                    <Typography variant="h4" sx={{ fontWeight: 'bold', mb: 1 }}>
                        Architecture Security Dashboard
                    </Typography>
                    <Typography variant="body1" sx={{ color: 'gray.400' }}>
                        Overview of your application security posture
                    </Typography>
                </div>
                <Button
                    variant="contained"
                    startIcon={<Plus />}
                    onClick={onCreateNew}
                    sx={{ bgcolor: '#2563eb', '&:hover': { bgcolor: '#1d4ed8' } }}
                >
                    New Assessment
                </Button>
            </Box>

            <Grid container spacing={3} sx={{ mb: 4 }}>
                <Grid item xs={12} sm={6} md={3}>
                    <StatCard
                        title="Total Assessments"
                        value={stats.assessments.total}
                        icon={Shield}
                        color="#3b82f6"
                    />
                </Grid>
                <Grid item xs={12} sm={6} md={3}>
                    <StatCard
                        title="Critical Vulnerabilities"
                        value={stats.vulnerabilities.critical}
                        icon={AlertTriangle}
                        color="#ef4444"
                    />
                </Grid>
                <Grid item xs={12} sm={6} md={3}>
                    <StatCard
                        title="Fixed Issues"
                        value={stats.vulnerabilities.fixed}
                        icon={CheckCircle}
                        color="#10b981"
                    />
                </Grid>
                <Grid item xs={12} sm={6} md={3}>
                    <StatCard
                        title="Avg Risk Score"
                        // Assuming stats might have this or calculate it
                        value="N/A"
                        icon={Activity}
                        color="#f59e0b"
                    />
                </Grid>
            </Grid>

            <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                    <Card sx={{ bgcolor: '#1f2937', border: '1px solid #374151', height: '400px' }}>
                        <CardContent sx={{ height: '100%' }}>
                            <Typography variant="h6" sx={{ color: 'white', mb: 2 }}>
                                Risk Distribution
                            </Typography>
                            <ResponsiveContainer width="100%" height="85%">
                                <PieChart>
                                    <Pie
                                        data={riskData}
                                        cx="50%"
                                        cy="50%"
                                        innerRadius={60}
                                        outerRadius={80}
                                        paddingAngle={5}
                                        dataKey="value"
                                    >
                                        {riskData.map((entry, index) => (
                                            <Cell key={`cell-${index}`} fill={entry.color} />
                                        ))}
                                    </Pie>
                                    <Tooltip
                                        contentStyle={{ backgroundColor: '#1f2937', borderColor: '#374151', color: 'white' }}
                                        itemStyle={{ color: 'white' }}
                                    />
                                </PieChart>
                            </ResponsiveContainer>
                        </CardContent>
                    </Card>
                </Grid>

                <Grid item xs={12} md={6}>
                    <Card sx={{ bgcolor: '#1f2937', border: '1px solid #374151', height: '400px' }}>
                        <CardContent sx={{ height: '100%' }}>
                            <Typography variant="h6" sx={{ color: 'white', mb: 2 }}>
                                Vulnerabilities by Category
                            </Typography>
                            <ResponsiveContainer width="100%" height="85%">
                                <BarChart data={stats.top_categories} layout="vertical">
                                    <XAxis type="number" hide />
                                    <YAxis
                                        dataKey="category_tag"
                                        type="category"
                                        width={150}
                                        tick={{ fill: '#9ca3af', fontSize: 12 }}
                                    />
                                    <Tooltip
                                        cursor={{ fill: 'transparent' }}
                                        contentStyle={{ backgroundColor: '#1f2937', borderColor: '#374151', color: 'white' }}
                                    />
                                    <Bar dataKey="count" fill="#3b82f6" radius={[0, 4, 4, 0]} barSize={20} />
                                </BarChart>
                            </ResponsiveContainer>
                        </CardContent>
                    </Card>
                </Grid>
            </Grid>
        </Box>
    );
};

export default AssessmentDashboard;
