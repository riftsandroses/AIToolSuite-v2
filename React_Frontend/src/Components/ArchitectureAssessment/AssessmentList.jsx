import React from 'react';
import {
    Box,
    Typography,
    List,
    ListItem,
    ListItemButton,
    ListItemText,
    ListItemSecondaryAction,
    IconButton,
    Divider,
    Tooltip,
    Chip,
    Stack,
    styled
} from '@mui/material';
import {
    Assessment as AssessmentIcon,
    Delete as DeleteIcon,
    Edit as EditIcon,
    Add as AddIcon
} from '@mui/icons-material';

const StyledSidebar = styled(Box)(({ theme }) => ({
    width: 320,
    backgroundColor: theme.palette.background.paper,
    borderRight: `1px solid ${theme.palette.divider}`,
    height: '100%',
    overflowY: 'auto',
    [theme.breakpoints.down('md')]: {
        width: 280,
    },
}));

const StyledListItem = styled(ListItemButton)(({ theme }) => ({
    borderRadius: theme.shape.borderRadius,
    marginBottom: theme.spacing(1),
    '&:hover': {
        backgroundColor: 'rgba(144, 202, 249, 0.08)',
    },
    '&.Mui-selected': {
        backgroundColor: 'rgba(144, 202, 249, 0.16)',
        '&:hover': {
            backgroundColor: 'rgba(144, 202, 249, 0.24)',
        },
    },
}));

const AssessmentList = ({
    assessments,
    selectedAssessment,
    onSelectAssessment,
    onDeleteAssessment,
    onEditAssessment,
    onNewAssessment
}) => {
    const getRiskLevel = (score) => {
        if (!score) return { level: 'Unknown', color: 'default' };
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

    return (
        <StyledSidebar>
            <Box sx={{ p: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Typography variant="h6">Assessments</Typography>
                <Tooltip title="New Assessment">
                    <IconButton color="primary" size="small" onClick={onNewAssessment}>
                        <AddIcon />
                    </IconButton>
                </Tooltip>
            </Box>
            <Divider />
            <List sx={{ p: 1 }}>
                {assessments && assessments.length > 0 ? (
                    assessments.map((assessment) => {
                        const riskInfo = getRiskLevel(assessment.overall_risk_score);
                        const isSelected = selectedAssessment?.id === assessment.id;

                        return (
                            <ListItem key={assessment.id} disablePadding>
                                <StyledListItem
                                    selected={isSelected}
                                    onClick={() => onSelectAssessment(assessment)}
                                >
                                    <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1.5, width: '100%', pr: 6 }}>
                                        <AssessmentIcon color="primary" sx={{ mt: 0.5 }} />
                                        <Box sx={{ flex: 1, minWidth: 0 }}>
                                            <Typography
                                                variant="body1"
                                                fontWeight={500}
                                                sx={{
                                                    overflow: 'hidden',
                                                    textOverflow: 'ellipsis',
                                                    display: '-webkit-box',
                                                    WebkitLineClamp: 2,
                                                    WebkitBoxOrient: 'vertical',
                                                }}
                                            >
                                                {assessment.application_purpose || 'Unnamed Assessment'}
                                            </Typography>
                                            <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 0.5 }}>
                                                {new Date(assessment.created_at).toLocaleDateString()}
                                            </Typography>
                                            <Stack direction="row" spacing={0.5} sx={{ mt: 1 }} flexWrap="wrap">
                                                <Chip
                                                    label={assessment.status || 'Unknown'}
                                                    color={getStatusColor(assessment.status)}
                                                    size="small"
                                                    sx={{ height: 20, fontSize: '0.7rem' }}
                                                />
                                                {assessment.overall_risk_score != null && (
                                                    <Chip
                                                        label={riskInfo.level}
                                                        color={riskInfo.color}
                                                        size="small"
                                                        sx={{ height: 20, fontSize: '0.7rem' }}
                                                    />
                                                )}
                                                {assessment.vulnerability_count != null && (
                                                    <Chip
                                                        label={`${assessment.vulnerability_count} vulns`}
                                                        size="small"
                                                        variant="outlined"
                                                        sx={{ height: 20, fontSize: '0.7rem' }}
                                                    />
                                                )}
                                            </Stack>
                                        </Box>
                                    </Box>
                                    <ListItemSecondaryAction>
                                        <Tooltip title="Edit">
                                            <IconButton
                                                edge="end"
                                                size="small"
                                                onClick={(e) => {
                                                    e.stopPropagation();
                                                    onEditAssessment(assessment);
                                                }}
                                                sx={{ mr: 0.5 }}
                                            >
                                                <EditIcon fontSize="small" />
                                            </IconButton>
                                        </Tooltip>
                                        <Tooltip title="Delete">
                                            <IconButton
                                                edge="end"
                                                size="small"
                                                onClick={(e) => {
                                                    e.stopPropagation();
                                                    onDeleteAssessment(assessment.id);
                                                }}
                                            >
                                                <DeleteIcon fontSize="small" />
                                            </IconButton>
                                        </Tooltip>
                                    </ListItemSecondaryAction>
                                </StyledListItem>
                            </ListItem>
                        );
                    })
                ) : (
                    <ListItem>
                        <ListItemText
                            primary="No assessments yet"
                            secondary="Click + to create one"
                            primaryTypographyProps={{ align: 'center', color: 'text.secondary' }}
                            secondaryTypographyProps={{ align: 'center' }}
                        />
                    </ListItem>
                )}
            </List>
        </StyledSidebar>
    );
};

export default AssessmentList;
