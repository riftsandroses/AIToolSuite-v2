import React, { useState, useEffect } from 'react';
import {
    Search,
    Plus,
    FileText,
    Clock,
    CheckCircle,
    AlertCircle,
    MoreVertical,
    Trash2,
    Download
} from 'lucide-react';
import {
    Box,
    Typography,
    TextField,
    InputAdornment,
    IconButton,
    List,
    ListItem,
    ListItemText,
    ListItemAvatar,
    Avatar,
    Menu,
    MenuItem,
    Chip,
    CircularProgress,
    Tooltip,
    Button
} from '@mui/material';

const AssessmentHistoryList = ({
    assessments,
    loading,
    selectedId,
    onSelect,
    onCreateNew,
    onDelete,
    onDownload
}) => {
    const [searchTerm, setSearchTerm] = useState('');
    const [anchorEl, setAnchorEl] = useState(null);
    const [menuTargetId, setMenuTargetId] = useState(null);

    const handleMenuOpen = (event, id) => {
        event.stopPropagation();
        setAnchorEl(event.currentTarget);
        setMenuTargetId(id);
    };

    const handleMenuClose = () => {
        setAnchorEl(null);
        setMenuTargetId(null);
    };

    const handleDeleteClick = (e) => {
        e.stopPropagation();
        handleMenuClose();
        if (menuTargetId) {
            onDelete(menuTargetId);
        }
    };

    const handleDownloadClick = (e) => {
        e.stopPropagation();
        handleMenuClose();
        if (menuTargetId) {
            onDownload(menuTargetId);
        }
    };

    const getStatusColor = (status) => {
        switch (status) {
            case 'completed': return 'success';
            case 'in_progress': return 'warning';
            case 'failed': return 'error';
            default: return 'default';
        }
    };

    const getRiskColor = (score) => {
        if (score >= 80) return 'error';
        if (score >= 50) return 'warning';
        return 'success';
    };

    const filteredAssessments = assessments.filter(assessment =>
        (assessment.application_purpose && assessment.application_purpose.toLowerCase().includes(searchTerm.toLowerCase())) ||
        (assessment.status && assessment.status.toLowerCase().includes(searchTerm.toLowerCase()))
    );

    return (
        <Box sx={{
            height: '100%',
            display: 'flex',
            flexDirection: 'column',
            backgroundColor: '#1f2937', // git-gray-800
            borderRight: '1px solid #374151' // git-gray-700
        }}>
            {/* Header */}
            <Box sx={{ p: 2, borderBottom: '1px solid #374151' }}>
                {/* <Button
                    fullWidth
                    variant="contained"
                    startIcon={<Plus size={20} />}
                    onClick={onCreateNew}
                    sx={{
                        mb: 2,
                        bgcolor: '#2563eb', // blue-600
                        '&:hover': { bgcolor: '#1d4ed8' } // blue-700
                    }}
                >
                    New Assessment
                </Button> */}
                <TextField
                    fullWidth
                    placeholder="Search assessments..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    size="small"
                    InputProps={{
                        startAdornment: (
                            <InputAdornment position="start">
                                <Search size={18} className="text-gray-400" />
                            </InputAdornment>
                        ),
                        sx: {
                            bgcolor: '#374151',
                            color: 'white',
                            '& fieldset': { border: 'none' }
                        }
                    }}
                />
            </Box>

            {/* List */}
            <Box sx={{ flexGrow: 1, overflowY: 'auto' }}>
                {loading ? (
                    <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
                        <CircularProgress size={24} />
                    </Box>
                ) : filteredAssessments.length === 0 ? (
                    <Box sx={{ p: 3, textAlign: 'center' }}>
                        <Typography variant="body2" color="text.secondary">
                            No assessments found
                        </Typography>
                    </Box>
                ) : (
                    <List sx={{ p: 0 }}>
                        {filteredAssessments.map((assessment) => (
                            <ListItem
                                key={assessment.id}
                                button
                                onClick={() => onSelect(assessment.id)}
                                selected={selectedId === assessment.id}
                                sx={{
                                    borderBottom: '1px solid #374151',
                                    '&.Mui-selected': {
                                        bgcolor: '#374151', // gray-700
                                        '&:hover': { bgcolor: '#4b5563' } // gray-600
                                    },
                                    '&:hover': {
                                        bgcolor: '#374151'
                                    }
                                }}
                                secondaryAction={
                                    <IconButton
                                        edge="end"
                                        onClick={(e) => handleMenuOpen(e, assessment.id)}
                                        size="small"
                                        sx={{ color: 'text.secondary' }}
                                    >
                                        <MoreVertical size={16} />
                                    </IconButton>
                                }
                            >
                                <ListItemAvatar>
                                    <Avatar sx={{
                                        bgcolor: assessment.overall_risk_score >= 80 ? '#991b1b' : // red-800
                                            assessment.overall_risk_score >= 50 ? '#92400e' : // amber-800
                                                '#166534' // green-800
                                    }}>
                                        <FileText size={20} />
                                    </Avatar>
                                </ListItemAvatar>
                                <ListItemText
                                    primary={
                                        <Typography variant="subtitle2" sx={{ color: 'white', fontWeight: 'bold' }} noWrap>
                                            {assessment.application_purpose}
                                        </Typography>
                                    }
                                    secondary={
                                        <Box component="span" sx={{ display: 'flex', flexDirection: 'column', gap: 0.5, mt: 0.5 }}>
                                            <Box component="span" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                                <Clock size={12} className="text-gray-400" />
                                                <Typography variant="caption" color="gray">
                                                    {new Date(assessment.created_at).toLocaleDateString()}
                                                </Typography>
                                            </Box>
                                            <Box component="span" sx={{ display: 'flex', gap: 1 }}>
                                                <Chip
                                                    label={`Score: ${assessment.overall_risk_score}`}
                                                    size="small"
                                                    color={getRiskColor(assessment.overall_risk_score)}
                                                    sx={{ height: 20, fontSize: '0.65rem' }}
                                                />
                                                <Chip
                                                    label={assessment.status}
                                                    size="small"
                                                    color={getStatusColor(assessment.status)}
                                                    variant="outlined"
                                                    sx={{ height: 20, fontSize: '0.65rem' }}
                                                />
                                            </Box>
                                        </Box>
                                    }
                                />
                            </ListItem>
                        ))}
                    </List>
                )}
            </Box>

            <Menu
                anchorEl={anchorEl}
                open={Boolean(anchorEl)}
                onClose={handleMenuClose}
                transformOrigin={{ horizontal: 'right', vertical: 'top' }}
                anchorOrigin={{ horizontal: 'right', vertical: 'bottom' }}
                PaperProps={{
                    sx: {
                        bgcolor: '#1f2937',
                        color: 'white',
                        border: '1px solid #374151'
                    }
                }}
            >
                <MenuItem onClick={handleDownloadClick} sx={{ gap: 1 }}>
                    <Download size={16} /> Download Report
                </MenuItem>
                <MenuItem onClick={handleDeleteClick} sx={{ gap: 1, color: '#ef4444' }}>
                    <Trash2 size={16} /> Delete
                </MenuItem>
            </Menu>
        </Box>
    );
};

export default AssessmentHistoryList;
