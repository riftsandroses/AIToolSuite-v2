import React from 'react';
import {
    Box,
    Paper,
    Typography,
    TextField,
    Button,
    CircularProgress,
    Alert,
    Chip,
    Card,
    CardContent
} from '@mui/material';

const TesterStep = ({
    testerId,
    setTesterId,
    handleTester,
    testerResponse,
    loading,
    error // Passed from parent for displaying general errors
}) => {
    return (
        <Box sx={{ mt: 3 }}>
            <Paper sx={{ p: 4, backgroundColor: '#2a2a2a', color: 'white' }}>
                <Typography variant="h6" sx={{ mb: 3, color: '#4fc3f7' }}>
                    Tester
                </Typography>

                {!testerResponse && ( // Only show input field if no response yet (i.e., not automatically triggered)
                    <Box sx={{ display: 'flex', gap: 2, mb: 3 }}>
                        <TextField
                            label="Enter ID"
                            value={testerId}
                            onChange={(e) => setTesterId(e.target.value)}
                            variant="outlined"
                            sx={{
                                '& .MuiOutlinedInput-root': {
                                    backgroundColor: '#1a1a1a',
                                    color: 'white',
                                    '& fieldset': { borderColor: '#444' },
                                    '&:hover fieldset': { borderColor: '#666' },
                                    '&.Mui-focused fieldset': { borderColor: '#4fc3f7' }
                                },
                                '& .MuiInputLabel-root': { color: '#bbb' }
                            }}
                        />
                        <Button
                            variant="contained"
                            onClick={() => handleTester()} // No ID passed here, uses state
                            disabled={loading}
                            sx={{
                                backgroundColor: '#4fc3f7',
                                color: 'white',
                                '&:hover': { backgroundColor: '#29b6f6' }
                            }}
                        >
                            {loading ? <CircularProgress size={24} /> : 'Test'}
                        </Button>
                    </Box>
                )}


                {loading && !testerResponse && ( // Show loading only when an action is in progress and no previous response
                    <Box sx={{ display: 'flex', justifyContent: 'center', mt: 3 }}>
                        <CircularProgress sx={{ color: '#4fc3f7' }} />
                    </Box>
                )}

                {testerResponse && (
                    <>
                        <Alert severity="success" sx={{ mb: 2, backgroundColor: '#1b5e20', color: 'white' }}>
                            {testerResponse.message}
                        </Alert>

                        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2, mb: 3 }}>
                            <Chip label={`Connection: ${testerResponse.connection_name}`} color="primary" />
                            <Chip label={`Total Processed: ${testerResponse.total_processed}`} color="secondary" />
                            <Chip label={`Success: ${testerResponse.successful_transfers}`} color="success" />
                            <Chip label={`Failed: ${testerResponse.failed_transfers}`} color="error" />
                        </Box>

                        <Card sx={{ mb: 3, backgroundColor: '#333', color: 'white' }}>
                            <CardContent>
                                <Typography variant="h6" sx={{ mb: 2, color: '#4fc3f7' }}>
                                    Processed Results
                                </Typography>
                                {testerResponse.processed_results.map((result, index) => (
                                    <Box key={index} sx={{ mb: 2, p: 2, backgroundColor: '#444', borderRadius: 1 }}>
                                        <Typography variant="body2" sx={{ mb: 1 }}>
                                            <strong>ID:</strong> {result.id}
                                        </Typography>
                                        <Typography variant="body2" sx={{ mb: 1 }}>
                                            <strong>DLL Name:</strong> {result.dll_name}
                                        </Typography>
                                        <Typography variant="body2" sx={{ mb: 1 }}>
                                            <strong>DLL Path:</strong> {result.dll_path}
                                        </Typography>
                                        <Typography variant="body2" sx={{ mb: 1 }}>
                                            <strong>Local DLL Path:</strong> {result.local_dll_path}
                                        </Typography>
                                        <Typography variant="body2" sx={{ mb: 1 }}>
                                            <strong>Application EXE:</strong> {result.application_exe}
                                        </Typography>
                                        <Chip
                                            label={result.status === 'success' ? 'Exploit Successful' : 'error'}
                                            color={result.status === 'success' ? 'success' : 'error'}
                                            size="small"
                                        />
                                    </Box>
                                ))}
                            </CardContent>
                        </Card>

                        <Card sx={{ backgroundColor: '#333', color: 'white' }}>
                            <CardContent>
                                <Typography variant="h6" sx={{ mb: 2, color: '#4fc3f7' }}>
                                    Started Applications
                                </Typography>
                                {testerResponse.started_applications.map((app, index) => (
                                    <Box key={index} sx={{ mb: 2, p: 2, backgroundColor: '#444', borderRadius: 1 }}>
                                        <Typography variant="body2" sx={{ mb: 1 }}>
                                            <strong>Application:</strong> {app.application}
                                        </Typography>
                                        <Typography variant="body2" sx={{ mb: 1 }}>
                                            <strong>Error:</strong> {app.error || 'None'}
                                        </Typography>
                                        <Chip
                                            label={app.status}
                                            color={app.status === 'success' ? 'success' : 'error'}
                                            size="small"
                                        />
                                    </Box>
                                ))}
                            </CardContent>
                        </Card>
                    </>
                )}
            </Paper>
        </Box>
    );
};

export default TesterStep;