import React, { useEffect } from 'react';
import {
    Box,
    Paper,
    Typography,
    TextField,
    Button,
    CircularProgress,
    Alert,
    TableContainer,
    Table,
    TableHead,
    TableRow,
    TableCell,
    TableBody,
    Chip,
    Card,
    CardContent
} from '@mui/material';

const ConnectStep = ({
    connectionData,
    setConnectionData,
    handleConnect,
    connectionResponse,
    selectedApp,
    handleAppSelect,
    processResponse,
    loading,
    error,
    setActiveStep,
    handleFilter
}) => {
    const [currentlyProcessingAppFullname, setCurrentlyProcessingAppFullname] = React.useState(null);

    const localHandleAppSelect = async (app) => {
        setCurrentlyProcessingAppFullname(app.fullname);
        await handleAppSelect(app);
    };

    useEffect(() => {
        if (!loading && currentlyProcessingAppFullname) {
            setCurrentlyProcessingAppFullname(null); // Clear the processing flag when global loading is done.
        }
    }, [loading, currentlyProcessingAppFullname]);

    const handleNext = () => {
        handleFilter();
        setActiveStep((prevActiveStep) => prevActiveStep + 1);
    }

    return (
        <Box sx={{ mt: 3 }}>
            <Paper sx={{ p: 4, backgroundColor: '#2a2a2a', color: 'white', borderRadius: '8px' }}>
                <Typography variant="h6" sx={{ mb: 3, color: '#4fc3f7' }}>
                    Configure Machine Details
                </Typography>
                <Typography variant="body2" sx={{ mb: 3, color: '#bbb' }}>
                    Enter the necessary information to connect to your server.
                </Typography>

                <Box sx={{ display: 'grid', gap: 2, gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', mb: 3 }}>
                    <TextField
                        label="Username"
                        value={connectionData.username}
                        onChange={(e) => setConnectionData({ ...connectionData, username: e.target.value })}
                        fullWidth
                        variant="outlined"
                        sx={{
                            '& .MuiOutlinedInput-root': {
                                backgroundColor: '#1a1a1a',
                                color: 'white',
                                borderRadius: '8px',
                                '& fieldset': { borderColor: '#444' },
                                '&:hover fieldset': { borderColor: '#666' },
                                '&.Mui-focused fieldset': { borderColor: '#4fc3f7' }
                            },
                            '& .MuiInputLabel-root': { color: '#bbb' }
                        }}
                    />
                    <TextField
                        label="Password"
                        type="password"
                        value={connectionData.password}
                        onChange={(e) => setConnectionData({ ...connectionData, password: e.target.value })}
                        fullWidth
                        variant="outlined"
                        sx={{
                            '& .MuiOutlinedInput-root': {
                                backgroundColor: '#1a1a1a',
                                color: 'white',
                                borderRadius: '8px',
                                '& fieldset': { borderColor: '#444' },
                                '&:hover fieldset': { borderColor: '#666' },
                                '&.Mui-focused fieldset': { borderColor: '#4fc3f7' }
                            },
                            '& .MuiInputLabel-root': { color: '#bbb' }
                        }}
                    />
                    <TextField
                        label="IP Address"
                        value={connectionData.ip_address}
                        onChange={(e) => setConnectionData({ ...connectionData, ip_address: e.target.value })}
                        fullWidth
                        variant="outlined"
                        sx={{
                            '& .MuiOutlinedInput-root': {
                                backgroundColor: '#1a1a1a',
                                color: 'white',
                                borderRadius: '8px',
                                '& fieldset': { borderColor: '#444' },
                                '&:hover fieldset': { borderColor: '#666' },
                                '&.Mui-focused fieldset': { borderColor: '#4fc3f7' }
                            },
                            '& .MuiInputLabel-root': { color: '#bbb' }
                        }}
                    />
                    <TextField
                        label="Connection Name"
                        value={connectionData.connection_name}
                        onChange={(e) => setConnectionData({ ...connectionData, connection_name: e.target.value })}
                        fullWidth
                        variant="outlined"
                        sx={{
                            '& .MuiOutlinedInput-root': {
                                backgroundColor: '#1a1a1a',
                                color: 'white',
                                borderRadius: '8px',
                                '& fieldset': { borderColor: '#444' },
                                '&:hover fieldset': { borderColor: '#666' },
                                '&.Mui-focused fieldset': { borderColor: '#4fc3f7' }
                            },
                            '& .MuiInputLabel-root': { color: '#bbb' }
                        }}
                    />
                </Box>

                <Button
                    variant="contained"
                    onClick={handleConnect}
                    disabled={loading} // Disable connect button if any loading is happening.
                    sx={{
                        backgroundColor: '#4fc3f7',
                        color: 'white',
                        borderRadius: '8px',
                        '&:hover': { backgroundColor: '#29b6f6' },
                        px: 4,
                        py: 1.5,
                        minWidth: '120px'
                    }}
                >
                    {/* Show CircularProgress for general connection loading, not app-specific processing */}
                    {loading && !currentlyProcessingAppFullname ? <CircularProgress size={24} color="inherit" /> : 'Connect'}
                </Button>
            </Paper>

            {connectionResponse && (
                <Paper sx={{ p: 3, mt: 3, backgroundColor: '#2a2a2a', color: 'white', borderRadius: '8px' }}>
                    <Alert severity="success" sx={{ mb: 2, backgroundColor: '#1b5e20', color: 'white', borderRadius: '8px' }}>
                        {connectionResponse.message}
                    </Alert>

                    <Box sx={{ display: 'flex', gap: 2, mb: 2, alignItems: 'flex-end', flexWrap: 'wrap' }}>
                        <Chip label={`Connection: ${connectionResponse.connection_name}`} color="primary" sx={{ backgroundColor: '#4fc3f7', color: 'white', borderRadius: '8px' }} />
                        <Chip label={`Total Apps: ${connectionResponse.total_apps}`} color="secondary" sx={{ backgroundColor: '#ffb300', color: 'black', borderRadius: '8px' }} />
                    </Box>

                    {/* New Warning for initiating a test */}
                    <Alert severity="info" sx={{ mb: 3, backgroundColor: '#1a237e', color: 'white', borderRadius: '8px' }}>
                        Before proceeding, please click on a desired row in the table below to initiate a test
                    </Alert>

                    <TableContainer component={Paper} sx={{ backgroundColor: '#1a1a1a', borderRadius: '8px', overflowX: 'auto' }}>
                        <Table>
                            <TableHead>
                                <TableRow sx={{ backgroundColor: '#333' }}>
                                    <TableCell sx={{ color: 'white', fontWeight: 'bold', borderBottom: '1px solid #444' }}>Name</TableCell>
                                    <TableCell sx={{ color: 'white', fontWeight: 'bold', borderBottom: '1px solid #444' }}>Directory</TableCell>
                                    <TableCell sx={{ color: 'white', fontWeight: 'bold', borderBottom: '1px solid #444' }}>Full Name</TableCell>
                                </TableRow>
                            </TableHead>
                            <TableBody>
                                {connectionResponse.apps.map((app, index) => (
                                    <React.Fragment key={index}>
                                        <TableRow
                                            onClick={() => localHandleAppSelect(app)} // Use the local handler for row clicks.
                                            sx={{
                                                cursor: 'pointer',
                                                backgroundColor: selectedApp?.name === app.name ? '#444' : 'transparent',
                                                '&:hover': { backgroundColor: '#333' }
                                            }}
                                        >
                                            <TableCell sx={{ color: 'white', borderBottom: '1px solid #222' }}>{app.name}</TableCell>
                                            <TableCell sx={{ color: 'white', borderBottom: '1px solid #222' }}>{app.directory}</TableCell>
                                            <TableCell sx={{ color: 'white', borderBottom: '1px solid #222' }}>{app.fullname}</TableCell>
                                        </TableRow>
                                        {/* Display process details or loading spinner if this app is selected */}
                                        {selectedApp?.name === app.name && (
                                            <TableRow>
                                                <TableCell colSpan={3} sx={{ py: 0, borderBottom: 'none' }}>
                                                    <Card sx={{ my: 2, backgroundColor: '#333', color: 'white', borderRadius: '8px' }}>
                                                        <CardContent>
                                                            <Typography variant="h6" sx={{ mb: 2, color: '#4fc3f7' }}>Process Details</Typography>
                                                            {/* Show CircularProgress if currently loading this specific app */}
                                                            {loading && currentlyProcessingAppFullname === app.fullname ? (
                                                                <Box sx={{ display: 'flex', justifyContent: 'start', py: 2 }}>
                                                                    Loading..
                                                                </Box>
                                                            ) : (
                                                                // Otherwise, display processResponse if available for the selected app
                                                                processResponse && (
                                                                    <>
                                                                        <Typography variant="body2" sx={{ mb: 1 }}>
                                                                            <strong>Filename:</strong> {processResponse.output.filename}
                                                                        </Typography>
                                                                        <Typography variant="body2" sx={{ mb: 1 }}>
                                                                            <strong>File Path:</strong> {processResponse.output.file_path}
                                                                        </Typography>
                                                                        <Typography variant="body2">
                                                                            <strong>CSV Size:</strong> {processResponse.output.csv_size} bytes
                                                                        </Typography>
                                                                    </>
                                                                )
                                                            )}
                                                        </CardContent>
                                                        <Button
                                                            variant="contained"
                                                            onClick={() => handleNext()}
                                                            disabled={loading} // Disable 'Next' button if any operation is loading.
                                                            sx={{
                                                                backgroundColor: '#4fc3f7',
                                                                color: 'white',
                                                                borderRadius: '8px',
                                                                '&:hover': { backgroundColor: '#29b6f6' },
                                                                marginLeft: '15px',
                                                                marginBottom: '10px',
                                                                px: 4,
                                                                py: 1
                                                            }}
                                                        >
                                                            Proceed
                                                        </Button>
                                                    </Card>
                                                </TableCell>
                                            </TableRow>
                                        )}
                                    </React.Fragment>
                                ))}
                            </TableBody>
                        </Table>
                    </TableContainer>
                </Paper>
            )}
        </Box>
    );
};

export default ConnectStep;