import React, { useState, useEffect } from 'react';
import {
    Box,
    Container,
    Typography,
    Paper,
    Button,
    Alert,
    Step,
    Stepper,
    StepLabel,
} from '@mui/material';
import { ArrowBack, CheckCircle } from '@mui/icons-material';

import { connectToScanner, initiateProcess, filterProcess, runTester } from '../../api/dllScannerApi';
import ConnectStep from '../../Components/DLLScanner/ConnectStep';
import FilterStep from '../../Components/DLLScanner/FilterStep';
import TesterStep from '../../Components/DLLScanner/TesterStep';

const steps = ['Reconnaissance', 'Triaging', 'Exploit'];

// Simple Custom Step Icon
const CustomStepIcon = ({ active, completed, icon }) => {
    const getIconStyle = () => {
        if (completed) {
            return {
                backgroundColor: '#4fc3f7',
                color: 'white',
                border: '2px solid #4fc3f7'
            };
        }
        if (active) {
            return {
                backgroundColor: '#4fc3f7',
                color: 'white',
                border: '2px solid #4fc3f7'
            };
        }
        return {
            backgroundColor: 'transparent',
            color: '#666',
            border: '2px solid #666'
        };
    };

    return (
        <Box
            sx={{
                width: 40,
                height: 40,
                borderRadius: '50%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '14px',
                fontWeight: 'bold',
                transition: 'all 0.3s ease',
                ...getIconStyle()
            }}
        >
            {completed ? <CheckCircle sx={{ fontSize: 20 }} /> : icon}
        </Box>
    );
};

const DLLScannerPage = () => {
    const [activeStep, setActiveStep] = useState(0);
    const [connectionData, setConnectionData] = useState({
        username: '',
        password: '',
        ip_address: '',
        connection_name: ''
    });
    const [connectionResponse, setConnectionResponse] = useState(null);
    const [selectedApp, setSelectedApp] = useState(null);
    const [processResponse, setProcessResponse] = useState(null);
    const [filterResponse, setFilterResponse] = useState(null);
    const [testerId, setTesterId] = useState('');
    const [testerResponse, setTesterResponse] = useState(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);
    const [isAppInitiated, setIsAppInitiated] = useState(false);

    // Effect to automatically run tester if an ID is set and we are on the tester step
    useEffect(() => {
        if (activeStep === 2 && testerId) {
            handleTester(testerId);
        }
    }, [activeStep, testerId]);

    const handleConnect = async () => {
        setLoading(true);
        setError(null);
        try {
            const data = await connectToScanner(connectionData);
            setConnectionResponse(data);
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const handleAppSelect = async (app) => {
        setLoading(true);
        setError(null);
        setProcessResponse(null);
        setSelectedApp(app);
        try {
            const data = await initiateProcess({
                name: app.name,
                directory: app.directory,
                fullname: app.fullname,
                connection_name: connectionData.connection_name
            });
            setProcessResponse(data);
            setIsAppInitiated(true);
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const handleFilter = async () => {
        setLoading(true);
        setError(null);
        try {
            const data = await filterProcess(connectionData.connection_name);
            setFilterResponse(data);
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const handleTester = async (idToTest = testerId) => {
        if (!idToTest) {
            setError('Please enter an ID or select a row to test.');
            return;
        }

        setLoading(true);
        setError(null);
        try {
            const data = await runTester(connectionData.connection_name, idToTest);
            setTesterResponse(data);
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const handleStartAttack = (id) => {
        setTesterId(id);
        setActiveStep(2);
    };

    const handleNext = () => {
        if (activeStep === 0) {
            if (!isAppInitiated) {
                setError('Please initiate a test by clicking on a desired row before moving to the next step.');
                return;
            }
            handleFilter();
        }
        setActiveStep((prevActiveStep) => prevActiveStep + 1);
    };

    const handleBack = () => {
        setActiveStep((prevActiveStep) => prevActiveStep - 1);
        if (activeStep === 2) {
            setTesterId('');
            setTesterResponse(null);
        }
        setError(null);
    };

    const renderStepContent = () => {
        switch (activeStep) {
            case 0:
                return (
                    <ConnectStep
                        connectionData={connectionData}
                        setConnectionData={setConnectionData}
                        handleConnect={handleConnect}
                        connectionResponse={connectionResponse}
                        selectedApp={selectedApp}
                        handleAppSelect={handleAppSelect}
                        processResponse={processResponse}
                        loading={loading}
                        error={error}
                        setActiveStep={setActiveStep}
                        handleFilter={handleFilter}
                    />
                );
            case 1:
                return (
                    <FilterStep
                        filterResponse={filterResponse}
                        handleStartAttack={handleStartAttack}
                    />
                );
            case 2:
                return (
                    <TesterStep
                        testerId={testerId}
                        setTesterId={setTesterId}
                        handleTester={handleTester}
                        testerResponse={testerResponse}
                        loading={loading}
                        error={error}
                    />
                );
            default:
                return null;
        }
    };

    return (
        <Box sx={{ backgroundColor: '#121212', minHeight: '100vh', color: 'white' }}>
            <Container maxWidth="lg" sx={{ py: 4 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 4 }}>
                    <Button
                        startIcon={<ArrowBack />}
                        sx={{ color: '#4fc3f7', mr: 2 }}
                        onClick={() => window.history.back()}
                    >
                        Back to Home
                    </Button>
                </Box>

                <Typography variant="h4" sx={{ mb: 4, fontWeight: 'bold' }}>
                    Automated DLL Exploitation using Agentic AI
                </Typography>

                {/* Simplified Stepper */}
                <Paper
                    sx={{
                        p: 3,
                        mb: 3,
                        backgroundColor: '#1e1e1e',
                        border: '1px solid #333',
                        borderRadius: 2
                    }}
                >
                    <Stepper
                        activeStep={activeStep}
                        sx={{
                            '& .MuiStepConnector-root': {
                                top: 20,
                                left: 'calc(-50% + 20px)',
                                right: 'calc(50% + 20px)',
                            },
                            '& .MuiStepConnector-line': {
                                height: 2,
                                border: 'none',
                                backgroundColor: '#333',
                                transition: 'background-color 0.3s ease',
                            },
                            '& .MuiStepConnector-root.Mui-completed .MuiStepConnector-line': {
                                backgroundColor: '#4fc3f7',
                            },
                            '& .MuiStepConnector-root.Mui-active .MuiStepConnector-line': {
                                backgroundColor: '#4fc3f7',
                            },
                            '& .MuiStep-root': {
                                padding: 0,
                            },
                            '& .MuiStepLabel-root': {
                                display: 'flex',
                                flexDirection: 'column',
                                alignItems: 'center',
                            },
                            '& .MuiStepLabel-label': {
                                mt: 2,
                                color: '#666',
                                fontSize: '0.9rem',
                                fontWeight: 500,
                                '&.Mui-active': {
                                    color: '#4fc3f7',
                                    fontWeight: 600,
                                },
                                '&.Mui-completed': {
                                    color: '#4fc3f7',
                                    fontWeight: 600,
                                },
                            },
                        }}
                    >
                        {steps.map((label, index) => (
                            <Step key={label}>
                                <StepLabel
                                    StepIconComponent={(props) => (
                                        <CustomStepIcon {...props} icon={index + 1} />
                                    )}
                                >
                                    {label}
                                </StepLabel>
                            </Step>
                        ))}
                    </Stepper>
                </Paper>

                {error && (
                    <Alert severity="error" sx={{ mb: 2 }}>
                        {error}
                    </Alert>
                )}

                {renderStepContent()}

                <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 4 }}>
                    <Button
                        disabled={activeStep === 0}
                        onClick={handleBack}
                        sx={{ color: '#4fc3f7' }}
                    >
                        Back
                    </Button>
                    {activeStep < steps.length - 1 && (
                        <Button
                            variant="contained"
                            onClick={handleNext}
                            disabled={loading || (activeStep === 0 && !isAppInitiated) || (activeStep === 0 && !connectionResponse)}
                            sx={{
                                backgroundColor: '#4fc3f7',
                                color: 'white',
                                '&:hover': { backgroundColor: '#29b6f6' }
                            }}
                        >
                            Next
                        </Button>
                    )}
                </Box>
            </Container>
        </Box>
    );
};

export default DLLScannerPage;