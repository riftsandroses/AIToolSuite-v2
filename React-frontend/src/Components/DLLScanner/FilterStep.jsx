import React from 'react';
import {
    Box,
    Paper,
    Typography,
    Button,
    Alert,
    Chip,
    Card,
    CardContent,
    TableContainer,
    Table,
    TableHead,
    TableRow,
    TableCell,
    TableBody
} from '@mui/material';
import { PlayArrow } from '@mui/icons-material';

const FilterStep = ({ filterResponse, handleStartAttack }) => {
    return (
        <Box sx={{ mt: 3 }}>
            <Paper sx={{ p: 4, backgroundColor: '#2a2a2a', color: 'white' }}>
                <Typography variant="h6" sx={{ mb: 3, color: '#4fc3f7' }}>
                    Filter Results
                </Typography>

                {filterResponse && (
                    <>
                        <Alert severity="success" sx={{ mb: 2, backgroundColor: '#1b5e20', color: 'white' }}>
                            {filterResponse.message}
                        </Alert>

                        <Box sx={{ display: 'flex', gap: 2, mb: 3 }}>
                            <Chip label={`Connection: ${filterResponse.connection_name}`} color="primary" />
                            <Chip label={`CSV Files: ${filterResponse.total_csv_files_processed}`} color="secondary" />
                            <Chip label={`Total Matches: ${filterResponse.total_matches}`} color="info" />
                        </Box>

                        {filterResponse.filtered_results.map((result, index) => (
                            <Card key={index} sx={{ mb: 3, backgroundColor: '#333', color: 'white' }}>
                                <CardContent>
                                    <Typography variant="h6" sx={{ mb: 2, color: '#4fc3f7' }}>
                                        {result.application_name}
                                    </Typography>
                                    <Typography variant="body2" sx={{ mb: 1 }}>
                                        <strong>CSV Filename:</strong> {result.csv_filename}
                                    </Typography>
                                    <Typography variant="body2" sx={{ mb: 2 }}>
                                        <strong>Match Count:</strong> {result.match_count}
                                    </Typography>

                                    <TableContainer component={Paper} sx={{ backgroundColor: '#1a1a1a' }}>
                                        <Table>
                                            <TableHead>
                                                <TableRow sx={{ backgroundColor: '#444' }}>
                                                    <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>ID</TableCell>
                                                    <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Process Name</TableCell>
                                                    <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Path</TableCell>
                                                    <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Result</TableCell>
                                                    <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Actions</TableCell>
                                                </TableRow>
                                            </TableHead>
                                            <TableBody>
                                                {result.matches.map((match, matchIndex) => (
                                                    <TableRow key={matchIndex} sx={{ '&:hover': { backgroundColor: '#333' } }}>
                                                        <TableCell sx={{ color: 'white' }}>{match.id}</TableCell>
                                                        <TableCell sx={{ color: 'white' }}>{match.process_name}</TableCell>
                                                        <TableCell sx={{ color: 'white' }}>{match.path}</TableCell>
                                                        <TableCell sx={{ color: 'white' }}>
                                                            <Chip
                                                                label={match.result}
                                                                color={match.result === 'NAME NOT FOUND' ? 'error' : 'success'}
                                                                size="small"
                                                            />
                                                        </TableCell>
                                                        <TableCell sx={{ color: 'white' }}>
                                                            <Button
                                                                variant="contained"
                                                                size="small"
                                                                onClick={() => handleStartAttack(match.id)}
                                                                sx={{
                                                                    backgroundColor: '#4caf50',
                                                                    color: 'white',
                                                                    '&:hover': { backgroundColor: '#388e3c' },
                                                                    whiteSpace: 'nowrap'
                                                                }}
                                                            >
                                                                Start Attack
                                                            </Button>
                                                        </TableCell>
                                                    </TableRow>
                                                ))}
                                            </TableBody>
                                        </Table>
                                    </TableContainer>
                                </CardContent>
                            </Card>
                        ))}
                    </>
                )}
            </Paper>
        </Box>
    );
};

export default FilterStep;