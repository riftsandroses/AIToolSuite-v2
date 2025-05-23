import {
  Box,
  Typography,
  Paper,
  Container,
  Button,
  CircularProgress,
  Alert,
  Stack
} from '@mui/material';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import StopIcon from '@mui/icons-material/Stop';
import RestartAltIcon from '@mui/icons-material/RestartAlt';
import { Link } from 'react-router-dom';
import { useState } from 'react';
import axios from 'axios';
import { getAuthCookies } from '../../api/auth';

const ThreatModel = () => {
  const [loading, setLoading] = useState(false);
  const [containerStatus, setContainerStatus] = useState('stopped'); // 'stopped', 'running'
  const [containerUrl, setContainerUrl] = useState('');
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');

  const API_URL = process.env.REACT_APP_API_BASE_URL;
  const API_BASE_URL = `${API_URL}/api/v1/aitm/containers`;
  const TOKEN = getAuthCookies().accessToken;

  const fetchContainerDetails = async () => {
    try {
      const response = await axios.get(
        `${API_BASE_URL}`, 
        {
          headers: {
            'Authorization': `Bearer ${TOKEN}`
          }
        }
      );
      
      if (response.data && response.data.container_url) {
        setContainerUrl(response.data.container_url);
        setContainerStatus('running');
        return true;
      } else {
        setError('Container URL not available');
        return false;
      }
    } catch (err) {
      setError(`Failed to fetch container details: ${err.message}`);
      return false;
    }
  };

  const handleStartContainer = async () => {
    setLoading(true);
    setError('');
    setMessage('Starting container...');
    
    try {
      await axios.post(
        `${API_BASE_URL}/1/start/`, 
        {}, 
        {
          headers: {
            'Authorization': `Bearer ${TOKEN}`
          }
        }
      );
      
      // After starting, fetch the container details to get the URL
      const success = await fetchContainerDetails();
      if (success) {
        setMessage('Container started successfully');
      }
    } catch (err) {
      setError(`Failed to start container: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleStopContainer = async () => {
    setLoading(true);
    setError('');
    setMessage('Stopping container...');
    
    try {
      await axios.post(
        `${API_BASE_URL}/1/stop/`, 
        {}, 
        {
          headers: {
            'Authorization': `Bearer ${TOKEN}`
          }
        }
      );
      
      setContainerStatus('stopped');
      setContainerUrl('');
      setMessage('Container stopped successfully');
    } catch (err) {
      setError(`Failed to stop container: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleRestartContainer = async () => {
    setLoading(true);
    setError('');
    setMessage('Restarting container...');
    
    try {
      await axios.post(
        `${API_BASE_URL}/1/restart/`, 
        {}, 
        {
          headers: {
            'Authorization': `Bearer ${TOKEN}`
          }
        }
      );
      
      // After restarting, fetch the container details to get the URL
      const success = await fetchContainerDetails();
      if (success) {
        setMessage('Container restarted successfully');
      }
    } catch (err) {
      setError(`Failed to restart container: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      <Box sx={{ mb: 3, display: 'flex', alignItems: 'center' }}>
        <Button component={Link} to="/" startIcon={<ArrowBackIcon />} sx={{ color: 'white' }}>
          Back to Home
        </Button>
      </Box>
      
      <Box sx={{ mb: 4 }}>
        <Typography
          variant="h5"
          component="h4"
          sx={{
            fontWeight: 700,
            color: 'white',
            mb: 1
          }}
        >
          Threat Model
        </Typography>
      </Box>

      <Paper
        elevation={3}
        sx={{
          borderRadius: 2,
          backgroundColor: 'background.paper',
          p: 3,
          mb: 3
        }}
      >
        <Stack direction="row" spacing={2} sx={{ mb: 3 }}>
          <Button 
            variant="contained" 
            color="primary" 
            startIcon={<PlayArrowIcon />}
            onClick={handleStartContainer}
            disabled={loading || containerStatus === 'running'}
          >
            Start
          </Button>
          <Button 
            variant="contained" 
            color="error" 
            startIcon={<StopIcon />}
            onClick={handleStopContainer}
            disabled={loading || containerStatus === 'stopped'}
          >
            Stop
          </Button>
          <Button 
            variant="contained" 
            color="secondary" 
            startIcon={<RestartAltIcon />}
            onClick={handleRestartContainer}
            disabled={loading}
          >
            Restart
          </Button>
          {loading && <CircularProgress size={24} />}
        </Stack>

        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}
        
        {message && !error && (
          <Alert severity="info" sx={{ mb: 2 }}>
            {message}
          </Alert>
        )}
        
        {containerStatus === 'running' && containerUrl && (
          <Box sx={{ mt: 3 }}>
            <Typography variant="subtitle1" gutterBottom>
              Container is running at: {containerUrl}
            </Typography>
            <Paper 
              elevation={1}
              sx={{
                height: 600,
                mt: 2,
                overflow: 'hidden',
                borderRadius: 1
              }}
            >
              <iframe 
                src={containerUrl}
                style={{
                  width: '100%',
                  height: '100%',
                  border: 'none'
                }}
                title="Threat Model Container"
              />
            </Paper>
          </Box>
        )}
      </Paper>
    </Container>
  );
};

export default ThreatModel;