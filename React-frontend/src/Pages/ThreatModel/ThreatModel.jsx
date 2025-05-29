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
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import { Link } from 'react-router-dom';
import { useState } from 'react';
import axios from 'axios';
import { getAuthCookies } from '../../api/auth';

const ThreatModel = () => {
  const [loading, setLoading] = useState(false);
  const [containerStatus, setContainerStatus] = useState('stopped'); // 'stopped', 'running'
  const [containerUrl, setContainerUrl] = useState('');
  const [id, setId] = useState(null);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [iframeError, setIframeError] = useState(false);

  const API_URL = process.env.REACT_APP_API_BASE_URL;
  const API_BASE_URL = `${API_URL}/api/v1/aitm/containers`;
  const TOKEN = getAuthCookies().accessToken;

  // Convert localhost container URL to proxied HTTPS URL
  const convertToProxiedUrl = (containerUrl) => {
    if (!containerUrl) return '';
    
    // Extract port from URL like "http://127.0.0.1/container/8763/"
    const portMatch = containerUrl.match(/\/container\/(\d+)\//);
    if (portMatch) {
      const port = portMatch[1];
      // Return the proxied URL through your nginx server
      return `${API_URL}/container/${port}/`;
    }
    
    return containerUrl;
  };

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
        const proxiedUrl = convertToProxiedUrl(response.data.container_url);
        setContainerUrl(proxiedUrl);
        setContainerStatus('running');
        setId(response.data.id || 1);
        // Use React state instead of localStorage
        setIframeError(false);
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

  const handleStopContainer = async () => {
    setLoading(true);
    setError('');
    setMessage('Stopping container...');

    if(!id) {
      setError('No container ID found. Please start the container first.');
      setLoading(false);
      return;
    }
    
    try {
      await axios.post(
        `${API_BASE_URL}/${id}/stop/`, 
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

    if(!id) {
      setError('No container ID found. Please start the container first.');
      setLoading(false);
      return;
    }
    
    try {
      await axios.post(
        `${API_BASE_URL}/${id}/restart/`, 
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

  const handleIframeError = () => {
    setIframeError(true);
  };

  const openInNewTab = () => {
    if (containerUrl) {
      window.open(containerUrl, '_blank');
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
            onClick={fetchContainerDetails}
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
          {containerStatus === 'running' && containerUrl && (
            <Button 
              variant="outlined" 
              startIcon={<OpenInNewIcon />}
              onClick={openInNewTab}
            >
              Open in New Tab
            </Button>
          )}
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

        {iframeError && (
          <Alert severity="warning" sx={{ mb: 2 }}>
            Unable to load the container in iframe. This might be due to security restrictions. 
            Try using the "Open in New Tab" button instead.
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
                onError={handleIframeError}
                sandbox="allow-scripts allow-same-origin allow-forms allow-popups allow-popups-to-escape-sandbox"
              />
            </Paper>
          </Box>
        )}
      </Paper>
    </Container>
  );
};

export default ThreatModel;