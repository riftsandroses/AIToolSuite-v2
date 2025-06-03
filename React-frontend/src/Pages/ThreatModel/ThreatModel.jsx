import {
  Box,
  Typography,
  Container,
  CircularProgress,
  Alert,
  Button
} from '@mui/material';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import { Link } from 'react-router-dom';
import { useState, useEffect } from 'react';
import axios from 'axios';
import { getAuthCookies } from '../../api/auth';

const ThreatModel = () => {
  const [loading, setLoading] = useState(true);
  const [containerUrl, setContainerUrl] = useState('');
  const [error, setError] = useState('');

  const API_URL = process.env.REACT_APP_API_BASE_URL;
  const API_BASE_URL = `${API_URL}/api/v1/aitm/containers/get-or-create`;
  const TOKEN = getAuthCookies().accessToken;

  const fetchContainerDetails = async () => {
    try {
      setLoading(true);
      setError('');
      
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
        console.log(containerUrl);
      } else {
        setError('Container URL not available');
      }
    } catch (err) {
      setError(`Failed to fetch container details: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  // Auto-fetch container details when component mounts
  useEffect(() => {
    fetchContainerDetails();
  }, []);

  if (loading) {
    return (
      <Box 
        sx={{ 
          display: 'flex', 
          flexDirection: 'column',
          justifyContent: 'center', 
          alignItems: 'center', 
          height: '100vh',
          backgroundColor: 'background.default'
        }}
      >
        <CircularProgress size={60} sx={{ mb: 2 }} />
        <Typography variant="h6" color="white">
          Loading Threat Model...
        </Typography>
      </Box>
    );
  }

  if (error) {
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

        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
        
        <Button 
          variant="contained" 
          color="primary" 
          onClick={fetchContainerDetails}
          disabled={loading}
        >
          Retry
        </Button>
      </Container>
    );
  }

  return (
    <Box sx={{ height: '100vh', width: '100vw', overflow: 'hidden' }}>
      {/* Back button overlay */}
      
        <Button 
          component={Link} 
          to="/" 
          startIcon={<ArrowBackIcon />} 
          sx={{ color: 'white' }}
          size="small"
        >
          Back
        </Button>

      {/* Full screen iframe */}
      {containerUrl && (
        <iframe 
          src={containerUrl}
          style={{
            width: '100%',
            height: '100%',
            border: 'none'
          }}
          title="Threat Model Container"
          sandbox="allow-scripts allow-same-origin allow-forms allow-popups allow-popups-to-escape-sandbox"
        />
      )}
    </Box>
  );
};

export default ThreatModel;