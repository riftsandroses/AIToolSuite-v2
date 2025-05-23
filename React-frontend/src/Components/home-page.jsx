import { Box, Button, Container, Typography } from "@mui/material";
import { useNavigate } from "react-router-dom";

export default function HomePage() {
  const navigate = useNavigate();

  // Function to handle the Get Started button click
  const handleGetStarted = () => {
    navigate("/risk-assessment"); // Navigate in the same tab
  };

  return (
    <Box
      component="main"
      sx={{
        width: "100%",
        minHeight: "calc(100vh - 64px)", // Subtract navbar height
        display: "flex",
        alignItems: "center",
        background: "linear-gradient(to bottom right, #121212, #1e1e1e)",
        pt: 8,
        pb: 12,
      }}
    >
      <Container maxWidth="lg">
        <Box
          sx={{
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            textAlign: "center",
            gap: 4,
          }}
        >
          <Typography
            variant="h1"
            component="h1"
            sx={{
              fontSize: { xs: "2.5rem", md: "4rem" },
              fontWeight: 700,
              lineHeight: 1.2,
              mb: 2,
              background: "linear-gradient(45deg, #90caf9, #f48fb1)",
              backgroundClip: "text",
              textFillColor: "transparent",
              WebkitBackgroundClip: "text",
              WebkitTextFillColor: "transparent",
            }}
          >
            Welcome to AI Tool Suite
          </Typography>

          <Typography
            variant="h5"
            component="p"
            sx={{
              maxWidth: "800px",
              mb: 4,
              color: "text.secondary",
              fontSize: { xs: "1rem", md: "1.25rem" },
            }}
          >
            Advanced AI-powered tools for security analysis, risk assessment, and threat detection
          </Typography>

          <Button
            variant="contained"
            size="large"
            onClick={handleGetStarted}
            sx={{
              px: 4,
              py: 1.5,
              fontSize: "1.1rem",
              fontWeight: 500,
              borderRadius: 2,
              background: "linear-gradient(45deg, #90caf9, #64b5f6)",
              "&:hover": {
                background: "linear-gradient(45deg, #64b5f6, #42a5f5)",
                transform: "translateY(-2px)",
                boxShadow: "0 8px 16px rgba(0,0,0,0.2)",
                transition: "all 0.3s ease",
              },
            }}
          >
            Get Started
          </Button>
        </Box>
      </Container>
    </Box>
  );
}