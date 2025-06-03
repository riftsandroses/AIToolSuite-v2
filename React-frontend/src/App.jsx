import { ThemeProvider, createTheme } from "@mui/material/styles";
import CssBaseline from "@mui/material/CssBaseline";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Navbar from "./Components/navbar";
import HomePage from "./Components/home-page";
import RiskAssessmentPage from "./Pages/RiskAssessment/RiskAssessmentPage";
import LLMVulnerabilityScanner from "./Pages/LLMVulnerabilityScanner/LLMVulnerabilityScanner";
import LLMVulnerabilityScannerReport from "./Pages/LLMVulnerabilityReport/LLMVulnerabilityScannerReport";
import UserAuth from "./Guards/UserAuth"
import Login from "./Pages/Login/Login";
import ThreatModel from "./Pages/ThreatModel/ThreatModel";
import LLMVulnerabilityScannerDetails from "./Pages/LLMVulnerabilityScannerDetails/LLMVulnerabilityScannerDetails";

// Create a dark theme
const darkTheme = createTheme({
  palette: {
    mode: "dark",
    primary: {
      main: "#90caf9",
    },
    secondary: {
      main: "#f48fb1",
    },
    background: {
      default: "#121212",
      paper: "#1e1e1e",
    },
  },
  shape: {
    borderRadius: 8,
  },
  components: {
    MuiButton: {
      styleOverrides: {
        root: {
          textTransform: "none",
          fontWeight: 500,
          boxShadow: "0 2px 4px rgba(0,0,0,0.1)",
          padding: "8px 16px",
          "&:hover": {
            boxShadow: "0 4px 8px rgba(0,0,0,0.2)",
            transform: "translateY(-2px)",
            transition: "all 0.3s ease",
          },
        },
      },
    },
    MuiAppBar: {
      styleOverrides: {
        root: {
          boxShadow: "0 2px 10px rgba(0,0,0,0.1)",
        },
      },
    },
  },
  typography: {
    fontFamily: '"Inter", "Roboto", "Helvetica", "Arial", sans-serif',
    h1: {
      fontWeight: 700,
    },
    h5: {
      fontWeight: 500,
    },
  },
});

function App() {
  return (
    <ThemeProvider theme={darkTheme}>
      <CssBaseline />
      <Router>
        <Navbar />
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/login" element={<Login />} />
          <Route path="/risk-assessment" element={
            <UserAuth>
              <RiskAssessmentPage />
            </UserAuth>
            } />
          <Route path="/llm-vulnerability-scanner" element={
              <UserAuth>
                <LLMVulnerabilityScanner />
              </UserAuth>
            } />
            <Route path="/llm-vulnerability-scanner-report" element={
              <UserAuth>
                <LLMVulnerabilityScannerReport />
              </UserAuth>
            } />
            <Route path="/threat-model" element={
              <UserAuth>  
                <ThreatModel />
              </UserAuth>
            } />
            <Route path="/llm-vulnerability-report-details" element={
              <UserAuth>  
                <LLMVulnerabilityScannerDetails />
              </UserAuth>
            } />
        </Routes>
      </Router>
    </ThemeProvider>
  );
}

export default App;