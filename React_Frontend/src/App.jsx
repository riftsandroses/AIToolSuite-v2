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
import DLLScannerPage from "./Pages/DLLScanner/DLLScannerPage";
import APIPentestPage from "./Pages/APIPenTest/APIPenTestPage";
import AllPentestScansPage from "./Pages/APIPenTest/AllPentestScansPage";
import ScanDetailsPage from "./Pages/APIPenTest/ScanDetailsPage";
import TestCasePage from "./Pages/APIPenTest/TestCasePage";
import EnvironmentVariablesPage from "./Pages/APIPenTest/EnvironmentVariablesPage";
import InitializeScanPage from "./Pages/APIPenTest/InitializeScanPage";
import AllThreatModelPage from "./Pages/ThreatModel/AllThreatModelPage";
import ThreatModelAssessment from "./Pages/ThreatModel/ThreatModelAssessment";
import API22023TC1 from "./Components/APIPentest/TestCasePages/API2/API22023TC1";
import API22023TC2 from "./Components/APIPentest/TestCasePages/API2/API22023TC2";
import API22023TC3 from "./Components/APIPentest/TestCasePages/API2/API22023TC3";
import API22023TC5 from "./Components/APIPentest/TestCasePages/API2/API22023TC5";
import API22023TC4 from "./Components/APIPentest/TestCasePages/API2/API22023TC4";
import API42023TC1 from "./Components/APIPentest/TestCasePages/API4/API42023TC1";
import API42023TC2 from "./Components/APIPentest/TestCasePages/API4/API42023TC2";
import API42023TC3 from "./Components/APIPentest/TestCasePages/API4/API42023TC3";
import API42023TC4 from "./Components/APIPentest/TestCasePages/API4/API42023TC4";
import API42023TC5 from "./Components/APIPentest/TestCasePages/API4/API42023TC5";
import API42023TC6 from "./Components/APIPentest/TestCasePages/API4/API42023TC6";
import API62023TC1 from "./Components/APIPentest/TestCasePages/API6/API62023TC1";
import API72023TC1 from "./Components/APIPentest/TestCasePages/API7/API72023TC1";
import API82023TC1 from "./Components/APIPentest/TestCasePages/API8/API82023TC1";
import API82023TC2 from "./Components/APIPentest/TestCasePages/API8/API82023TC2";
import API82023TC3 from "./Components/APIPentest/TestCasePages/API8/API82023TC3";
import API92023TC1 from "./Components/APIPentest/TestCasePages/API9/API92023TC1";
import API92023TC2 from "./Components/APIPentest/TestCasePages/API9/API92023TC2";
import API92023TC3 from "./Components/APIPentest/TestCasePages/API9/API92023TC3";
import API92023TC4 from "./Components/APIPentest/TestCasePages/API9/API92023TC4";
import API92023TC5 from "./Components/APIPentest/TestCasePages/API9/API92023TC5";
import API92023TC6 from "./Components/APIPentest/TestCasePages/API9/API92023TC6";

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
          <Route path="/threat-model/all" element={
            <UserAuth>
              <AllThreatModelPage />
            </UserAuth>
          } />
          <Route path="/threat-model/:id" element={
            <UserAuth>
              <ThreatModelAssessment />
            </UserAuth>
          } />
          <Route path="/llm-vulnerability-report-details" element={
            <UserAuth>
              <LLMVulnerabilityScannerDetails />
            </UserAuth>
          } />
          <Route path="/dll" element={
            <UserAuth>
              <DLLScannerPage />
            </UserAuth>
          } />
          <Route path="/api-pentest" element={
            <UserAuth>
              <APIPentestPage />
            </UserAuth>
          } />
          <Route path="/api-pentest/all" element={<UserAuth><AllPentestScansPage /></UserAuth>} />
          <Route path="/api-pentest/:id" element={<UserAuth><ScanDetailsPage /></UserAuth>} />
          <Route path="/api-pentest/select-test-case/:id" element={<UserAuth><TestCasePage /></UserAuth>} />
          <Route path="/api-pentest/scan/:id/environment" element={<UserAuth><EnvironmentVariablesPage /></UserAuth>} />
          <Route path="/api-pentest/scan/:id/start" element={<UserAuth><InitializeScanPage /></UserAuth>} />

          <Route path="/api-pentest/scan/:scanId/API22023TC1" element={<UserAuth><API22023TC1 /></UserAuth>} />
          <Route path="/api-pentest/scan/:scanId/API22023TC2" element={<UserAuth><API22023TC2 /></UserAuth>} />
          {/* <Route path="/api-pentest/scan/:scanId/API22023TC3" element={<UserAuth><API22023TC3 /></UserAuth>} /> */}
          <Route path="/api-pentest/scan/:scanId/API22023TC4" element={<UserAuth><API22023TC4 /></UserAuth>} />
          <Route path="/api-pentest/scan/:scanId/API22023TC5" element={<UserAuth><API22023TC5 /></UserAuth>} />
          <Route path="/api-pentest/scan/:scanId/API42023TC1" element={<UserAuth><API42023TC1 /></UserAuth>} />
          <Route path="/api-pentest/scan/:scanId/API42023TC2" element={<UserAuth><API42023TC2 /></UserAuth>} />
          <Route path="/api-pentest/scan/:scanId/API42023TC3" element={<UserAuth><API42023TC3 /></UserAuth>} />
          <Route path="/api-pentest/scan/:scanId/API42023TC4" element={<UserAuth><API42023TC4 /></UserAuth>} />
          <Route path="/api-pentest/scan/:scanId/API42023TC5" element={<UserAuth><API42023TC5 /></UserAuth>} />
          <Route path="/api-pentest/scan/:scanId/API42023TC6" element={<UserAuth><API42023TC6 /></UserAuth>} />
          <Route path="/api-pentest/results-tc6/:scanUuid" element={<UserAuth><API42023TC6 /></UserAuth>} />
          <Route path="/api-pentest/scan/:scanId/API62023TC1" element={<UserAuth><API62023TC1 /></UserAuth>} />
          <Route path="/api-pentest/api7-ssrf/" element={<UserAuth><API72023TC1 /></UserAuth>} />
          <Route path="/api-pentest/scan/:scanId/API72023TC1" element={<UserAuth><API72023TC1 /></UserAuth>} />
          <Route path="/api-pentest/scan/:scanId/API82023TC1" element={<UserAuth><API82023TC1 /></UserAuth>} />
          <Route path="/api-pentest/scan/:scanId/API82023TC2" element={<UserAuth><API82023TC2 /></UserAuth>} />
          <Route path="/api-pentest/scan/:scanId/API82023TC3" element={<UserAuth><API82023TC3 /></UserAuth>} />
          <Route path="/api-pentest/scan/:scanId/API92023TC1" element={<UserAuth><API92023TC1 /></UserAuth>} />
          <Route path="/api-pentest/scan/:scanId/API92023TC2" element={<UserAuth><API92023TC2 /></UserAuth>} />
          <Route path="/api-pentest/scan/:scanId/API92023TC3" element={<UserAuth><API92023TC3 /></UserAuth>} />
          <Route path="/api-pentest/scan/:scanId/API92023TC4" element={<UserAuth><API92023TC4 /></UserAuth>} />
          <Route path="/api-pentest/scan/:scanId/API92023TC5" element={<UserAuth><API92023TC5 /></UserAuth>} />
          <Route path="/api-pentest/scan/:scanId/API92023TC6" element={<UserAuth><API92023TC6 /></UserAuth>} />

        </Routes>
      </Router>
    </ThemeProvider>
  );
}

export default App;

// kpmg-tester
// Qwerty@12345
// 192.168.10.47
// Server1