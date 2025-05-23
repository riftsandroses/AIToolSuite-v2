// RiskAssessmentPage.js
import { useState, useEffect } from "react";
import {
  Box,
  Container,
  Typography,
  Button,
  Stepper,
  Step,
  StepLabel,
  Drawer,
  useMediaQuery
} from "@mui/material";
import { useTheme } from "@mui/material/styles";
import { Link } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import InfoIcon from "@mui/icons-material/Info";
import CloudIcon from "@mui/icons-material/Cloud";
import SecurityIcon from "@mui/icons-material/Security";
import AssessmentIcon from "@mui/icons-material/Assessment";

// Import components
import AppInformation from "../../components/RiskAssessment/AppInformation";
import ArchitectureHosting from "../../components/RiskAssessment/ArchitectureHosting";
import RiskSecurity from "../../components/RiskAssessment/RiskSecurity";
import RiskAnalysis from "../../components/RiskAssessment/RiskAnalysis";
import AssessmentList from "../../components/RiskAssessment/AssessmentList";

// Import API service
import { fetchAssessments, createAssessment, updateAssessment, deleteAssessment } from "../../api/assessmentService";

// Main component
export default function RiskAssessmentPage() {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));

  // State for the stepper and form
  const [activeStep, setActiveStep] = useState(0);
  const [mobileDrawerOpen, setMobileDrawerOpen] = useState(false);
  const [assessments, setAssessments] = useState([]);
  const [selectedAssessment, setSelectedAssessment] = useState(null); // Stores the full selected assessment object
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isEditing, setIsEditing] = useState(false);

  // Form data state
  const [formData, setFormData] = useState({
    application_name: "",
    business_logic: "",
    application_type: "",
    platforms: "",
    frontend: "",
    backend: "",
    database: "",
    architecture: "",
    hosting: "",
    sensitive_data: "",
    third_party_integrations: "",
    error_handling: "",
    user_input_handling: "",
    data_security: "",
    legacy_dependencies: "",
    monitoring: ""
  });

  // State for the assessment result from API (contains risk_score, application_description, etc.)
  const [assessmentResult, setAssessmentResult] = useState(null);

  // Steps for the stepper
  const steps = [
    { label: "Application Information", icon: <InfoIcon /> },
    { label: "Architecture & Hosting", icon: <CloudIcon /> },
    { label: "Risk & Security", icon: <SecurityIcon /> },
    { label: "Risk Analysis", icon: <AssessmentIcon /> },
  ];

  // Fetch assessments on component mount
  useEffect(() => {
    fetchExistingAssessments();
  }, []);

  // Fetch existing assessments from the API
  const fetchExistingAssessments = async () => {
    try {
      const data = await fetchAssessments();
      setAssessments(data);
    } catch (error) {
      console.error("Error fetching assessments:", error);
    }
  };

  // Handle form input changes
  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  // Handle tech stack input changes
  const handleTechStackChange = (category, value) => {
    setFormData(prev => ({
      ...prev,
      [category]: value
    }));
  };

  // Combine tech stack values into a single string for API submission
  const combineTechStack = () => {
    const { frontend, backend, database } = formData;
    let techStackParts = [];

    if (frontend) {
      techStackParts.push(`Frontend: ${frontend}`);
    }

    if (backend) {
      techStackParts.push(`Backend: ${backend}`);
    }

    if (database) {
      techStackParts.push(`Database: ${database}`);
    }

    return techStackParts.join(", ");
  };

  // Prepare form data for API submission
  const prepareFormDataForSubmission = () => {
    return {
      application_name: formData.application_name,
      business_logic: formData.business_logic,
      sensitive_data: formData.sensitive_data,
      application_type: formData.application_type,
      third_party_integrations: formData.third_party_integrations,
      error_handling: formData.error_handling,
      user_input_handling: formData.user_input_handling,
      architecture: formData.architecture,
      hosting: formData.hosting,
      tech_stack: combineTechStack(),
      platforms: formData.platforms,
      data_security: formData.data_security,
      legacy_dependencies: formData.legacy_dependencies,
      monitoring: formData.monitoring
    };
  };

  // Handle submit assessment (called after step 2)
  const handleSubmitAssessment = async () => {
    setIsSubmitting(true);
    try {
      const dataToSubmit = prepareFormDataForSubmission();
      let response;

      if (isEditing && selectedAssessment) {
        response = await updateAssessment(selectedAssessment.id, dataToSubmit);
      } else {
        response = await createAssessment(dataToSubmit);
      }

      setAssessmentResult(response); // Store the full API response
      await fetchExistingAssessments(); // Refresh the list of assessments
      setSelectedAssessment(response); // Set the current assessment as selected
      setIsEditing(false); // Reset editing mode
      setActiveStep(3); // Move to Risk Analysis step to show results

    } catch (error) {
      console.error("Error submitting assessment:", error);
      // Optionally, set an error state here to display to the user
    } finally {
      setIsSubmitting(false);
    }
  };

  // Handle next step
  const handleNext = () => {
    if (activeStep === 2) { // If on "Risk & Security" step (index 2)
      handleSubmitAssessment();
    } else if (activeStep < steps.length - 1) {
      setActiveStep((prevStep) => prevStep + 1);
    }
  };

  // Handle back step
  const handleBack = () => {
    setActiveStep((prevStep) => prevStep - 1);
  };


  // Handle assessment selection from the list
  const handleAssessmentSelect = (assessment) => {
    setSelectedAssessment(assessment); // Store the full selected assessment object
    setAssessmentResult(assessment);   // Use this to display in RiskAnalysis

    // Update form data with selected assessment details (primarily if user wants to edit later)
    // For direct viewing, assessmentResult is used.
    const techStackString = assessment.tech_stack || "";
    const techStackParts = {};
    ['Frontend', 'Backend', 'Database'].forEach(part => {
      const regex = new RegExp(`${part}: ([^,]+)`);
      const match = techStackString.match(regex);
      if (match && match[1]) {
        techStackParts[part.toLowerCase()] = match[1].trim();
      }
    });

    setFormData({
      application_name: assessment.application_name || "",
      business_logic: assessment.business_logic || "",
      application_type: assessment.application_type || "",
      platforms: assessment.platforms || "",
      architecture: assessment.architecture || "",
      hosting: assessment.hosting || "",
      sensitive_data: assessment.sensitive_data || "",
      third_party_integrations: assessment.third_party_integrations || "",
      error_handling: assessment.error_handling || "",
      user_input_handling: assessment.user_input_handling || "",
      data_security: assessment.data_security || "",
      legacy_dependencies: assessment.legacy_dependencies || "",
      monitoring: assessment.monitoring || "",
      frontend: techStackParts.frontend || "",
      backend: techStackParts.backend || "",
      database: techStackParts.database || ""
    });

    setIsEditing(false); // When selecting, it's for viewing, not editing initially
    setActiveStep(3); // Move to Risk Analysis step to show the selected assessment's details

    if (isMobile) {
      setMobileDrawerOpen(false);
    }
  };

  // Handle delete assessment
  const handleDeleteAssessment = async (id, e) => {
    if (e) e.stopPropagation();

    if (window.confirm("Are you sure you want to delete this assessment?")) {
      try {
        await deleteAssessment(id);
        await fetchExistingAssessments();

        if (selectedAssessment && selectedAssessment.id === id) {
          handleNewAssessment(); // Reset to new assessment state
        }
      } catch (error) {
        console.error("Error deleting assessment:", error);
      }
    }
  };

  // Handle edit assessment action
  const handleEditAssessment = (assessment, e) => {
    if (e) e.stopPropagation();

    setSelectedAssessment(assessment);
    setAssessmentResult(null); // Clear previous result as we are starting an edit

    const techStackString = assessment.tech_stack || "";
    const techStackParts = {};
    ['Frontend', 'Backend', 'Database'].forEach(part => {
      const regex = new RegExp(`${part}: ([^,]+)`);
      const match = techStackString.match(regex);
      if (match && match[1]) {
        techStackParts[part.toLowerCase()] = match[1].trim();
      }
    });

    setFormData({
      application_name: assessment.application_name || "",
      business_logic: assessment.business_logic || "",
      application_type: assessment.application_type || "",
      platforms: assessment.platforms || "",
      architecture: assessment.architecture || "",
      hosting: assessment.hosting || "",
      sensitive_data: assessment.sensitive_data || "",
      third_party_integrations: assessment.third_party_integrations || "",
      error_handling: assessment.error_handling || "",
      user_input_handling: assessment.user_input_handling || "",
      data_security: assessment.data_security || "",
      legacy_dependencies: assessment.legacy_dependencies || "",
      monitoring: assessment.monitoring || "",
      frontend: techStackParts.frontend || "",
      backend: techStackParts.backend || "",
      database: techStackParts.database || ""
    });

    setIsEditing(true);
    setActiveStep(0); // Start editing from the first step

    if (isMobile) {
      setMobileDrawerOpen(false);
    }
  };

  // Handle new assessment action
  const handleNewAssessment = () => {
    setSelectedAssessment(null);
    setAssessmentResult(null);

    setFormData({
      application_name: "",
      business_logic: "",
      application_type: "",
      platforms: "",
      frontend: "",
      backend: "",
      database: "",
      architecture: "",
      hosting: "",
      sensitive_data: "",
      third_party_integrations: "",
      error_handling: "",
      user_input_handling: "",
      data_security: "",
      legacy_dependencies: "",
      monitoring: ""
    });

    setIsEditing(false);
    setActiveStep(0); // Start at the beginning
    if (isMobile) {
      setMobileDrawerOpen(false);
    }
  };

  // Render form step content
  const getStepContent = (step) => {
    switch (step) {
      case 0:
        return (
          <AppInformation
            formData={formData}
            handleInputChange={handleInputChange}
            handleTechStackChange={handleTechStackChange}
          />
        );
      case 1:
        return (
          <ArchitectureHosting
            formData={formData}
            handleInputChange={handleInputChange}
          />
        );
      case 2:
        return (
          <RiskSecurity
            formData={formData}
            handleInputChange={handleInputChange}
          />
        );
      case 3:
        if (assessmentResult) { // If we have results from API (either new submission or selected)
          return <RiskAnalysis assessmentData={assessmentResult} />;
        }
        // Fallback if no assessmentResult (e.g. user directly navigates or error)
        return (
          <RiskAnalysis
            assessmentData={{
              application_name: formData.application_name || "Assessment",
              risk_score: "Not Calculated",
              application_description: "Please complete the assessment steps or select an existing one to view analysis."
            }}
          />
        );
      default:
        return "Unknown step";
    }
  };

  // Sidebar content
  const sidebarContent = (
    <AssessmentList
      assessments={assessments}
      selectedAssessment={selectedAssessment}
      handleAssessmentSelect={handleAssessmentSelect}
      handleDeleteAssessment={handleDeleteAssessment}
      handleEditAssessment={handleEditAssessment}
      handleNewAssessment={handleNewAssessment}
    />
  );

  return (
    <Box
      component="main"
      sx={{
        width: "100%",
        minHeight: "calc(100vh - 64px)",
        background: "linear-gradient(to bottom right, #121212, #1e1e1e)",
        display: "flex",
        flexDirection: "column",
      }}
    >
      <Container maxWidth="xl" sx={{ flex: 1, display: 'flex', flexDirection: 'column', py: 3 }}>
        <Box sx={{ mb: 3, display: 'flex', alignItems: 'center' }}>
          <Button component={Link} to="/" startIcon={<ArrowBackIcon />}>
            Back to Home
          </Button>
          {isMobile && (
            <Button
              variant="outlined"
              size="small"
              sx={{ ml: 'auto', fontSize: { xs: "1rem", md: "1.5rem" } }}
              onClick={() => setMobileDrawerOpen(true)}
            >
              Assessments
            </Button>
          )}
        </Box>

        <Typography
          variant="h2"
          component="h1"
          sx={{
            fontWeight: 700,
            mb: 2,
            background: "linear-gradient(45deg, #90caf9, #64b5f6)",
            backgroundClip: "text",
            textFillColor: "transparent",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
            fontSize: { xs: "2rem", md: "2.5rem" }
          }}
        >
          Risk Assessment Lab
        </Typography>

        <Typography
          variant="h5"
          component="p"
          sx={{
            mb: 4,
            color: "text.secondary",
            fontSize: { xs: "1rem", md: "1.1rem" }
          }}
        >
          Comprehensive AI-powered risk assessment tools to identify and mitigate potential security threats
        </Typography>

        <Box sx={{ flex: 1, display: 'flex', bgcolor: 'background.paper', borderRadius: 2, overflow: 'hidden' }}>
          {!isMobile && sidebarContent}
          {isMobile && (
            <Drawer
              anchor="left"
              open={mobileDrawerOpen}
              onClose={() => setMobileDrawerOpen(false)}
            >
              {sidebarContent}
            </Drawer>
          )}

          <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'auto' }}>
            <Box sx={{ p: 3, borderBottom: 1, borderColor: 'divider' }}>
              <Stepper
                activeStep={activeStep}
                alternativeLabel={!isMobile}
                orientation={isMobile ? "vertical" : "horizontal"}
                sx={{
                  '& .MuiStepLabel-iconContainer': {
                    '& .MuiSvgIcon-root': {
                      color: 'primary.main',
                    },
                  },
                }}
              >
                {steps.map((step) => (
                  <Step key={step.label}>
                    <StepLabel
                      StepIconProps={{
                        icon: step.icon
                      }}
                    >
                      {!isMobile && step.label}
                    </StepLabel>
                    {isMobile && (
                      <Typography variant="body2" sx={{ ml: 2, mt: 1 }}>
                        {step.label}
                      </Typography>
                    )}
                  </Step>
                ))}
              </Stepper>
            </Box>

            <Box sx={{ flex: 1, overflow: 'auto', p: 3 /* Add padding to content area */ }}>
              {getStepContent(activeStep)}
            </Box>

            <Box sx={{ p: 3, borderTop: 1, borderColor: 'divider', display: 'flex', justifyContent: 'space-between' }}>
              <Button
                disabled={activeStep === 0}
                onClick={handleBack}
                variant="outlined"
              >
                Back
              </Button>
              {/* Show Next/Submit button only for steps 0, 1, 2 */}
              {activeStep < steps.length - 1 && (
                <Button
                  variant="contained"
                  onClick={handleNext}
                  disabled={isSubmitting}
                  sx={{
                    background: "linear-gradient(45deg, #90caf9, #64b5f6)",
                    "&:hover": {
                      background: "linear-gradient(45deg, #64b5f6, #42a5f5)",
                    },
                  }}
                >
                  {activeStep === 2 ? 'Submit Assessment' : 'Next'}
                </Button>
              )}
              {/* On the last step (Risk Analysis), show a "Start New Assessment" button */}
              {activeStep === steps.length - 1 && (
                 <Button
                     variant="contained"
                     onClick={handleNewAssessment}
                     sx={{
                       background: "linear-gradient(45deg, #90caf9, #64b5f6)",
                       "&:hover": {
                         background: "linear-gradient(45deg, #64b5f6, #42a5f5)",
                       },
                     }}
                 >
                     Start New Assessment
                 </Button>
              )}
            </Box>
          </Box>
        </Box>
      </Container>
    </Box>
  );
}