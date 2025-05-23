import React from "react";
import { Box, Typography, Chip, LinearProgress, linearProgressClasses } from "@mui/material";
import { styled } from "@mui/material/styles";
import AssessmentIcon from "@mui/icons-material/Assessment";

const BorderLinearProgress = styled(LinearProgress)(({ theme, componentcolor }) => ({
  height: 15,
  borderRadius: 7,
  [`&.${linearProgressClasses.colorPrimary}`]: {
    backgroundColor: theme.palette.grey[theme.palette.mode === 'light' ? 300 : 800],
  },
  [`& .${linearProgressClasses.bar}`]: {
    borderRadius: 7,
    backgroundColor: theme.palette[componentcolor] ? theme.palette[componentcolor].main : theme.palette.primary.main,
  },
}));

const RiskAnalysis = ({ assessmentData }) => {
  const riskScore = assessmentData.risk_score;
  
  const getRiskSeverity = (score) => {
    if (score > 70) return "error";
    if (score > 40) return "warning";
    return "success";
  };

  const getRiskLabelText = (score) => {
    if (score > 70) return "High Risk";
    if (score > 40) return "Medium Risk";
    return "Low Risk";
  };

  const currentRiskSeverity = getRiskSeverity(riskScore);
  const currentRiskLabel = getRiskLabelText(riskScore);

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h5" component="h4" sx={{ mb: 3, fontWeight: 600 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <AssessmentIcon />
          Risk Analysis
        </Box>
      </Typography>

      <Typography variant="h6" component="h5" sx={{ mt: 2, mb: 1, fontWeight: 500 }}>
        Application Description
      </Typography>
      <Typography variant="body1" sx={{ mb: 4, color: "text.secondary", lineHeight: 1.7 }}>
        {assessmentData.application_description || 
          "This is a placeholder for the application description. In a real-world scenario, this content would be dynamically generated based on the assessment data."}
      </Typography>

      <Typography variant="h6" component="h5" sx={{ mt: 5, mb: 2, fontWeight: 500 }}>
        Overall Risk Score
      </Typography>
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
        <Typography
          variant="h2"
          component="span"
          sx={{ color: `${currentRiskSeverity}.main`, fontWeight: "bold" }}
        >
          {riskScore?.toFixed(0) || 0}
        </Typography>
        <Chip
          label={currentRiskLabel}
          color={currentRiskSeverity}
          sx={{ fontWeight: "medium" }}
        />
      </Box>
      <BorderLinearProgress
        variant="determinate"
        value={riskScore}
        componentcolor={currentRiskSeverity}
      />
      <Typography variant="body2" sx={{ mt: 1, color: `${currentRiskSeverity}.main` }}>
        {`Based on the current assessment, this application is considered ${currentRiskLabel.toLowerCase()}.`}
      </Typography>
    </Box>
  );
};

export default RiskAnalysis;
