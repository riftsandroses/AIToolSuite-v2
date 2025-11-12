// components/AssessmentList.js
import React from "react";
import {
  Box,
  Typography,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  ListItemSecondaryAction,
  IconButton,
  Divider,
  Tooltip,
  styled,
} from "@mui/material";
import AssessmentIcon from "@mui/icons-material/Assessment";
import DeleteIcon from "@mui/icons-material/Delete";
import EditIcon from "@mui/icons-material/Edit";
import AddIcon from "@mui/icons-material/Add";
import RiskChip from "./RiskChip";

const StyledSidebar = styled(Box)(({ theme }) => ({
  width: 280,
  backgroundColor: theme.palette.background.paper,
  borderRight: `1px solid ${theme.palette.divider}`,
  height: "100%",
  overflowY: "auto",
  [theme.breakpoints.down("md")]: {
    width: 240,
  },
}));

const StyledListItem = styled(ListItem)(({ theme }) => ({
  borderRadius: theme.shape.borderRadius,
  marginBottom: theme.spacing(1),
  "&:hover": {
    backgroundColor: "rgba(144, 202, 249, 0.08)",
  },
}));

const AssessmentList = ({ 
  assessments,
  selectedAssessment,
  handleAssessmentSelect,
  handleDeleteAssessment,
  handleEditAssessment,
  handleNewAssessment
}) => {
  return (
    <StyledSidebar>
      <Box sx={{ p: 2, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <Typography variant="h6">Previous Assessments</Typography>
        <Tooltip title="New Assessment">
          <IconButton color="primary" size="small" onClick={handleNewAssessment}>
            <AddIcon />
          </IconButton>
        </Tooltip>
      </Box>
      <Divider />
      <List sx={{ p: 1 }}>
        {assessments.length > 0 ? (
          assessments.map((assessment) => {
            // Determine risk level based on score
            let riskLevel = "Low";
            if (assessment.risk_score > 70) riskLevel = "High";
            else if (assessment.risk_score > 40) riskLevel = "Medium";
            
            return (
              <StyledListItem
                key={assessment.id}
                button
                selected={selectedAssessment?.id === assessment.id}
                onClick={() => handleAssessmentSelect(assessment)}
              >
                <ListItemIcon>
                  <AssessmentIcon color="primary" />
                </ListItemIcon>
                <ListItemText
                  primary={assessment.application_name}
                  secondary={
                    <Box sx={{ display: "flex", alignItems: "center", mt: 0.5 }}>
                      <Typography variant="caption" sx={{ mr: 1 }}>
                        {new Date(assessment.created_at).toLocaleDateString()}
                      </Typography>
                      <RiskChip label={riskLevel} size="small" risklevel={riskLevel} />
                    </Box>
                  }
                />
                <ListItemSecondaryAction>
                  <Tooltip title="Edit">
                    <IconButton
                      edge="end"
                      size="small"
                      onClick={(e) => handleEditAssessment(assessment, e)}
                    >
                      <EditIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                  <Tooltip title="Delete">
                    <IconButton
                      edge="end"
                      size="small"
                      onClick={(e) => handleDeleteAssessment(assessment.id, e)}
                    >
                      <DeleteIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                </ListItemSecondaryAction>
              </StyledListItem>
            );
          })
        ) : (
          <ListItem>
            <ListItemText primary="No assessments yet" />
          </ListItem>
        )}
      </List>
    </StyledSidebar>
  );
};

export default AssessmentList;