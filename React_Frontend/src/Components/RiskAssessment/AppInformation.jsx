import React from "react";
import {
  Box,
  Typography,
  TextField,
  FormControl,
  Select,
  MenuItem,
  Grid,
  Button,
  IconButton,
} from "@mui/material";
import InfoIcon from "@mui/icons-material/Info";
import CodeIcon from "@mui/icons-material/Code";
import DevicesIcon from "@mui/icons-material/Devices";
import BusinessIcon from "@mui/icons-material/Business";
import FileUploadIcon from "@mui/icons-material/FileUpload";
import ClearIcon from "@mui/icons-material/Clear";
import DescriptionIcon from "@mui/icons-material/Description";
import { appTypeOptions, platformOptions, techStackOptions } from "./optionsData";

const AppInformation = ({
  formData,
  handleInputChange,
  handleTechStackChange,
  handleFileChange,
  handleRemoveFile,
}) => {
  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h5" component="h4" sx={{ mb: 3, fontWeight: 600 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <InfoIcon />
          Application Information
        </Box>
      </Typography>

      <Grid container spacing={3}>
        {/* Application Name */}
        <Grid item xs={12} md={6}>
          <Typography variant="subtitle1" color="primary" gutterBottom>
            Application Name
          </Typography>
          <TextField
            fullWidth
            placeholder="Enter application name"
            name="application_name"
            value={formData.application_name || ""}
            onChange={handleInputChange}
            variant="outlined"
            size="small"
          />
        </Grid>

        {/* Application Type */}
        <Grid item xs={12} md={6}>
          <Typography variant="subtitle1" color="primary" gutterBottom>
            Application Type
          </Typography>
          <FormControl fullWidth size="small">
            <Select
              name="application_type"
              value={formData.application_type || ""}
              onChange={handleInputChange}
              displayEmpty
            >
              <MenuItem value="" disabled>
                Select application type
              </MenuItem>
              {appTypeOptions.map((option) => (
                <MenuItem key={option.value} value={option.value}>
                  {option.label}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </Grid>

        {/* Platforms */}
        <Grid item xs={12} md={6}>
          <Typography
            variant="subtitle1"
            color="primary"
            gutterBottom
            sx={{ display: "flex", alignItems: "center" }}
          >
            <DevicesIcon sx={{ mr: 1, fontSize: "1rem" }} />
            Platforms
          </Typography>
          <FormControl fullWidth size="small">
            <Select
              name="platforms"
              value={formData.platforms || ""}
              onChange={handleInputChange}
              displayEmpty
            >
              <MenuItem value="" disabled>
                Select platforms
              </MenuItem>
              {platformOptions.map((option) => (
                <MenuItem key={option.value} value={option.value}>
                  {option.label}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </Grid>

        {/* Business Logic */}
        <Grid item style={{ width: "90%" }} xs={12} md={6}>
          <Typography
            variant="subtitle1"
            color="primary"
            gutterBottom
            sx={{ display: "flex", alignItems: "center" }}
          >
            <BusinessIcon sx={{ mr: 1, fontSize: "1rem" }} />
            Business Logic
          </Typography>
          <TextField
            fullWidth
            placeholder="Describe the business logic and purpose of the application"
            name="business_logic"
            value={formData.business_logic || ""}
            onChange={handleInputChange}
            variant="outlined"
            multiline
            rows={3}
          />
        </Grid>

        {/* --- FIX: Tech Stack is now full-width --- */}
        <Grid item xs={12} md={12}>
          <Typography
            variant="subtitle1"
            color="primary"
            gutterBottom
            sx={{ display: "flex", alignItems: "center" }}
          >
            <CodeIcon sx={{ mr: 1, fontSize: "1rem" }} />
            Tech Stack
          </Typography>
          <Grid container spacing={2}>
            {/* Frontend */}
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle1" color="primary" gutterBottom>
                Frontend
              </Typography>
              <FormControl fullWidth size="small">
                <Select
                  name="frontend"
                  value={formData.frontend || ""}
                  onChange={(e) =>
                    handleTechStackChange("frontend", e.target.value)
                  }
                  displayEmpty
                >
                  <MenuItem value="" disabled>
                    Select Frontend Tech
                  </MenuItem>
                  {techStackOptions.frontend.map((option) => (
                    <MenuItem key={option.value} value={option.value}>
                      {option.label}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
            {/* Backend */}
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle1" color="primary" gutterBottom>
                Backend
              </Typography>
              <FormControl fullWidth size="small">
                <Select
                  name="backend"
                  value={formData.backend || ""}
                  onChange={(e) =>
                    handleTechStackChange("backend", e.target.value)
                  }
                  displayEmpty
                >
                  <MenuItem value="" disabled>
                    Select Backend Tech
                  </MenuItem>
                  {techStackOptions.backend.map((option) => (
                    <MenuItem key={option.value} value={option.value}>
                      {option.label}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
            {/* Database */}
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle1" color="primary" gutterBottom>
                Database
              </Typography>
              <FormControl fullWidth size="small">
                <Select
                  name="database"
                  value={formData.database || ""}
                  onChange={(e) =>
                    handleTechStackChange("database", e.target.value)
                  }
                  displayEmpty
                >
                  <MenuItem value="" disabled>
                    Select Database
                  </MenuItem>
                  {techStackOptions.database.map((option) => (
                    <MenuItem key={option.value} value={option.value}>
                      {option.label}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>

            {/* Upload Architecture Diagram */}
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle1" color="primary" gutterBottom>
                Upload Architecture Diagram
              </Typography>
              {formData.tech_stack_file ? (
                <Box
                  sx={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    border: "1px solid rgba(0, 0, 0, 0.23)",
                    borderRadius: "4px",
                    padding: "8.5px 14px",
                    height: "40px",
                    boxSizing: "border-box",
                  }}
                >
                  <Typography
                    variant="body1"
                    sx={{
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                      color: "text.primary",
                    }}
                  >
                    {formData.tech_stack_file.name}
                  </Typography>
                  <IconButton
                    onClick={() => handleRemoveFile("tech_stack_file")}
                    size="small"
                    sx={{ p: 0.5 }}
                  >
                    <ClearIcon fontSize="small" />
                  </IconButton>
                </Box>
              ) : (
                <Button
                  variant="outlined"
                  component="label"
                  fullWidth
                  size="small"
                  startIcon={<FileUploadIcon />}
                  sx={{
                    height: "40px",
                    justifyContent: "flex-start",
                    textTransform: "none",
                    color: "text.secondary",
                    borderColor: "rgba(0, 0, 0, 0.23)",
                    "&:hover": {
                      borderColor: "rgba(0, 0, 0, 0.87)",
                      bgcolor: "rgba(0, 0, 0, 0.04)",
                    },
                  }}
                >
                  Select File...
                  <input
                    type="file"
                    hidden
                    name="tech_stack_file"
                    onChange={handleFileChange}
                    onClick={(e) => (e.target.value = null)}
                  />
                </Button>
              )}
            </Grid>
          </Grid>
        </Grid>
        {/* --- END OF TECH STACK GRID ITEM --- */}

        {/* --- FIX: SOW/Proposal is now its own full-width section --- */}
        <Grid item xs={12} md={12}>
          <Typography
            variant="subtitle1"
            color="primary"
            gutterBottom
            sx={{ display: "flex", alignItems: "center" }}
          >
            <DescriptionIcon sx={{ mr: 1, fontSize: "1rem" }} />
            SOW/Proposal
          </Typography>
          {formData.sow_proposal_file ? (
            <Box
              sx={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                border: "1px solid rgba(0, 0, 0, 0.23)",
                borderRadius: "4px",
                padding: "8.5px 14px",
                height: "40px",
                boxSizing: "border-box",
              }}
            >
              <Typography
                variant="body1"
                sx={{
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                  color: "text.primary",
                }}
              >
                {formData.sow_proposal_file.name}
              </Typography>
              <IconButton
                onClick={() => handleRemoveFile("sow_proposal_file")}
                size="small"
                sx={{ p: 0.5 }}
              >
                <ClearIcon fontSize="small" />
              </IconButton>
            </Box>
          ) : (
            <Button
              variant="outlined"
              component="label"
              fullWidth
              size="small"
              startIcon={<FileUploadIcon />}
              sx={{
                height: "40px",
                justifyContent: "flex-start",
                textTransform: "none",
                color: "text.secondary",
                borderColor: "rgba(0, 0, 0, 0.23)",
                "&:hover": {
                  borderColor: "rgba(0, 0, 0, 0.87)",
                  bgcolor: "rgba(0, 0, 0, 0.04)",
                },
              }}
            >
              Select File...
              <input
                type="file"
                hidden
                // --- THIS WAS THE BUG ---
                name="sow_proposal_file"
                onChange={handleFileChange}
                onClick={(e) => (e.target.value = null)}
              />
            </Button>
          )}
        </Grid>
        {/* --- END OF SOW/PROPOSAL GRID ITEM --- */}
      </Grid>
    </Box>
  );
};

export default AppInformation;