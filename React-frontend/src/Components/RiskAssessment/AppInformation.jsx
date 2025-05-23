import React from "react";
import {
  Box,
  Typography,
  TextField,
  FormControl,
  Select,
  MenuItem,
  Grid,
} from "@mui/material";
import InfoIcon from "@mui/icons-material/Info";
import CodeIcon from "@mui/icons-material/Code";
import DevicesIcon from "@mui/icons-material/Devices";
import BusinessIcon from "@mui/icons-material/Business";
import { appTypeOptions, platformOptions, techStackOptions } from "./optionsData";

const AppInformation = ({ formData, handleInputChange, handleTechStackChange }) => {
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

        {/* Tech Stack */}
        <Grid item xs={12} md={6}>
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
                  onChange={(e) => handleTechStackChange("frontend", e.target.value)}
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
                  onChange={(e) => handleTechStackChange("backend", e.target.value)}
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
                  onChange={(e) => handleTechStackChange("database", e.target.value)}
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
          </Grid>
        </Grid>
      </Grid>
    </Box>
  );
};

export default AppInformation;