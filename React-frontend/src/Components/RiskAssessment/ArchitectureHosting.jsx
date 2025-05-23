import React from "react";
import {
  Box,
  Typography,
  FormControl,
  Select,
  MenuItem,
  Grid,
  InputLabel,
  FormHelperText,
} from "@mui/material";
import CloudIcon from "@mui/icons-material/Cloud";
import { architectureOptions, hostingOptions } from "./optionsData";

const ArchitectureHosting = ({ formData, handleInputChange }) => {
  const styles = {
    formControl: {
      width: "100%",
    },
    selectLabel: {
      padding: "0 5px",
    },
    helperText: {
      marginTop: 1,
      fontSize: "0.75rem",
    },
  };

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h5" component="h4" sx={{ mb: 3, fontWeight: 600 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <CloudIcon />
          Architecture and Hosting
        </Box>
      </Typography>
      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <FormControl variant="outlined" sx={styles.formControl} fullWidth>
            <InputLabel id="architecture-label" sx={styles.selectLabel}>
              Architecture
            </InputLabel>
            <Select
              labelId="architecture-label"
              id="architecture"
              name="architecture"
              value={formData.architecture || ""}
              onChange={handleInputChange}
              label="Architecture"
            >
              {architectureOptions.map((option) => (
                <MenuItem key={option.value} value={option.value}>
                  {option.label}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
          <FormHelperText sx={styles.helperText}>
            Select the architecture pattern used in your application
          </FormHelperText>
        </Grid>
        <Grid item xs={12} md={6}>
          <FormControl variant="outlined" sx={styles.formControl}>
            <InputLabel id="hosting-label" sx={styles.selectLabel}>
              Hosting
            </InputLabel>
            <Select
              labelId="hosting-label"
              id="hosting"
              name="hosting"
              value={formData.hosting || ""}
              onChange={handleInputChange}
              label="Hosting"
            >
              {hostingOptions.map((option) => (
                <MenuItem key={option.value} value={option.value}>
                  {option.label}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
          <FormHelperText sx={styles.helperText}>
            Select the hosting service used for your application
          </FormHelperText>
        </Grid>
      </Grid>
    </Box>
  );
};

export default ArchitectureHosting;