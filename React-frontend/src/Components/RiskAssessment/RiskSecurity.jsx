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
import SecurityIcon from "@mui/icons-material/Security";
import {
  dataSecurityOptions,
  sensitiveDataOptions,
  thirdPartyOptions,
  errorHandlingOptions,
  userInputOptions,
  monitoringOptions,
  legacyDependenciesOptions,
} from "./optionsData";

const RiskSecurity = ({ formData, handleInputChange }) => {
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

  const getHelperText = (field) => {
    switch (field) {
      case "data_security":
        return "Select the level of data security measures implemented in your application";
      case "sensitive_data":
        return "Select the type of sensitive data your application handles";
      case "third_party_integrations":
        return "Indicate the extent of third-party service integrations";
      case "error_handling":
        return "Select how comprehensively your application handles errors";
      case "user_input_handling":
        return "Select the types of user inputs your application processes";
      case "monitoring":
        return "Indicate the level of application monitoring implemented";
      case "legacy_dependencies":
        return "Select the extent of legacy dependencies in your application";
      case "compliance_requirements":
        return "List applicable compliance requirements (e.g., GDPR, HIPAA, PCI DSS)";
      default:
        return "";
    }
  };

  return (
    <Box sx={{ p: 3, borderRadius: 2 }}>
      <Typography variant="h5" component="h4" sx={{ mb: 3, fontWeight: 600 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <SecurityIcon />
          Risk and Security
        </Box>
      </Typography>

      <Grid container spacing={3}>
        {/* Data Security Level */}
        <Grid item xs={12} md={6}>
          <FormControl variant="outlined" sx={styles.formControl}>
            <InputLabel id="data-security-label" sx={styles.selectLabel}>
              Data Security
            </InputLabel>
            <Select
              labelId="data-security-label"
              name="data_security"
              value={formData.data_security || ""}
              onChange={handleInputChange}
              label="Data Security"
            >
              {dataSecurityOptions.map((option) => (
                <MenuItem key={option} value={option}>
                  {option.charAt(0).toUpperCase() + option.slice(1)}
                </MenuItem>
              ))}
            </Select>
            <FormHelperText sx={styles.helperText}>
              {getHelperText("data_security")}
            </FormHelperText>
          </FormControl>
        </Grid>

        {/* Sensitive Data */}
        <Grid item xs={12} md={6}>
          <FormControl variant="outlined" sx={styles.formControl}>
            <InputLabel id="sensitive-data-label" sx={styles.selectLabel}>
              Sensitive Data
            </InputLabel>
            <Select
              labelId="sensitive-data-label"
              name="sensitive_data"
              value={formData.sensitive_data || ""}
              onChange={handleInputChange}
              label="Sensitive Data"
            >
              {sensitiveDataOptions.map((option) => (
                <MenuItem key={option} value={option}>
                  {option.charAt(0).toUpperCase() + option.slice(1)}
                </MenuItem>
              ))}
            </Select>
            <FormHelperText sx={styles.helperText}>
              {getHelperText("sensitive_data")}
            </FormHelperText>
          </FormControl>
        </Grid>

        {/* Third Party Integrations */}
        <Grid item xs={12} md={6}>
          <FormControl variant="outlined" sx={styles.formControl}>
            <InputLabel id="third-party-label" sx={styles.selectLabel}>
              Third-Party Integrations
            </InputLabel>
            <Select
              labelId="third-party-label"
              name="third_party_integrations"
              value={formData.third_party_integrations || ""}
              onChange={handleInputChange}
              label="Third-Party Integrations"
            >
              {thirdPartyOptions.map((option) => (
                <MenuItem key={option} value={option}>
                  {option.charAt(0).toUpperCase() + option.slice(1)}
                </MenuItem>
              ))}
            </Select>
            <FormHelperText sx={styles.helperText}>
              {getHelperText("third_party_integrations")}
            </FormHelperText>
          </FormControl>
        </Grid>

        {/* Error Handling */}
        <Grid item xs={12} md={6}>
          <FormControl variant="outlined" sx={styles.formControl}>
            <InputLabel id="error-handling-label" sx={styles.selectLabel}>
              Error Handling
            </InputLabel>
            <Select
              labelId="error-handling-label"
              name="error_handling"
              value={formData.error_handling || ""}
              onChange={handleInputChange}
              label="Error Handling"
            >
              {errorHandlingOptions.map((option) => (
                <MenuItem key={option} value={option}>
                  {option.charAt(0).toUpperCase() + option.slice(1)}
                </MenuItem>
              ))}
            </Select>
            <FormHelperText sx={styles.helperText}>
              {getHelperText("error_handling")}
            </FormHelperText>
          </FormControl>
        </Grid>

        {/* User Input Handling */}
        <Grid item xs={12} md={6}>
          <FormControl variant="outlined" sx={styles.formControl}>
            <InputLabel id="user-input-label" sx={styles.selectLabel}>
              User Input Handling
            </InputLabel>
            <Select
              labelId="user-input-label"
              name="user_input_handling"
              value={formData.user_input_handling || ""}
              onChange={handleInputChange}
              label="User Input Handling"
            >
              {userInputOptions.map((option) => (
                <MenuItem key={option} value={option}>
                  {option.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ')}
                </MenuItem>
              ))}
            </Select>
            <FormHelperText sx={styles.helperText}>
              {getHelperText("user_input_handling")}
            </FormHelperText>
          </FormControl>
        </Grid>

        {/* Monitoring */}
        <Grid item xs={12} md={6}>
          <FormControl variant="outlined" sx={styles.formControl}>
            <InputLabel id="monitoring-label" sx={styles.selectLabel}>
              Monitoring
            </InputLabel>
            <Select
              labelId="monitoring-label"
              name="monitoring"
              value={formData.monitoring || ""}
              onChange={handleInputChange}
              label="Monitoring"
            >
              {monitoringOptions.map((option) => (
                <MenuItem key={option} value={option}>
                  {option.charAt(0).toUpperCase() + option.slice(1)}
                </MenuItem>
              ))}
            </Select>
            <FormHelperText sx={styles.helperText}>
              {getHelperText("monitoring")}
            </FormHelperText>
          </FormControl>
        </Grid>

        {/* Legacy Dependencies */}
        <Grid item xs={12} md={6}>
          <FormControl variant="outlined" sx={styles.formControl}>
            <InputLabel id="legacy-dependencies-label" sx={styles.selectLabel}>
              Legacy Dependencies
            </InputLabel>
            <Select
              labelId="legacy-dependencies-label"
              name="legacy_dependencies"
              value={formData.legacy_dependencies || ""}
              onChange={handleInputChange}
              label="Legacy Dependencies"
            >
              {legacyDependenciesOptions.map((option) => (
                <MenuItem key={option} value={option}>
                  {option.charAt(0).toUpperCase() + option.slice(1)}
                </MenuItem>
              ))}
            </Select>
            <FormHelperText sx={styles.helperText}>
              {getHelperText("legacy_dependencies")}
            </FormHelperText>
          </FormControl>
        </Grid>
      </Grid>
    </Box>
  );
};

export default RiskSecurity;