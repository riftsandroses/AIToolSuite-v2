import { useState, useEffect } from "react";
import {
  AppBar,
  Toolbar,
  Button,
  Menu,
  MenuItem,
  Box,
  IconButton,
  Drawer,
  List,
  ListItem,
  ListItemButton,
  ListItemText,
  Collapse,
  Divider,
  Typography,
} from "@mui/material";
import MenuIcon from "@mui/icons-material/Menu";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ExpandLessIcon from "@mui/icons-material/ExpandLess";
import LoginIcon from "@mui/icons-material/Login";
import LogoutIcon from "@mui/icons-material/Logout";
import CloseIcon from "@mui/icons-material/Close";
import { useMediaQuery, useTheme } from "@mui/material";
import { Link, useNavigate } from "react-router-dom";
import { getAuthCookies, deleteAuthCookies, signOutUser } from "../api/auth";

export default function Navbar() {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));
  const navigate = useNavigate();

  const [isAuthenticated, setIsAuthenticated] = useState(false);

  const [insightsLabAnchorEl, setInsightsLabAnchorEl] = useState(null);
  const [attackLabAnchorEl, setAttackLabAnchorEl] = useState(null);
  const [windowLabAnchorEl, setWindowLabAnchorEl] = useState(null);

  const [mobileOpen, setMobileOpen] = useState(false);
  const [insightsLabOpen, setInsightsLabOpen] = useState(false);
  const [attackLabOpen, setAttackLabOpen] = useState(false);
  const [windowLabOpen, setWindowLabOpen] = useState(false);

  useEffect(() => {
    const token = getAuthCookies().accessToken;
    setIsAuthenticated(!!token);
  }, []);

  const handleDrawerToggle = () => {
    setMobileOpen(!mobileOpen);
  };

  const toggleInsightsLabMenu = () => {
    setInsightsLabOpen(!insightsLabOpen);
  };

  const toggleAttackLabMenu = () => {
    setAttackLabOpen(!attackLabOpen);
  };

  const toggleWindowLabMenu = () => {
    setWindowLabOpen(!windowLabOpen);
  };

  const handleArchitectureAssessmentClick = () => {
    navigate("/architecture-assessment");
    setMobileOpen(false);
  };

  const handleRiskAssessmentClick = () => {
    navigate("/risk-assessment");
    setMobileOpen(false);
  };

  const handleThreatModelClick = () => {
    navigate("/threat-model");
    setMobileOpen(false);
  };

  const handleApiPentestClick = () => {
    navigate("/api-pentest");
    setMobileOpen(false);
  };

  const handleLoginClick = () => {
    navigate("/login");
    setMobileOpen(false);
  };

  const handleLogoutClick = async () => {
    try {
      await signOutUser();  // ✅ wait for backend
    } catch (error) {
      console.error("Logout failed:", error.response?.data || error.message);
    } finally {
      deleteAuthCookies();     // ✅ clear tokens AFTER
      setIsAuthenticated(false);
      navigate("/login");
    }
  };

  const desktopNavbar = (
    <>
      <Button color="inherit" onClick={handleArchitectureAssessmentClick} sx={{ mr: 2, textTransform: "none" }}>
        Architecture Assessment
      </Button>

      {/* <Button color="inherit" onClick={handleRiskAssessmentClick} sx={{ mr: 2, textTransform: "none" }}>
        Architecture Risk Assessment Lab
      </Button> */}

      <Button color="inherit" onClick={handleThreatModelClick} sx={{ mr: 2, textTransform: "none" }}>
        Threat Model
      </Button>

      {/* AI Attack Lab */}
      <Button
        color="inherit"
        onClick={(e) => setAttackLabAnchorEl(e.currentTarget)}
        endIcon={<ExpandMoreIcon />}
        sx={{ mr: 2, textTransform: "none" }}
      >
        AI Attack Lab
      </Button>

      <Menu
        anchorEl={attackLabAnchorEl}
        open={Boolean(attackLabAnchorEl)}
        onClose={() => setAttackLabAnchorEl(null)}
      >
        <Link to="/llm-vulnerability-scanner" style={{ textDecoration: "none", color: "inherit" }}>
          <MenuItem onClick={() => setAttackLabAnchorEl(null)}>
            AI Attack Tester
          </MenuItem>
        </Link>
      </Menu>

      {/* Reports & Insights */}
      <Button
        color="inherit"
        onClick={(e) => setInsightsLabAnchorEl(e.currentTarget)}
        endIcon={<ExpandMoreIcon />}
        sx={{ mr: 2, textTransform: "none" }}
      >
        Reports & Insights Lab
      </Button>

      <Menu
        anchorEl={insightsLabAnchorEl}
        open={Boolean(insightsLabAnchorEl)}
        onClose={() => setInsightsLabAnchorEl(null)}
      >
        <Link to="/llm-vulnerability-scanner-report" style={{ textDecoration: "none", color: "inherit" }}>
          <MenuItem onClick={() => setInsightsLabAnchorEl(null)}>
            AI Attack Report
          </MenuItem>
        </Link>
      </Menu>

      {/* API Pentest */}
      <Button color="inherit" onClick={handleApiPentestClick} sx={{ mr: 2, textTransform: "none" }}>
        API Pentest
      </Button>

      {/* Windows Attack Lab */}
      <Button
        color="inherit"
        onClick={(e) => setWindowLabAnchorEl(e.currentTarget)}
        endIcon={<ExpandMoreIcon />}
        sx={{ mr: 3, textTransform: "none" }}
      >
        Windows Attack Lab
      </Button>

      <Menu
        anchorEl={windowLabAnchorEl}
        open={Boolean(windowLabAnchorEl)}
        onClose={() => setWindowLabAnchorEl(null)}
      >
        <Link to="/dll" style={{ textDecoration: "none", color: "inherit" }}>
          <MenuItem onClick={() => setWindowLabAnchorEl(null)}>
            DLL Hijacker (AI Agent)
          </MenuItem>
        </Link>
      </Menu>

      {isAuthenticated ? (
        <Button color="inherit" onClick={handleLogoutClick} startIcon={<LogoutIcon />}>
          Logout
        </Button>
      ) : (
        <Button color="inherit" onClick={handleLoginClick} startIcon={<LoginIcon />}>
          Login
        </Button>
      )}
    </>
  );

  const mobileDrawer = (
    <Box sx={{ width: 300 }}>
      <Box
        sx={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          p: 2,
          borderBottom: "1px solid rgba(255,255,255,0.1)",
        }}
      >
        <Typography variant="h6">AI Security Suite</Typography>
        <IconButton onClick={handleDrawerToggle}>
          <CloseIcon />
        </IconButton>
      </Box>

      <List>

        <ListItem disablePadding>
          <ListItemButton onClick={handleArchitectureAssessmentClick}>
            <ListItemText primary="Architecture Assessment" />
          </ListItemButton>
        </ListItem>

        <ListItem disablePadding>
          <ListItemButton onClick={handleRiskAssessmentClick}>
            <ListItemText primary="Architecture Risk Assessment Lab" />
          </ListItemButton>
        </ListItem>

        <ListItem disablePadding>
          <ListItemButton onClick={handleThreatModelClick}>
            <ListItemText primary="Threat Model" />
          </ListItemButton>
        </ListItem>

        {/* AI Attack Lab */}
        <ListItem disablePadding>
          <ListItemButton onClick={toggleAttackLabMenu}>
            <ListItemText primary="AI Attack Lab" />
            {attackLabOpen ? <ExpandLessIcon /> : <ExpandMoreIcon />}
          </ListItemButton>
        </ListItem>

        <Collapse in={attackLabOpen}>
          <List component="div" disablePadding>
            <Link to="/llm-vulnerability-scanner" style={{ textDecoration: "none", color: "inherit" }}>
              <ListItemButton sx={{ pl: 4 }}>
                <ListItemText primary="AI Attack Tester" />
              </ListItemButton>
            </Link>
          </List>
        </Collapse>

        {/* Reports */}
        <ListItem disablePadding>
          <ListItemButton onClick={toggleInsightsLabMenu}>
            <ListItemText primary="Reports & Insights Lab" />
            {insightsLabOpen ? <ExpandLessIcon /> : <ExpandMoreIcon />}
          </ListItemButton>
        </ListItem>

        <Collapse in={insightsLabOpen}>
          <List component="div" disablePadding>
            <Link to="/llm-vulnerability-scanner-report" style={{ textDecoration: "none", color: "inherit" }}>
              <ListItemButton sx={{ pl: 4 }}>
                <ListItemText primary="AI Attack Report" />
              </ListItemButton>
            </Link>
          </List>
        </Collapse>

        <ListItem disablePadding>
          <ListItemButton onClick={handleApiPentestClick}>
            <ListItemText primary="API Pentest" />
          </ListItemButton>
        </ListItem>

        {/* Windows Attack */}
        <ListItem disablePadding>
          <ListItemButton onClick={toggleWindowLabMenu}>
            <ListItemText primary="Windows Attack Lab" />
            {windowLabOpen ? <ExpandLessIcon /> : <ExpandMoreIcon />}
          </ListItemButton>
        </ListItem>

        <Collapse in={windowLabOpen}>
          <List component="div" disablePadding>
            <Link to="/dll" style={{ textDecoration: "none", color: "inherit" }}>
              <ListItemButton sx={{ pl: 4 }}>
                <ListItemText primary="DLL Hijacker (AI Agent)" />
              </ListItemButton>
            </Link>
          </List>
        </Collapse>

        <Divider sx={{ my: 2 }} />

        {isAuthenticated ? (
          <ListItem disablePadding>
            <ListItemButton onClick={handleLogoutClick}>
              <LogoutIcon sx={{ mr: 2 }} />
              <ListItemText primary="Logout" />
            </ListItemButton>
          </ListItem>
        ) : (
          <ListItem disablePadding>
            <ListItemButton onClick={handleLoginClick}>
              <LoginIcon sx={{ mr: 2 }} />
              <ListItemText primary="Login" />
            </ListItemButton>
          </ListItem>
        )}

      </List>
    </Box>
  );

  return (
    <>
      <AppBar
        position="static"
        color="transparent"
        elevation={0}
        sx={{ borderBottom: "1px solid rgba(255,255,255,0.1)" }}
      >
        <Toolbar>

          <Box
            component={Link}
            to="/"
            sx={{
              fontWeight: 700,
              fontSize: "1.3rem",
              textDecoration: "none",
              color: "primary.main",
              mr: 4,
            }}
          >
            AI Security Suite
          </Box>

          {isMobile ? (
            <IconButton sx={{ ml: "auto" }} onClick={handleDrawerToggle}>
              <MenuIcon />
            </IconButton>
          ) : (
            <Box sx={{ display: "flex", ml: "auto", alignItems: "center" }}>
              {desktopNavbar}
            </Box>
          )}
        </Toolbar>
      </AppBar>

      <Drawer
        variant="temporary"
        open={mobileOpen}
        onClose={handleDrawerToggle}
        sx={{
          "& .MuiDrawer-paper": {
            width: 300,
          },
        }}
      >
        {mobileDrawer}
      </Drawer>
    </>
  );
}