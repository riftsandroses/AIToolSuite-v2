import { useState } from "react";
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
} from "@mui/material";
import MenuIcon from "@mui/icons-material/Menu";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ExpandLessIcon from "@mui/icons-material/ExpandLess";
import { useMediaQuery, useTheme } from "@mui/material";
import { Link, useNavigate } from "react-router-dom";

export default function Navbar() {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));
  const navigate = useNavigate();

  // Desktop dropdown states
  const [insightsLabAnchorEl, setInsightsLabAnchorEl] = useState(null);
  const [attackLabAnchorEl, setAttackLabAnchorEl] = useState(null);

  // Mobile menu state
  const [mobileOpen, setMobileOpen] = useState(false);
  const [insightsLabOpen, setInsightsLabOpen] = useState(false);
  const [attackLabOpen, setAttackLabOpen] = useState(false);

  // Desktop dropdown handlers
  const handleInsightsLabMenuOpen = (event) => {
    setInsightsLabAnchorEl(event.currentTarget);
  };

  const handleInsightsLabMenuClose = () => {
    setInsightsLabAnchorEl(null);
  };

  const handleAttackLabMenuOpen = (event) => {
    setAttackLabAnchorEl(event.currentTarget);
  };

  const handleAttackLabMenuClose = () => {
    setAttackLabAnchorEl(null);
  };

  // Mobile drawer handlers
  const handleDrawerToggle = () => {
    setMobileOpen(!mobileOpen);
  };

  const toggleInsightsLabMenu = () => {
    setInsightsLabOpen(!insightsLabOpen);
  };

  const toggleAttackLabMenu = () => {
    setAttackLabOpen(!attackLabOpen);
  };

  // Handle Risk Assessment click to navigate in the same tab
  const handleRiskAssessmentClick = () => {
    navigate("/risk-assessment");
    setMobileOpen(false); // Close mobile drawer if open
  };
  
  const handleThreatModelClick = () => {
    navigate("/threat-model");
    setMobileOpen(false); // Close mobile drawer if open
  };

  // Desktop navbar
  const desktopNavbar = (
    <>
      <Button
        color="inherit"
        aria-controls="insights-lab-menu"
        aria-haspopup="true"
        onClick={handleInsightsLabMenuOpen}
        endIcon={<ExpandMoreIcon />}
        sx={{
          mr: 2,
          "&:hover": {
            backgroundColor: "rgba(255, 255, 255, 0.08)",
            transition: "all 0.3s ease",
          },
        }}
      >
        Reports & Insights Lab
      </Button>
      <Menu
        id="insights-lab-menu"
        anchorEl={insightsLabAnchorEl}
        keepMounted
        open={Boolean(insightsLabAnchorEl)}
        onClose={handleInsightsLabMenuClose}
        MenuListProps={{
          "aria-labelledby": "insights-lab-button",
        }}
        PaperProps={{
          elevation: 3,
          sx: {
            mt: 1,
            "& .MuiMenuItem-root": {
              "&:hover": {
                backgroundColor: "rgba(144, 202, 249, 0.08)",
                transition: "all 0.2s ease",
              },
            },
          },
        }}
      >
        <Link to="/llm-vulnerability-scanner-report" style={{ textDecoration: "none", color: "inherit" }}>
          <MenuItem onClick={handleInsightsLabMenuClose}>LLM Vulnerability</MenuItem>
        </Link>
      </Menu>

      <Button
        color="inherit"
        aria-controls="attack-lab-menu"
        aria-haspopup="true"
        onClick={handleAttackLabMenuOpen}
        endIcon={<ExpandMoreIcon />}
        sx={{
          mr: 2,
          "&:hover": {
            backgroundColor: "rgba(255, 255, 255, 0.08)",
            transition: "all 0.3s ease",
          },
        }}
      >
        AI Attack Lab
      </Button>
      <Menu
        id="attack-lab-menu"
        anchorEl={attackLabAnchorEl}
        keepMounted
        open={Boolean(attackLabAnchorEl)}
        onClose={handleAttackLabMenuClose}
        MenuListProps={{
          "aria-labelledby": "attack-lab-button",
        }}
        PaperProps={{
          elevation: 3,
          sx: {
            mt: 1,
            "& .MuiMenuItem-root": {
              "&:hover": {
                backgroundColor: "rgba(144, 202, 249, 0.08)",
                transition: "all 0.2s ease",
              },
            },
          },
        }}
      >
        <MenuItem onClick={handleAttackLabMenuClose}><Link to="/llm-vulnerability-scanner">LLM Vulnerability Scanner</Link></MenuItem>
      </Menu>

      <Button
        color="inherit"
        onClick={handleRiskAssessmentClick}
        sx={{
          "&:hover": {
            backgroundColor: "rgba(255, 255, 255, 0.08)",
            transition: "all 0.3s ease",
          },
        }}
      >
        Risk Assessment Lab
      </Button>
      
      <Button
        color="inherit"
        onClick={handleThreatModelClick}
        sx={{
          "&:hover": {
            backgroundColor: "rgba(255, 255, 255, 0.08)",
            transition: "all 0.3s ease",
          },
        }}
      >
        Threat Model
      </Button>
    </>
  );

  // Mobile drawer content
  const mobileDrawer = (
    <Box onClick={handleDrawerToggle} sx={{ textAlign: "center" }}>
      <List>
        <ListItem disablePadding>
          <ListItemButton onClick={toggleInsightsLabMenu} sx={{ textAlign: "left" }}>
            <ListItemText primary="Reports & Insights Lab" />
            {insightsLabOpen ? <ExpandLessIcon /> : <ExpandMoreIcon />}
          </ListItemButton>
        </ListItem>
        <Collapse in={insightsLabOpen} timeout="auto" unmountOnExit>
          <List component="div" disablePadding>
            <ListItemButton sx={{ pl: 4 }}>
              <ListItemText primary="Insights Dashboard" />
            </ListItemButton>
            <ListItemButton sx={{ pl: 4 }}>
              <ListItemText primary="Analytics Reports" />
            </ListItemButton>
          </List>
        </Collapse>

        <ListItem disablePadding>
          <ListItemButton onClick={toggleAttackLabMenu} sx={{ textAlign: "left" }}>
            <ListItemText primary="AI Attack Lab" />
            {attackLabOpen ? <ExpandLessIcon /> : <ExpandMoreIcon />}
          </ListItemButton>
        </ListItem>
        <Collapse in={attackLabOpen} timeout="auto" unmountOnExit>
          <List component="div" disablePadding>
              <Link to="/llm-vulnerability-scanner" style={{ textDecoration: "none", color: "inherit" }}> 
                <ListItemButton sx={{ pl: 4 }}>
                  <ListItemText primary="LLM Vulnerability Scanner" />
                </ListItemButton>
              </Link>
          </List>
        </Collapse>

        <ListItem disablePadding>
          <Link to="/risk-assessment" style={{ textDecoration: "none", color: "inherit" }}>
            <ListItemButton 
              sx={{ textAlign: "left" }} 
              onClick={handleRiskAssessmentClick}
            >
              <ListItemText primary="Risk Assessment Lab" />
            </ListItemButton>
          </Link>
        </ListItem>

        <ListItem disablePadding>
          <Link to="/threat-model" style={{ textDecoration: "none", color: "inherit" }}>
            <ListItemButton 
              sx={{ textAlign: "left" }} 
              onClick={handleRiskAssessmentClick}
            >
              <ListItemText primary="Threat Model" />
            </ListItemButton>
          </Link>
        </ListItem>
      </List>
    </Box>
  );

  return (
    <>
      <AppBar position="static" color="transparent">
        <Toolbar>
          <Box
            component="div"
            sx={{
              flexGrow: 1,
              display: "flex",
              alignItems: "center",
            }}
          >
            <Box
              component={Link}
              to="/"
              sx={{
                fontWeight: 700,
                fontSize: "1.25rem",
                color: "primary.main",
                mr: 4,
                textDecoration: "none",
              }}
            >
              AI Tool Suite
            </Box>

            {isMobile ? (
              <IconButton
                color="inherit"
                aria-label="open drawer"
                edge="start"
                onClick={handleDrawerToggle}
                sx={{ ml: "auto" }}
              >
                <MenuIcon />
              </IconButton>
            ) : (
              <Box sx={{ display: "flex" }}>{desktopNavbar}</Box>
            )}
          </Box>
        </Toolbar>
      </AppBar>

      {/* Mobile Navigation Drawer */}
      <Drawer
        variant="temporary"
        open={mobileOpen}
        onClose={handleDrawerToggle}
        ModalProps={{
          keepMounted: true, // Better open performance on mobile
        }}
        sx={{
          display: { xs: "block", md: "none" },
          "& .MuiDrawer-paper": { boxSizing: "border-box", width: 280 },
        }}
      >
        {mobileDrawer}
      </Drawer>
    </>
  );
}