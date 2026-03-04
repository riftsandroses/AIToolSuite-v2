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
import { getAuthCookies, deleteAuthCookies } from "../api/auth";

export default function Navbar() {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));
  const navigate = useNavigate();

  // Auth state
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  // Desktop dropdown states
  const [insightsLabAnchorEl, setInsightsLabAnchorEl] = useState(null);
  const [attackLabAnchorEl, setAttackLabAnchorEl] = useState(null);
  const [windowLabAnchorEl, setWindowLabAnchorEl] = useState(null);
  const [userMenuAnchorEl, setUserMenuAnchorEl] = useState(null);

  // Mobile menu state
  const [mobileOpen, setMobileOpen] = useState(false);
  const [insightsLabOpen, setInsightsLabOpen] = useState(false);
  const [attackLabOpen, setAttackLabOpen] = useState(false);
  const [windowLabOpen, setWindowLabOpen] = useState(false);

  // Check authentication status
  useEffect(() => {
    const token = getAuthCookies().accessToken;
    setIsAuthenticated(!!token);
  }, []);

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

  const handleWindowLabMenuOpen = (event) => {
    setWindowLabAnchorEl(event.currentTarget);
  };

  const handleWindowLabMenuClose = () => {
    setWindowLabAnchorEl(null);
  };

  const handleUserMenuClose = () => {
    setUserMenuAnchorEl(null);
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

  const toggleWindowLabMenu = () => {
    setWindowLabOpen(!windowLabOpen);
  };

  // Navigation handlers
  const handleRiskAssessmentClick = () => {
    navigate("/risk-assessment");
    setMobileOpen(false);
  };

  const handleThreatModelClick = () => {
    navigate("/threat-model");
    setMobileOpen(false);
  };

  // **NEW**: Handler for API Pentest button
  const handleApiPentestClick = () => {
    navigate("/api-pentest");
    setMobileOpen(false);
  };

  const handleArchitectureAssessmentClick = () => {
    navigate("/architecture-assessment");
    setMobileOpen(false);
  };

  const handleLoginClick = () => {
    navigate("/login");
    setMobileOpen(false);
    handleUserMenuClose();
  };

  const handleLogoutClick = () => {
    deleteAuthCookies();
    setIsAuthenticated(false);
    window.location.href = "/";
    setMobileOpen(false);
    handleUserMenuClose();
  };

  const handleMenuItemClick = (callback) => {
    return () => {
      callback();
      setMobileOpen(false);
    };
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
          textTransform: "none",
          fontWeight: 500,
          fontSize: "0.95rem",
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
          elevation: 8,
          sx: {
            mt: 1.5,
            borderRadius: 2,
            minWidth: 200,
            "& .MuiMenuItem-root": {
              fontSize: "0.9rem",
              py: 1.5,
              "&:hover": {
                backgroundColor: "rgba(144, 202, 249, 0.12)",
                transition: "all 0.2s ease",
              },
            },
          },
        }}
      >
        <Link to="/llm-vulnerability-scanner-report" style={{ textDecoration: "none", color: "inherit" }}>
          <MenuItem onClick={handleInsightsLabMenuClose}>AI Attack Report</MenuItem>
        </Link>
      </Menu>

      <Button
        color="inherit"
        aria-controls="window-lab-menu"
        aria-haspopup="true"
        onClick={handleWindowLabMenuOpen}
        endIcon={<ExpandMoreIcon />}
        sx={{
          mr: 2,
          textTransform: "none",
          fontWeight: 500,
          fontSize: "0.95rem",
          "&:hover": {
            backgroundColor: "rgba(255, 255, 255, 0.08)",
            transition: "all 0.3s ease",
          },
        }}
      >
        Windows Attack Lab
      </Button>
      <Menu
        id="window-lab-menu"
        anchorEl={windowLabAnchorEl}
        keepMounted
        open={Boolean(windowLabAnchorEl)}
        onClose={handleWindowLabMenuClose}
        MenuListProps={{
          "aria-labelledby": "window-lab-button",
        }}
        PaperProps={{
          elevation: 8,
          sx: {
            mt: 1.5,
            borderRadius: 2,
            minWidth: 200,
            "& .MuiMenuItem-root": {
              fontSize: "0.9rem",
              py: 1.5,
              "&:hover": {
                backgroundColor: "rgba(144, 202, 249, 0.12)",
                transition: "all 0.2s ease",
              },
            },
          },
        }}
      >
        <Link to="/dll" style={{ textDecoration: "none", color: "inherit" }}>
          <MenuItem onClick={handleWindowLabMenuClose}>DLL Hijacker (AI Agent)</MenuItem>
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
          textTransform: "none",
          fontWeight: 500,
          fontSize: "0.95rem",
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
          elevation: 8,
          sx: {
            mt: 1.5,
            borderRadius: 2,
            minWidth: 200,
            "& .MuiMenuItem-root": {
              fontSize: "0.9rem",
              py: 1.5,
              "&:hover": {
                backgroundColor: "rgba(144, 202, 249, 0.12)",
                transition: "all 0.2s ease",
              },
            },
          },
        }}
      >
        <Link to="/llm-vulnerability-scanner" style={{ textDecoration: "none", color: "inherit" }}>
          <MenuItem onClick={handleAttackLabMenuClose}>AI Attack Tester</MenuItem>
        </Link>
      </Menu>

      <Button
        color="inherit"
        onClick={handleRiskAssessmentClick}
        sx={{
          mr: 2,
          textTransform: "none",
          fontWeight: 500,
          fontSize: "0.95rem",
          "&:hover": {
            backgroundColor: "rgba(255, 255, 255, 0.08)",
            transition: "all 0.3s ease",
          },
        }}
      >
        Architecture Risk Assessment Lab
      </Button>

      <Button
        color="inherit"
        onClick={handleThreatModelClick}
        sx={{
          mr: 2, // Changed from 3 to 2 for consistent spacing
          textTransform: "none",
          fontWeight: 500,
          fontSize: "0.95rem",
          "&:hover": {
            backgroundColor: "rgba(255, 255, 255, 0.08)",
            transition: "all 0.3s ease",
          },
        }}
      >
        Threat Model
      </Button>

      <Button
        color="inherit"
        onClick={handleArchitectureAssessmentClick}
        sx={{
          mr: 2,
          textTransform: "none",
          fontWeight: 500,
          fontSize: "0.95rem",
          "&:hover": {
            backgroundColor: "rgba(255, 255, 255, 0.08)",
            transition: "all 0.3s ease",
          },
        }}
      >
        Architecture Assessment
      </Button>

      {/* **NEW**: API Pentest Button */}
      <Button
        color="inherit"
        onClick={handleApiPentestClick}
        sx={{
          mr: 3,
          textTransform: "none",
          fontWeight: 500,
          fontSize: "0.95rem",
          "&:hover": {
            backgroundColor: "rgba(255, 255, 255, 0.08)",
            transition: "all 0.3s ease",
          },
        }}
      >
        API Pentest
      </Button>

      {/* User Menu */}
      {isAuthenticated ? (
        <Button
          color="inherit"
          onClick={handleLogoutClick}
          startIcon={<LoginIcon />}
          sx={{
            textTransform: "none",
            fontWeight: 500,
            fontSize: "0.95rem",
            px: 2,
            "&:hover": {
              backgroundColor: "rgba(255, 57, 57, 0.08)",
              borderColor: "rgba(255, 255, 255, 0.5)",
              transition: "all 0.3s ease",
              color: "rgba(255, 57, 57, 0.987)"
            },
          }}
        >
          Logout
        </Button>
      ) : (
        <Button
          color="inherit"
          onClick={handleLoginClick}
          startIcon={<LoginIcon />}
          sx={{
            textTransform: "none",
            fontWeight: 500,
            fontSize: "0.95rem",
            px: 2,
            "&:hover": {
              backgroundColor: "rgba(255, 255, 255, 0.08)",
              borderColor: "rgba(255, 255, 255, 0.5)",
              transition: "all 0.3s ease",
              color: "primary.main",
            },
          }}
        >
          Login
        </Button>
      )}
    </>
  );

  // Mobile drawer content
  const mobileDrawer = (
    <Box sx={{ width: 300, height: "100%" }}>
      {/* Drawer Header */}
      <Box sx={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        p: 2,
        borderBottom: "1px solid rgba(255, 255, 255, 0.12)"
      }}>
        <Typography variant="h6" sx={{ fontWeight: 600, color: "primary.main" }}>
          AI Security Suite
        </Typography>
        <IconButton onClick={handleDrawerToggle} sx={{ color: "text.secondary" }}>
          <CloseIcon />
        </IconButton>
      </Box>

      <List sx={{ pt: 1 }}>
        {/* Reports & Insights Lab */}
        <ListItem disablePadding>
          <ListItemButton
            onClick={toggleInsightsLabMenu}
            sx={{
              textAlign: "left",
              py: 1.5,
              "&:hover": {
                backgroundColor: "rgba(144, 202, 249, 0.08)",
              },
            }}
          >
            <ListItemText
              primary="Reports & Insights Lab"
              primaryTypographyProps={{ fontWeight: 500 }}
            />
            {insightsLabOpen ? <ExpandLessIcon /> : <ExpandMoreIcon />}
          </ListItemButton>
        </ListItem>
        <Collapse in={insightsLabOpen} timeout="auto" unmountOnExit>
          <List component="div" disablePadding>
            <Link to="/llm-vulnerability-scanner-report" style={{ textDecoration: "none", color: "inherit" }}>
              <ListItemButton
                sx={{
                  pl: 4,
                  py: 1,
                  "&:hover": {
                    backgroundColor: "rgba(144, 202, 249, 0.08)",
                  },
                }}
                onClick={handleMenuItemClick(() => { })}
              >
                <ListItemText
                  primary="AI Attack Report"
                  primaryTypographyProps={{ fontSize: "0.9rem" }}
                />
              </ListItemButton>
            </Link>
          </List>
        </Collapse>

        {/* Windows Attack Lab */}
        <ListItem disablePadding>
          <ListItemButton
            onClick={toggleWindowLabMenu}
            sx={{
              textAlign: "left",
              py: 1.5,
              "&:hover": {
                backgroundColor: "rgba(144, 202, 249, 0.08)",
              },
            }}
          >
            <ListItemText
              primary="Windows Attack Lab"
              primaryTypographyProps={{ fontWeight: 500 }}
            />
            {windowLabOpen ? <ExpandLessIcon /> : <ExpandMoreIcon />}
          </ListItemButton>
        </ListItem>
        <Collapse in={windowLabOpen} timeout="auto" unmountOnExit>
          <List component="div" disablePadding>
            <Link to="/dll" style={{ textDecoration: "none", color: "inherit" }}>
              <ListItemButton
                sx={{
                  pl: 4,
                  py: 1,
                  "&:hover": {
                    backgroundColor: "rgba(144, 202, 249, 0.08)",
                  },
                }}
                onClick={handleMenuItemClick(() => { })}
              >
                <ListItemText
                  primary="DLL Hijacker (AI Agent)"
                  primaryTypographyProps={{ fontSize: "0.9rem" }}
                />
              </ListItemButton>
            </Link>
          </List>
        </Collapse>

        {/* AI Attack Lab */}
        <ListItem disablePadding>
          <ListItemButton
            onClick={toggleAttackLabMenu}
            sx={{
              textAlign: "left",
              py: 1.5,
              "&:hover": {
                backgroundColor: "rgba(144, 202, 249, 0.08)",
              },
            }}
          >
            <ListItemText
              primary="AI Attack Lab"
              primaryTypographyProps={{ fontWeight: 500 }}
            />
            {attackLabOpen ? <ExpandLessIcon /> : <ExpandMoreIcon />}
          </ListItemButton>
        </ListItem>
        <Collapse in={attackLabOpen} timeout="auto" unmountOnExit>
          <List component="div" disablePadding>
            <Link to="/llm-vulnerability-scanner" style={{ textDecoration: "none", color: "inherit" }}>
              <ListItemButton
                sx={{
                  pl: 4,
                  py: 1,
                  "&:hover": {
                    backgroundColor: "rgba(144, 202, 249, 0.08)",
                  },
                }}
                onClick={handleMenuItemClick(() => { })}
              >
                <ListItemText
                  primary="AI Attack Tester"
                  primaryTypographyProps={{ fontSize: "0.9rem" }}
                />
              </ListItemButton>
            </Link>
          </List>
        </Collapse>

        {/* Risk Assessment Lab */}
        <ListItem disablePadding>
          <Link to="/risk-assessment" style={{ textDecoration: "none", color: "inherit" }}>
            <ListItemButton
              sx={{
                textAlign: "left",
                py: 1.5,
                "&:hover": {
                  backgroundColor: "rgba(144, 202, 249, 0.08)",
                },
              }}
              onClick={handleMenuItemClick(handleRiskAssessmentClick)}
            >
              <ListItemText
                primary="Risk Assessment Lab"
                primaryTypographyProps={{ fontWeight: 500 }}
              />
            </ListItemButton>
          </Link>
        </ListItem>

        {/* Threat Model */}
        <ListItem disablePadding>
          <Link to="/threat-model" style={{ textDecoration: "none", color: "inherit" }}>
            <ListItemButton
              sx={{
                textAlign: "left",
                py: 1.5,
                "&:hover": {
                  backgroundColor: "rgba(144, 202, 249, 0.08)",
                },
              }}
              onClick={handleMenuItemClick(handleThreatModelClick)}
            >
              <ListItemText
                primary="Threat Model"
                primaryTypographyProps={{ fontWeight: 500 }}
              />
            </ListItemButton>
          </Link>
        </ListItem>

        {/* Architecture Assessment */}
        <ListItem disablePadding>
          <Link to="/architecture-assessment" style={{ textDecoration: "none", color: "inherit" }}>
            <ListItemButton
              sx={{
                textAlign: "left",
                py: 1.5,
                "&:hover": {
                  backgroundColor: "rgba(144, 202, 249, 0.08)",
                },
              }}
              onClick={handleMenuItemClick(handleArchitectureAssessmentClick)}
            >
              <ListItemText
                primary="Architecture Assessment"
                primaryTypographyProps={{ fontWeight: 500 }}
              />
            </ListItemButton>
          </Link>
        </ListItem>

        {/* **NEW**: API Pentest Item */}
        <ListItem disablePadding>
          <Link to="/api-pentest" style={{ textDecoration: "none", color: "inherit" }}>
            <ListItemButton
              sx={{
                textAlign: "left",
                py: 1.5,
                "&:hover": {
                  backgroundColor: "rgba(144, 202, 249, 0.08)",
                },
              }}
              onClick={handleMenuItemClick(handleApiPentestClick)}
            >
              <ListItemText
                primary="API Pentest"
                primaryTypographyProps={{ fontWeight: 500 }}
              />
            </ListItemButton>
          </Link>
        </ListItem>

        <Divider sx={{ my: 2 }} />

        {/* Login/Logout */}
        {isAuthenticated ? (
          <ListItem disablePadding>
            <ListItemButton
              onClick={handleMenuItemClick(handleLogoutClick)}
              sx={{
                textAlign: "left",
                py: 1.5,
                "&:hover": {
                  backgroundColor: "rgba(244, 67, 54, 0.08)",
                },
              }}
            >
              <LogoutIcon sx={{ mr: 2, color: "error.main" }} />
              <ListItemText
                primary="Logout"
                primaryTypographyProps={{ fontWeight: 500, color: "error.main" }}
              />
            </ListItemButton>
          </ListItem>
        ) : (
          <ListItem disablePadding>
            <ListItemButton
              onClick={handleMenuItemClick(handleLoginClick)}
              sx={{
                textAlign: "left",
                py: 1.5,
                "&:hover": {
                  backgroundColor: "rgba(144, 202, 249, 0.08)",
                },
              }}
            >
              <LoginIcon sx={{ mr: 2, color: "primary.main" }} />
              <ListItemText
                primary="Login"
                primaryTypographyProps={{ fontWeight: 500, color: "primary.main" }}
              />
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
        sx={{
          borderBottom: "1px solid rgba(255, 255, 255, 0.12)",
          backdropFilter: "blur(10px)",
        }}
      >
        <Toolbar sx={{ px: { xs: 2, sm: 3 } }}>
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
                fontSize: "1.4rem",
                color: "primary.main",
                mr: 4,
                textDecoration: "none",
                "&:hover": {
                  opacity: 0.8,
                  transition: "opacity 0.3s ease",
                },
              }}
            >
              AI Security Suite
            </Box>

            {isMobile ? (
              <IconButton
                color="inherit"
                aria-label="open drawer"
                edge="start"
                onClick={handleDrawerToggle}
                sx={{
                  ml: "auto",
                  "&:hover": {
                    backgroundColor: "rgba(255, 255, 255, 0.08)",
                  },
                }}
              >
                <MenuIcon />
              </IconButton>
            ) : (
              <Box sx={{ display: "flex", alignItems: "center", ml: "auto" }}>
                {desktopNavbar}
              </Box>
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
          keepMounted: true,
        }}
        sx={{
          display: { xs: "block", md: "none" },
          "& .MuiDrawer-paper": {
            boxSizing: "border-box",
            width: 300,
            backgroundColor: "background.paper",
          },
        }}
      >
        {mobileDrawer}
      </Drawer>
    </>
  );
}