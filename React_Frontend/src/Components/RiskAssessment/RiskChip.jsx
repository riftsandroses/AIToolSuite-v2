import { Chip, styled } from "@mui/material";

const RiskChip = styled(Chip)(({ theme, risklevel }) => {
  const colors = {
    High: {
      bg: "rgba(244, 67, 54, 0.1)",
      color: theme.palette.error.main,
    },
    Medium: {
      bg: "rgba(255, 152, 0, 0.1)",
      color: theme.palette.warning.main,
    },
    Low: {
      bg: "rgba(76, 175, 80, 0.1)",
      color: theme.palette.success.main,
    },
  };

  return {
    backgroundColor: colors[risklevel].bg,
    color: colors[risklevel].color,
    fontWeight: 500,
    fontSize: "0.75rem",
  };
});

export default RiskChip;