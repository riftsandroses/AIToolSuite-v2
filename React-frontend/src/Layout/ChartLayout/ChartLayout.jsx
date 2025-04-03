import classes from "../ChartLayout/chartLayout.module.css";
import { Box } from "@mui/material";


const ChartLayout = ({
    children,
    title = "Title",
    subtitle = "",
}) => {
    return (
        <Box className={`${classes.parentContainer} shadow-lg`}>
            <Box className={`${classes.chartHeading}`}>
                <Box className={`${classes.chartTitle}`}>{title}</Box>
                {subtitle && <Box className={`${classes.chartSubtitle}`}>{subtitle}</Box>}
                {/* {dataSourceName && <Box className={`${classes.chartDataSourceName}`}>{dataSourceName}</Box>}
                {asset && <Box className={`${classes.chartAssets}`}>{asset}</Box>} */}
            </Box>
            <Box sx={{padding:"0.5rem 0.5rem"}}>
                {children}
            </Box>
        </Box>
    )
}

export default ChartLayout;