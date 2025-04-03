import React from "react";
import { Box, Card, Typography, Divider } from "@mui/material";
import classes from "./numberMetricCard.module.css";

//Icons
import ChairIcon from "@mui/icons-material/Chair";
import PersonAddIcon from "@mui/icons-material/PersonAdd";
import OtherHousesIcon from "@mui/icons-material/OtherHouses";
import BarChartIcon from "@mui/icons-material/BarChart";

const NumberMetricCard = ({inputs = data}) => {
  return (
    <>
     {/* <Box className={classes.cardContainer}> */}
        {inputs.map((data) => (
          <Card className={classes.card}>
            <Box className={classes.iconBox}>
              <Box
                fontSize="medium"
                className={classes.icon}
                backgroundColor={data.color}
                color="white"
              >
                {data.icon}
              </Box>
            </Box>
            <Box textAlign="right">
              <Typography variant="button" fontWeight="light" color="text" style={{fontSize:"0.8rem"}}>
                {data.title}
              </Typography>
              <Typography variant="h4">{data.count}</Typography>
            </Box>

            <Divider variant="middle" />
            <Box pt={1} px={2}>
              <Typography display="flex" fontWeight="light">
                <Typography fontWeight="light">{data.amount}</Typography>
                &nbsp;{data.label}
              </Typography>
            </Box>
          </Card>
        ))}
      {/* </Box> */}
      </>
     

  );
};

export default NumberMetricCard;

const data = [
    {
      title: "Robustness Evaluation",
      count: "115",
      amount: "+55% ",
      label: "than last week",
      color: "#40E0D0",
      icon: <ChairIcon />,
    },
    {
      title: "Adversarial Resilience",
      count: "30",
      amount: "+3%",
      label: "than last month",
      color: "#FF7F50",
      icon: <ChairIcon />,
    },
    {
      title: "Exploitation Resistance",
      count: "85%",
      amount: "+1%",
      label: "than yesterday",
      color: "#3A9E33",
      icon: <ChairIcon />,
    },
    {
      title: "Ethical Alignment",
      count: "140",
      amount: "+55% ",
      label: "than last week",
      color: "#E3316F",
      icon: <ChairIcon />,
    },
    {
      title: "Hallucination Rate",
      count: "40",
      amount: "+1%",
      label: "Than yesterday",
      color: "#343338",
      icon: <ChairIcon />,
    },
  
  ];
