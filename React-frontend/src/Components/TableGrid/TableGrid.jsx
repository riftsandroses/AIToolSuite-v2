// import React, { useMemo, useState } from "react";

// import "ag-grid-community/styles/ag-theme-quartz.css"; // Optional Theme applied to the Data Grid
// import { Box } from '@mui/material';

// import classes from './tableGrid.module.css'

// import { AgGridReact } from 'ag-grid-react';
// import {
//     ClientSideRowModelModule,
//     ModuleRegistry,
//     TooltipModule,
//     ValidationModule,
//   } from "ag-grid-community";
  
//   ModuleRegistry.registerModules([
//     TooltipModule,
//     ClientSideRowModelModule,
//     ValidationModule /* Development Only */,
//   ]);


// const TableGrid = ({ data, cols }) => {

//     // const defaultColDef = (() => ({
//     //   // filter: true,
//     //   filter: "agTextColumnFilter",
//     //   // sortable: false,
//     //   floatingFilter: true,
//     //   // cellStyle: { borderRight: '1px solid #ccc' },
//     //   // tooltip: (params) => params.value, // enable tooltips for all columns
//     // }));

//     const defaultColDef = useMemo(() => {
//         return {
//             // filter: true,
//             sortable: true,
//             // floatingFilter: true,
//             cellStyle: { borderRight: '1px solid #ccc' },
//             tooltip: (params) => params.value, // enable tooltips for all columns
//         };
//     }, []);

//     return (
//         <Box
//             className={` ${classes.container} ag-theme-quartz`}
//         >
//             <AgGridReact
//                 rowData={data}
//                 columnDefs={cols}
//             defaultColDef={defaultColDef}
//             // pagination={true}
//             tooltipShowDelay={500}
//             // getRowStyle={(params) => rowStyle(params)}

//             />
//         </Box>
//     )
// }

// export default TableGrid

import React, { useMemo} from "react";
import { AgGridReact } from "ag-grid-react";
import {
  ClientSideRowModelModule,
  ModuleRegistry,
  TooltipModule,
  ValidationModule,
} from "ag-grid-community";

ModuleRegistry.registerModules([
  TooltipModule,
  ClientSideRowModelModule,
  ValidationModule /* Development Only */,
]);

const TableGrid = ({data,cols}) => {
    console.log(data)
    console.log(cols)
  const containerStyle = useMemo(() => ({ width: "100%", height: "100%" }), []);
  const gridStyle = useMemo(() => ({ height: "100%", width: "100%" }), []);


  const defaultColDef = useMemo(() => {
    return {
    //   flex: 1,
    //   minWidth: 100,
    };
  }, []);


 

  return (
    <div style={containerStyle}>
      <div style={gridStyle}>
        <AgGridReact
          rowData={data}
          columnDefs={cols}
          defaultColDef={defaultColDef}
          tooltipShowDelay={500}
        //   onGridReady={onGridReady}
        />
      </div>
    </div>
  );
};

export default TableGrid;