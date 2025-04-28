import React from 'react';
import ReactECharts from 'echarts-for-react';
import ChartLayout from '../../../Layout/ChartLayout/ChartLayout';

// import ReactEChartsCore from 'echarts-for-react/lib/core';
// // Import the echarts core module, which provides the necessary interfaces for using echarts.
// import * as echarts from 'echarts/core';

// import {
//     PieChart,
// } from 'echarts/charts';
// // import components, all suffixed with Component
// import {
//     // GridSimpleComponent,
//     GridComponent,
//     // PolarComponent,
//     // RadarComponent,
//     // GeoComponent,
//     // SingleAxisComponent,
//     // ParallelComponent,
//     // CalendarComponent,
//     // GraphicComponent,
//     // ToolboxComponent,
//     TooltipComponent,
//     // AxisPointerComponent,
//     // BrushComponent,
//     TitleComponent,
//     // TimelineComponent,
//     // MarkPointComponent,
//     // MarkLineComponent,
//     // MarkAreaComponent,
//     // LegendComponent,
//     // LegendScrollComponent,
//     // LegendPlainComponent,
//     // DataZoomComponent,
//     // DataZoomInsideComponent,
//     // DataZoomSliderComponent,
//     // VisualMapComponent,
//     // VisualMapContinuousComponent,
//     // VisualMapPiecewiseComponent,
//     // AriaComponent,
//     // TransformComponent,
// } from 'echarts/components';
// // Import renderer, note that introducing the CanvasRenderer or SVGRenderer is a required step
// import {
//     CanvasRenderer,
//     // SVGRenderer,
// } from 'echarts/renderers';

// // Register the required components
// echarts.use(
//     [TitleComponent, TooltipComponent, GridComponent, PieChart, CanvasRenderer]
// );





const PieChartComp = ({inputs = basicPieInputs}) => {

    const option = {
        tooltip: {
          trigger: 'item',
          formatter: "{a} <br/>{b}: {c} ({d}%)"
        },
        legend: {
          orient: inputs.data.legendOrientaion, // Make sure it's correctly spelled as "legendOrientation" if it's not working
          left: inputs.data.legendAlignment
        },
        
        series: [
          {
            name: inputs.data.dataName,
            type: 'pie',
            radius: '80%', 
            data: inputs.data.seriesData.map((item, index) => ({
              value: item.value,
              name: item.name,
              itemStyle: {
                color: item.color, // Assumes each item in seriesData has a color attribute
              }
            })),
            label: {
              show: true,
              position: 'inside', // Positioning the label inside the section
              formatter: '{c}', // Displaying only the value. Change to '{b}: {c}' to show names and values
              fontSize: 14,
              fontWeight: '400',
              color: 'white' // Choose a contrasting color for better visibility
            },
            labelLine: {
              show: false // Disabling the label line
            },
            emphasis: {
              label: {
                show: true,
                fontSize: 18, // Slightly larger font on mouse hover
                fontWeight: 'bold',
                color: 'white'
              },
              itemStyle: {
                shadowBlur: 10,
                shadowOffsetX: 0,
                shadowColor: 'rgba(1, 0, 0, 0.5)'
              }
            }
          }
        ]
      };

    return (
        <ChartLayout title={inputs.title} subtitle={inputs.subtitle}>
            <ReactECharts
                option={option}
                notMerge={true}
                lazyUpdate={true}
                // theme={"dark"}
            // onChartReady={this.onChartReadyCallback}
            // onEvents={EventsDict}
            // opts={ }
            />

            {/* <ReactEChartsCore
                echarts={echarts}
                option={option}
                notMerge={true}
                lazyUpdate={true}
                theme={"dark"}
                // onChartReady={this.onChartReadyCallback}
                // onEvents={EventsDict}
                // opts={ }
            /> */}
        </ChartLayout>
    )
}

export default PieChartComp

const basicPieInputs = {

    title: "Test Scan Azure",
    subtitle: "Client A",
    data: {
      legendOrientaion: "horizontal",
      legendAlignment: "center",
      dataName: "Severity",
      seriesData: [
        // { value: 17, name: 'High', color:"red" },
        { value: 17, name: 'High'},
        { value: 7, name: 'Medium'},
        { value: 8, name: 'Low' },
        // { value: 484, name: 'Union Ads' },
        // { value: 300, name: 'Video Ads' }
      ]
    }
  }
  