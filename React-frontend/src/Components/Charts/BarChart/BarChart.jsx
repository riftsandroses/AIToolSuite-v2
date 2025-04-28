import ReactECharts from 'echarts-for-react';
import ChartLayout from '../../../Layout/ChartLayout/ChartLayout';

const BasicBarChart = ({ inputs }) => {
    const { xAxisData, yAxisName, xAxisName, SeriesData, colors } = inputs.data;

    const option = {
        xAxis: {
            type: 'category',
            data: xAxisData,
            name: xAxisName,
            nameLocation: 'middle',
            nameGap: 25,
            nameTextStyle: {
                color: '#333',
                fontSize: 12
            },
            axisLabel: {
                show: true,
                fontSize: 10,
                rotate: 0,
                interval: 0,
            },
        },
        yAxis: {
            type: 'value',
            name: yAxisName,
            nameLocation: 'middle',
            nameGap: 30,
            nameTextStyle: {
                color: '#333',
                fontSize: 12
            },
        },
        grid: {
            top:"3%",
            left: "6%",
            right: "4%",
            bottom: "6%",
            containLabel: true,
        },
        series: [
            {
                data: SeriesData,
                type: 'bar',
                itemStyle: {
                    color: (params) => {
                        return colors[params.dataIndex % colors.length];
                    }
                },
                label: {
                    show: true,
                    position: 'top',
                    fontSize: 12,
                    fontWeight: 'light',
                    formatter: '{c}',
                    color: 'black'
                }
            }
        ],
        tooltip: {
            trigger: 'item',
            formatter: "{b} : {c}"
        },
    };

    return (
        <ChartLayout
            title={inputs.title}
            subtitle={inputs.subtitle}
            dataSourceName={inputs.dataSourceName}
            asset={inputs.assets}>
            <ReactECharts option={option} />
        </ChartLayout>
    );
};

export default BasicBarChart;

const basicBarInputs = {
    title: "Top Risk Categories",
    subtitle: "Highlights the percentage distribution of risks across the risk categories",
    data: {
        xAxisData: ["Security", "Operation", "Compliance", "Finance", "Reputational"],
        xAxisName: "Risk Category",
        yAxisName: "Risk Percentage (%)",
        SeriesData: [85, 78, 80, 75, 70],
        colors: [
            "#492E87",
            "#a294c2",
            "#7662a5",
            "#bcb1d3",
            "#d9d3e6"
        ]
    }
};