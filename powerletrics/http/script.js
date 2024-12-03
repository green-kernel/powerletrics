


$(document).ready(function() {

    const UPDATE_TIME = 5000
    const BAR_INTERVAL = 100;

    var allColumns = [
        { data: 'pid', title: 'PID' },
        { data: 'cpu_time_ns', title: 'CPU Time (ns)' },
        { data: 'cpu_wakeups', title: 'CPU Wakeups' },
        { data: 'memory_usage', title: 'Memory Usage (Bytes)' },
        { data: 'memory_usage_mb', title: 'Memory Usage (MB)' },
        { data: 'net_rx_packets', title: 'Network RX Packets' },
        { data: 'net_tx_packets', title: 'Network TX Packets' },
        { data: 'disk_read_bytes', title: 'Disk Read (Bytes)' },
        { data: 'disk_write_bytes', title: 'Disk Write (Bytes)' },
        { data: 'cpu_utilization', title: 'Average CPU Utilization (%)' },
        { data: 'energy_footprint', title: 'Average Energy Footprint' },
        { data: 'cmdline', title: 'Command Line' },
        { data: 'comm', title: 'Command' },
    ];

    var table = $('#datatable').DataTable({
        data: [],
        retrieve: true,
        columns: allColumns,
        columnDefs: [
        { targets: '_all', visible: false }
        ],
        colReorder: true
    });

    function error(xhr, status, error) {
        $.toast({
            title: 'Error fetching data',
            message: error,
            showProgress: 'bottom',
            classProgress: 'red'
          })
          ;
        console.error('Error fetching data:', error);
    }
    function fetchData() {
        $.ajax({
            url: '/get_table_data',
            type: 'GET',
            dataType: 'json',
            success: function(response) {
                if (response.length != 0){
                    createTable(response);
                }
            },
            error: error
        });
        $.ajax({
            url: '/get_timed_data',
            type: 'GET',
            dataType: 'json',
            success: function(response) {
                if (response.length != 0){
                    updateChartOptions(response);
                }
            },
            error: error
        });



    }

    function createDropdown(){
        $('#column-selector').dropdown({
            onChange: function(value, text, $selectedItem) {
                var selectedColumns = value ? value.split(',').map(Number) : [];
                table.columns().visible(false);
                selectedColumns.forEach(function(index) {
                    table.column(index).visible(true);
                });
                table.columns.adjust().draw(false);
            }
        });

        var defaultColumns = ['12', '10', '9', '2', '0'];

        allColumns.forEach(function(col, index) {
            col.visible = defaultColumns.includes(index.toString());
        });

        $('#column-selector').dropdown('set selected', defaultColumns);

        defaultColumns.map(Number).forEach(function(index) {
            table.column(index).visible(true);
        });
    }


    function createTable(table_data){

        // We need filter down the data somehow as otherwise the table becomes to large
        table_data = table_data.filter(item => item.energy_footprint !== 0.0);

        table.clear();
        table.rows.add(table_data);
        table.draw(); // Redraw the table to display the new data
        $('#table_laoding_loader').removeClass('active');
    }

    function setProgress(){

        const totalSteps = UPDATE_TIME / BAR_INTERVAL;

        $('#update_progress').progress({
            total: totalSteps,
        });
        var progressInterval = setInterval(function() {
            $('#update_progress').progress('increment');
            var currentValue = $('#update_progress').progress('get value');
            if (currentValue >= totalSteps) {
                $('#update_progress').progress('reset');
            }
        }, BAR_INTERVAL);

    }

    // Function to format epoch time to a readable format
    function formatTime(epochTime) {
        var date = new Date(epochTime * 1000); // Convert to milliseconds
        return date.toLocaleString(); // Customize the format as needed
    }

    // Function to prepare chart data for a single series
    function prepareChartData(dataObject) {
        // Create an array to hold the time-value pairs
        var dataArray = [];

        // Iterate over the dataObject keys
        for (var key in dataObject) {
            if (dataObject.hasOwnProperty(key)) {
                // Parse the key to a float (epoch time)
                var epochTime = parseFloat(key);
                var value = dataObject[key];

                dataArray.push({
                    epochTime: epochTime,
                    formattedTime: formatTime(epochTime),
                    value: value
                });
            }
        }

        // Sort the data by epochTime
        dataArray.sort(function(a, b) {
            return a.epochTime - b.epochTime;
        });

        // Extract times and values for the chart
        var times = dataArray.map(function(item) {
            return item.formattedTime;
        });

        var values = dataArray.map(function(item) {
            return item.value;
        });

        return { times: times, values: values };
    }

    function updateChartOptions(dataObject) {
        var series = [];
        var yAxes = [];
        var colorPalette = ['#5470C6', '#91CC75', '#EE6666', '#FAC858', '#73C0DE', '#3BA272', '#FC8452'];
        var colorIndex = 0;

        if (!dataObject.energy_footprint) {
            console.error("Missing 'energy_footprint' data.");
            return;
        }

        var energyData = prepareChartData(dataObject.energy_footprint);

        yAxes.push({
            type: 'value',
            name: 'Energy Footprint Sum',
            position: 'left',
            axisLine: {
                lineStyle: {
                    color: colorPalette[colorIndex]
                }
            },
        });

        series.push({
            name: 'Energy Footprint Sum',
            type: 'line',
            data: energyData.values,
            smooth: true,
            yAxisIndex: 0,
            color: colorPalette[colorIndex]
        });

        colorIndex++;

        // Iterate over other keys in dataObject to add optional series
        for (var key in dataObject) {
            if (dataObject.hasOwnProperty(key) && key !== 'energy_footprint') {
                var chartData = prepareChartData(dataObject[key]);

                yAxes.push({
                    type: 'value',
                    name: key,
                    position: 'right',
                    offset: (colorIndex - 1) * 60,
                    axisLine: {
                        lineStyle: {
                            color: colorPalette[colorIndex % colorPalette.length]
                        }
                    },
                });

                series.push({
                    name: key,
                    type: 'line',
                    data: chartData.values,
                    smooth: true,
                    yAxisIndex: yAxes.length - 1,
                    color: colorPalette[colorIndex % colorPalette.length]
                });

                colorIndex++;
            }
        }

        var option = {
            title: {
                text: 'Energy Footprint and Other Metrics Over Time'
            },
            toolbox: {
                show: true,
                feature: {
                  dataZoom: {
                    yAxisIndex: 'none'
                  },
                  dataView: { readOnly: false },
                  magicType: { type: ['line', 'bar'] },
                  restore: {},
                  saveAsImage: {}
                }
              },

            tooltip: {
                trigger: 'axis'
            },
            legend: {
                data: series.map(function(s) { return s.name; })
            },
            xAxis: {
                type: 'category',
                data: energyData.times,
                name: 'Time',
                boundaryGap: false
            },
            yAxis: yAxes,
            series: series,
            grid: {
                containLabel: true
            },
        };

        chart.setOption(option);
    }

    var chart = echarts.init(document.getElementById('main_chart'));

    createDropdown();

    setInterval(fetchData, UPDATE_TIME);

    // We don't do this as it uses quite a lot of CPU
    //setProgress();

    fetchData();
});
