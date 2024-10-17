


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
        { data: 'energy_impact', title: 'Average Energy Impact' },
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
                    updateChartOptions(response.energy_impact);
                }
            },
            error: error
        });



    }

    function createDropdown(){
        var $dropdownMenu = $('#column-selector .menu');
        $dropdownMenu.empty(); // Clear any existing items

        allColumns.forEach(function(column, index) {
            var $item = $('<div class="item"></div>')
                .attr('data-value', index)
                .text(column.title);
            $dropdownMenu.append($item);
        });

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
        // var progressInterval = setInterval(function() {
        //     $('#update_progress').progress('increment');
        //     var currentValue = $('#update_progress').progress('get value');
        //     if (currentValue >= totalSteps) {
        //         $('#update_progress').progress('reset');
        //     }
        // }, BAR_INTERVAL);

    }

    function formatTime(epochTime) {
        var date = new Date(epochTime * 1000);
        return date.toLocaleTimeString();
    }

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
        var chartData = prepareChartData(dataObject);

        var option = {
            title: {
                text: 'Energy Impact Over Time'
            },
            tooltip: {
                trigger: 'axis'
            },
            xAxis: {
                type: 'category',
                data: chartData.times,
                name: 'Time',
                boundaryGap: false
            },
            yAxis: {
                type: 'value',
                name: 'Energy Impact Sum'
            },
            series: [{
                name: 'Energy Impact Sum',
                type: 'line',
                data: chartData.values,
                smooth: true
            }]
        };

        chart.setOption(option);
    }

    var chart = echarts.init(document.getElementById('main_chart'));

    createDropdown()

    setInterval(fetchData, UPDATE_TIME);
    setProgress()

    fetchData();
});
