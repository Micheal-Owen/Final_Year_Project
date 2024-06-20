// Set new default font family and font color to mimic Bootstrap's default styling
Chart.defaults.global.defaultFontFamily = 'Nunito', '-apple-system,system-ui,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif';
Chart.defaults.global.defaultFontColor = '#858796';

function number_format(number, decimals, dec_point, thousands_sep) {
  number = (number + '').replace(',', '').replace(' ', '');
  var n = !isFinite(+number) ? 0 : +number,
    prec = !isFinite(+decimals) ? 0 : Math.abs(decimals),
    sep = (typeof thousands_sep === 'undefined') ? ',' : thousands_sep,
    dec = (typeof dec_point === 'undefined') ? '.' : dec_point,
    s = '',
    toFixedFix = function(n, prec) {
      var k = Math.pow(10, prec);
      return '' + Math.round(n * k) / k;
    };
  s = (prec ? toFixedFix(n, prec) : '' + Math.round(n)).split('.');
  if (s[0].length > 3) {
    s[0] = s[0].replace(/\B(?=(?:\d{3})+(?!\d))/g, sep);
  }
  if ((s[1] || '').length < prec) {
    s[1] = s[1] || '';
    s[1] += new Array(prec - s[1].length + 1).join('0');
  }
  return s.join(dec);
}

// Function to create Area Chart
function createAreaChart(ctx) {
  return new Chart(ctx, {
    type: 'line',
    data: {
      labels: ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
      datasets: [{
        label: "Aggregated Probability",
        lineTension: 0.3,
        backgroundColor: "rgba(78, 115, 223, 0.05)",
        borderColor: "rgba(78, 115, 223, 1)",
        pointRadius: 3,
        pointBackgroundColor: "rgba(78, 115, 223, 1)",
        pointBorderColor: "rgba(78, 115, 223, 1)",
        pointHoverRadius: 3,
        pointHoverBackgroundColor: "rgba(78, 115, 223, 1)",
        pointHoverBorderColor: "rgba(78, 115, 223, 1)",
        pointHitRadius: 10,
        pointBorderWidth: 2,
        data: [0.1, 0.5, 0.3, 0.7, 0.2, 0.6, 0.4, 0.8, 0.3, 0.7, 0.5, 0.9],
      }],
    },
    options: {
      maintainAspectRatio: false,
      layout: {
        padding: {
          left: 10,
          right: 25,
          top: 25,
          bottom: 0
        }
      },
      scales: {
        xAxes: [{
          type: 'time',
          time: {
            unit: 'month'
          },
          gridLines: {
            display: false,
            drawBorder: false
          },
          ticks: {
            maxTicksLimit: 7
          }
        }],
        yAxes: [{
          ticks: {
            maxTicksLimit: 5,
            padding: 10,
            callback: function(value) {
              return number_format(value);
            }
          },
          gridLines: {
            color: "rgb(234, 236, 244)",
            zeroLineColor: "rgb(234, 236, 244)",
            drawBorder: false,
            borderDash: [2],
            zeroLineBorderDash: [2]
          }
        }],
      },
      legend: {
        display: false
      },
      tooltips: {
        backgroundColor: "rgb(255,255,255)",
        bodyFontColor: "#858796",
        titleMarginBottom: 10,
        titleFontColor: '#6e707e',
        titleFontSize: 14,
        borderColor: '#dddfeb',
        borderWidth: 1,
        xPadding: 15,
        yPadding: 15,
        displayColors: false,
        intersect: false,
        mode: 'index',
        caretPadding: 10,
      }
    }
  });
}

// Function to create Bar Chart
function createBarChart(ctx) {
  return new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
      datasets: [{
        label: "Benign Probability",
        backgroundColor: "rgba(78, 115, 223, 1)",
        hoverBackgroundColor: "rgba(78, 115, 223, 0.9)",
        borderColor: "#4e73df",
        data: [0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0, 0.9, 0.8, 0.7],
      }],
    },
    options: {
      maintainAspectRatio: false,
      layout: {
        padding: {
          left: 10,
          right: 25,
          top: 25,
          bottom: 0
        }
      },
      scales: {
        xAxes: [{
          type: 'time',
          time: {
            unit: 'month'
          },
          gridLines: {
            display: false,
            drawBorder: false
          },
          ticks: {
            maxTicksLimit: 10
          },
          maxBarThickness: 25,
        }],
        yAxes: [{
          ticks: {
            min: 0,
            max: 1,
            maxTicksLimit: 5,
            padding: 10,
            callback: function(value) {
              return number_format(value);
            }
          },
          gridLines: {
            color: "rgb(234, 236, 244)",
            zeroLineColor: "rgb(234, 236, 244)",
            drawBorder: false,
            borderDash: [2],
            zeroLineBorderDash: [2]
          }
        }],
      },
      legend: {
        display: false
      },
      tooltips: {
        backgroundColor: "rgb(255,255,255)",
        bodyFontColor: "#858796",
        titleMarginBottom: 10,
        titleFontColor: '#6e707e',
        titleFontSize: 14,
        borderColor: '#dddfeb',
        borderWidth: 1,
        xPadding: 15,
        yPadding: 15,
        displayColors: false,
        caretPadding: 10,
      },
    }
  });
}

// Function to create Pie Chart
function createPieChart(ctx) {
  return new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ["Benign", "FTP-BruteForce", "DDOS attack-HOIC", "DDOS attack-LOIC-UDP", "Brute Force -Web", "Brute Force -XSS", "SQL Injection"],
      datasets: [{
        data: [55, 30, 15, 20, 10, 5, 25],
        backgroundColor: ['#4e73df', '#1cc88a', '#36b9cc', '#f6c23e', '#e74a3b', '#858796', '#f8f9fc'],
        hoverBackgroundColor: ['#2e59d9', '#17a673', '#2c9faf', '#d4ac0d', '#d63031', '#6c757d', '#e8eaed'],
        hoverBorderColor: "rgba(234, 236, 244, 1)",
      }],
    },
    options: {
      maintainAspectRatio: false,
      tooltips: {
        backgroundColor: "rgb(255,255,255)",
        bodyFontColor: "#858796",
        borderColor: '#dddfeb',
        borderWidth: 1,
        xPadding: 15,
        yPadding: 15,
        displayColors: false,
        caretPadding: 10,
      },
      legend: {
        display: false
      },
      cutoutPercentage: 80,
    },
  });
}

// Function to update charts with new data
function updateCharts(areaChart, barChart, pieChart, data) {
  // Update Area Chart
  areaChart.data.labels = data.labels;
  areaChart.data.datasets[0].data = data.areaData;
  areaChart.update();

  // Update Bar Chart
  barChart.data.labels = data.labels;
  barChart.data.datasets[0].data = data.barData;
  barChart.update();

  // Update Pie Chart
  pieChart.data.labels = data.pieLabels;
  pieChart.data.datasets[0].data = data.pieData;
  pieChart.update();
}

// Function to fetch data from the API
function fetchData(areaChart, barChart, pieChart) {
  // For now, using dummy data
  let labels = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  let areaData = [0.1, 0.5, 0.3, 0.7, 0.2, 0.6, 0.4, 0.8, 0.3, 0.7, 0.5, 0.9];
  let barData = [0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0, 0.9, 0.8, 0.7];
  let pieLabels = ["Benign", "FTP-BruteForce", "DDOS attack-HOIC", "DDOS attack-LOIC-UDP", "Brute Force -Web", "Brute Force -XSS", "SQL Injection"];
  let pieData = [55, 30, 15, 20, 10, 5, 25];

  updateCharts(areaChart, barChart, pieChart, { labels, areaData, barData, pieLabels, pieData });

  // When ready, replace the dummy data with AJAX call
  // $.ajax({
  //   url: "{% url 'predictions' %}",
  //   method: "GET",
  //   success: function(response) {
  //     let labels = response.map(p => new Date(p.timestamp).toLocaleString());
  //     let areaData = response.map(p => p.probabilities.reduce((a, b) => a + b, 0));
  //     let barData = response.map(p => p.probabilities[0]); // Example of using one probability
  //     let pieLabels = ["Benign", "FTP-BruteForce", "DDOS attack-HOIC", "DDOS attack-LOIC-UDP", "Brute Force -Web", "Brute Force -XSS", "SQL Injection"];
  //     let pieData = pieLabels.map(label => response.filter(p => p.predicted_class === label).length);

  //     updateCharts(areaChart, barChart, pieChart, { labels, areaData, barData, pieLabels, pieData });
  //   }
  // });
}

$(document).ready(function() {
  // Initialize charts
  var ctxArea = document.getElementById("myAreaChart").getContext('2d');
  var ctxBar = document.getElementById("myBarChart").getContext('2d');
  var ctxPie = document.getElementById("myPieChart").getContext('2d');

  var areaChart = createAreaChart(ctxArea);
  var barChart = createBarChart(ctxBar);
  var pieChart = createPieChart(ctxPie);

  // Fetch data initially and then every 5 seconds
  fetchData(areaChart, barChart, pieChart);
  setInterval(function() {
    fetchData(areaChart, barChart, pieChart);
  }, 5000);
});
