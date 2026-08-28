import React from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
} from 'chart.js';
import { Bar } from 'react-chartjs-2';

ChartJS.register(CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend);

const ShapWaterfallChart = ({ featureImportances = [], baseValue = 0.15, predictionScore = 0.5 }) => {
  // Sort and take top contributing features
  const topFeatures = [...featureImportances]
    .sort((a, b) => Math.abs(b.shap_value) - Math.abs(a.shap_value))
    .slice(0, 8);

  const labels = topFeatures.map((f) => f.human_label);
  const values = topFeatures.map((f) => f.shap_value);

  const backgroundColors = values.map((val) =>
    val >= 0 ? 'rgba(244, 63, 94, 0.85)' : 'rgba(16, 185, 129, 0.85)'
  );

  const borderColors = values.map((val) =>
    val >= 0 ? '#f43f5e' : '#10b981'
  );

  const chartData = {
    labels,
    datasets: [
      {
        label: 'SHAP Impact (Contribution to Threat Score)',
        data: values,
        backgroundColor: backgroundColors,
        borderColor: borderColors,
        borderWidth: 1.5,
        borderRadius: 4,
      },
    ],
  };

  const chartOptions = {
    indexAxis: 'y',
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        display: false,
      },
      tooltip: {
        backgroundColor: '#0f172a',
        titleColor: '#f1f5f9',
        bodyColor: '#94a3b8',
        borderColor: '#334155',
        borderWidth: 1,
        padding: 12,
        callbacks: {
          label: function (context) {
            const val = context.raw;
            const sign = val > 0 ? '+' : '';
            return ` SHAP Value: ${sign}${val.toFixed(4)} (${val > 0 ? 'Elevates Risk' : 'Reduces Risk'})`;
          },
        },
      },
    },
    scales: {
      x: {
        grid: {
          color: 'rgba(51, 65, 85, 0.4)',
        },
        ticks: {
          color: '#94a3b8',
          callback: (value) => `${value > 0 ? '+' : ''}${value}`,
        },
      },
      y: {
        grid: {
          display: false,
        },
        ticks: {
          color: '#e2e8f0',
          font: {
            size: 11,
          },
        },
      },
    },
  };

  return (
    <div className="w-full">
      <div className="flex items-center justify-between mb-3 text-xs">
        <div className="flex items-center gap-4">
          <span className="flex items-center gap-1.5 text-slate-300">
            <span className="w-3 h-3 rounded-sm bg-rose-500"></span>
            Elevates Risk (+Threat)
          </span>
          <span className="flex items-center gap-1.5 text-slate-300">
            <span className="w-3 h-3 rounded-sm bg-emerald-500"></span>
            Safe Indicator (-Threat)
          </span>
        </div>
        <span className="font-mono text-slate-400">
          Base Model Prior: {(baseValue * 100).toFixed(1)}%
        </span>
      </div>

      <div className="h-64 w-full">
        <Bar data={chartData} options={chartOptions} />
      </div>
    </div>
  );
};

export default ShapWaterfallChart;
