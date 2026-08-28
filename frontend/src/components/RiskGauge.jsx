import React from 'react';

const RiskGauge = ({ score = 0, size = 180, strokeWidth = 14, verdict = 'SAFE' }) => {
  const normalizedScore = Math.min(100, Math.max(0, score));
  const radius = (size - strokeWidth) / 2;
  const circumference = radius * 2 * Math.PI;
  // Arc angle (270 degrees total)
  const arcLength = circumference * 0.75;
  const strokeDashoffset = arcLength - (normalizedScore / 100) * arcLength;

  const getColor = (s) => {
    if (s >= 70) return { stroke: '#f43f5e', glow: 'rgba(244, 63, 94, 0.4)', text: 'text-rose-400' };
    if (s >= 38) return { stroke: '#f59e0b', glow: 'rgba(245, 158, 11, 0.4)', text: 'text-amber-400' };
    return { stroke: '#10b981', glow: 'rgba(16, 185, 129, 0.4)', text: 'text-emerald-400' };
  };

  const theme = getColor(normalizedScore);

  return (
    <div className="relative flex flex-col items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="transform -rotate-135">
        {/* Background Track */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="transparent"
          stroke="#1e293b"
          strokeWidth={strokeWidth}
          strokeDasharray={`${arcLength} ${circumference}`}
          strokeLinecap="round"
        />
        {/* Animated Active Score Arc */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="transparent"
          stroke={theme.stroke}
          strokeWidth={strokeWidth}
          strokeDasharray={`${arcLength} ${circumference}`}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          style={{
            filter: `drop-shadow(0 0 8px ${theme.glow})`,
            transition: 'stroke-dashoffset 1s cubic-bezier(0.4, 0, 0.2, 1), stroke 0.5s ease',
          }}
        />
      </svg>

      {/* Center Score Readout */}
      <div className="absolute flex flex-col items-center justify-center text-center">
        <span className={`text-4xl font-black tracking-tight ${theme.text}`}>
          {normalizedScore.toFixed(0)}
        </span>
        <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 mt-0.5">
          / 100 Risk
        </span>
        <span
          className={`text-[10px] font-bold uppercase tracking-widest px-2 py-0.5 mt-1 rounded-full ${
            normalizedScore >= 70
              ? 'bg-rose-500/20 text-rose-300'
              : normalizedScore >= 38
              ? 'bg-amber-500/20 text-amber-300'
              : 'bg-emerald-500/20 text-emerald-300'
          }`}
        >
          {verdict}
        </span>
      </div>
    </div>
  );
};

export default RiskGauge;
