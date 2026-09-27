import React, { useId } from 'react';

const LEVEL_COLORS = {
  SAFE: '#34d399',
  LOW: '#60a5fa',
  MEDIUM: '#fbbf24',
  HIGH: '#f97316',
  CRITICAL: '#fb7185',
};

const clampScore = (value) => {
  const numericValue = Number(value);
  if (!Number.isFinite(numericValue)) return 0;
  return Math.min(100, Math.max(0, numericValue));
};

export default function RiskGauge({ score = 0, level = 'SAFE', label = 'RISK SCORE' }) {
  const safeScore = clampScore(score);
  const normalized = safeScore / 100;
  const gradientId = useId().replace(/:/g, '');
  const radius = 80;
  const arcLength = Math.PI * radius;
  const dashLength = arcLength * normalized;
  const displayLevel = (level || 'SAFE').toString().toUpperCase();
  const accentColor = LEVEL_COLORS[displayLevel] || LEVEL_COLORS.SAFE;

  const tickValues = [0, 20, 40, 60, 80, 100];

  return (
    <div className="w-full max-w-xl mx-auto">
      <div className="text-center text-xs font-mono uppercase tracking-[0.28em] text-secondaryText mb-2">
        {label} | {displayLevel}
      </div>

      <svg viewBox="0 0 220 140" className="mx-auto block w-full max-w-[520px] h-auto">
        <defs>
          <linearGradient id={gradientId} x1="0%" x2="100%" y1="0%" y2="0%">
            <stop offset="0%" stopColor="#60a5fa" />
            <stop offset="35%" stopColor="#5aa5ff" />
            <stop offset="70%" stopColor="#fbbf24" />
            <stop offset="100%" stopColor="#fb7185" />
          </linearGradient>
        </defs>

        <path
          d="M 20 100 A 80 80 0 0 1 200 100"
          fill="none"
          stroke="#1f2e52"
          strokeWidth="18"
          strokeLinecap="round"
        />

        <path
          d="M 20 100 A 80 80 0 0 1 200 100"
          fill="none"
          stroke={`url(#${gradientId})`}
          strokeWidth="18"
          strokeLinecap="round"
          strokeDasharray={`${dashLength} ${arcLength}`}
        />

        {tickValues.map((tick) => {
          const percentage = tick / 100;
          const angle = percentage * Math.PI;
          const x1 = 100 + Math.cos(Math.PI - angle) * 80;
          const y1 = 100 - Math.sin(Math.PI - angle) * 80;
          const x2 = 100 + Math.cos(Math.PI - angle) * 92;
          const y2 = 100 - Math.sin(Math.PI - angle) * 92;
          const textX = 100 + Math.cos(Math.PI - angle) * 108;
          const textY = 100 - Math.sin(Math.PI - angle) * 108;

          return (
            <g key={tick}>
              <line x1={x1} y1={y1} x2={x2} y2={y2} stroke="rgba(255,255,255,0.55)" strokeWidth="1.2" />
              <text x={textX} y={textY + 5} textAnchor="middle" fill="rgba(255,255,255,0.7)" fontSize="10" fontFamily="ui-monospace, SFMono-Regular, monospace">
                {tick}
              </text>
            </g>
          );
        })}
      </svg>

      <div className="text-center -mt-9 pb-4">
        <div className="text-5xl font-light text-white leading-none tracking-tight">
          {safeScore}
          <span className="text-2xl text-secondaryText">/100</span>
        </div>
      </div>

      <div className="flex justify-center">
        <span
          className="inline-flex items-center px-3 py-1 rounded-full border text-[10px] font-bold uppercase tracking-[0.2em]"
          style={{
            borderColor: `${accentColor}66`,
            backgroundColor: `${accentColor}1a`,
            color: accentColor,
          }}
        >
          {displayLevel}
        </span>
      </div>
    </div>
  );
}
