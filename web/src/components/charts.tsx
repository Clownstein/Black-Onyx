import React from "react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Label,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

export type SeriesPoint = { label: string; value: number; [key: string]: string | number };

const tooltipStyle = {
  background: "var(--surface-raised)",
  border: "1px solid var(--border)",
  borderRadius: "6px",
  color: "var(--text)",
  fontSize: "12px",
};

export function TimeSeriesArea({
  data,
  color = "var(--accent)",
  onPointClick,
}: {
  data: SeriesPoint[];
  color?: string;
  onPointClick?: (point: SeriesPoint) => void;
}) {
  if (!data.length) return <p className="muted">No series data.</p>;
  return (
    <div className="chart-frame">
      <ResponsiveContainer width="100%" height={220}>
        <AreaChart
          data={data}
          style={onPointClick ? { cursor: "pointer" } : undefined}
          onClick={(state: any) => {
            const label = state?.activeLabel;
            if (!onPointClick || label == null) return;
            const point = data.find((d) => d.label === label);
            if (point) onPointClick(point);
          }}
        >
          <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
          <XAxis dataKey="label" stroke="var(--muted)" fontSize={11} />
          <YAxis stroke="var(--muted)" fontSize={11} allowDecimals={false} />
          <Tooltip contentStyle={tooltipStyle} />
          <Area type="monotone" dataKey="value" stroke={color} fill="var(--accent-soft)" strokeWidth={2} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

export function StackedBar({
  data,
  keys,
  colors,
  height = 220,
}: {
  data: SeriesPoint[];
  keys: string[];
  colors?: string[];
  height?: number;
}) {
  if (!data.length) return <p className="muted">No series data.</p>;
  const palette = colors || ["var(--accent)", "var(--accent-glow)", "#A9ADB6", "#2F3138", "#1A1A1F", "#0B0B0E"];
  return (
    <div className="chart-frame">
      <ResponsiveContainer width="100%" height={height}>
        <BarChart data={data}>
          <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
          <XAxis dataKey="label" stroke="var(--muted)" fontSize={11} />
          <YAxis stroke="var(--muted)" fontSize={11} allowDecimals={false} />
          <Tooltip contentStyle={tooltipStyle} />
          {keys.map((key, index) => (
            <Bar key={key} dataKey={key} stackId="a" fill={palette[index % palette.length]} />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export function Donut({
  data,
  onPointClick,
  colors,
  showLegend = false,
  showTotal = false,
}: {
  data: SeriesPoint[];
  onPointClick?: (point: SeriesPoint) => void;
  colors?: string[];
  showLegend?: boolean;
  showTotal?: boolean;
}) {
  if (!data.length) return <p className="muted">No distribution data.</p>;
  const palette = colors || ["var(--accent)", "var(--accent-glow)", "#A9ADB6", "#2F3138", "#1A1A1F", "#0B0B0E"];
  const total = data.reduce((sum, d) => sum + (Number(d.value) || 0), 0);
  return (
    <div className="chart-frame">
      <ResponsiveContainer width="100%" height={220}>
        <PieChart>
          <Tooltip contentStyle={tooltipStyle} />
          <Pie
            data={data}
            dataKey="value"
            nameKey="label"
            innerRadius={55}
            outerRadius={85}
            paddingAngle={2}
            style={onPointClick ? { cursor: "pointer" } : undefined}
            onClick={(_: unknown, index: number) => {
              if (onPointClick && data[index]) onPointClick(data[index]);
            }}
          >
            {data.map((entry, index) => (
              <Cell key={entry.label} fill={palette[index % palette.length]} />
            ))}
            {showTotal ? (
              <Label
                position="center"
                content={({ viewBox }) => {
                  const box = viewBox as { cx?: number; cy?: number } | undefined;
                  if (!box?.cx || !box?.cy) return null;
                  return (
                    <>
                      <text x={box.cx} y={box.cy - 4} textAnchor="middle" fontSize={26} fontWeight={650} fill="var(--text)">
                        {total}
                      </text>
                      <text x={box.cx} y={box.cy + 16} textAnchor="middle" fontSize={10} fill="var(--text-dim)">
                        total
                      </text>
                    </>
                  );
                }}
              />
            ) : null}
          </Pie>
        </PieChart>
      </ResponsiveContainer>
      {showLegend ? (
        <div className="chart-legend">
          {data.map((entry, index) => (
            <span key={entry.label}>
              <span className="swatch" style={{ background: palette[index % palette.length] }} />
              {entry.label} ({entry.value})
            </span>
          ))}
        </div>
      ) : null}
    </div>
  );
}

export function Sparkline({
  data,
  color = "var(--accent)",
  label,
}: {
  data: number[];
  color?: string;
  label?: string;
}) {
  const series = data.map((value, index) => ({ label: String(index), value }));
  if (!series.length) return <span className="muted">—</span>;
  return (
    <div className="sparkline" role={label ? "img" : undefined} aria-label={label}>
      <ResponsiveContainer width="100%" height={36}>
        <LineChart data={series}>
          <Line type="monotone" dataKey="value" stroke={color} strokeWidth={2} dot={false} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

export function HorizontalBars({
  data,
  onPointClick,
}: {
  data: SeriesPoint[];
  onPointClick?: (point: SeriesPoint) => void;
}) {
  if (!data.length) return <p className="muted">No distribution data.</p>;
  return (
    <div className="chart-frame">
      <ResponsiveContainer width="100%" height={Math.max(180, data.length * 28)}>
        <BarChart data={data} layout="vertical" margin={{ left: 24 }}>
          <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
          <XAxis type="number" stroke="var(--muted)" fontSize={11} allowDecimals={false} />
          <YAxis type="category" dataKey="label" stroke="var(--muted)" fontSize={11} width={90} />
          <Tooltip contentStyle={tooltipStyle} />
          <Bar
            dataKey="value"
            fill="var(--accent)"
            radius={[0, 4, 4, 0]}
            style={onPointClick ? { cursor: "pointer" } : undefined}
            onClick={(entry: any) => {
              if (!onPointClick) return;
              const label = String(entry?.label ?? entry?.payload?.label ?? "");
              const point = data.find((d) => d.label === label) || (entry?.payload as SeriesPoint);
              if (point?.label != null) onPointClick(point);
            }}
          />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

/** Hour (0–23) × weekday (0=Sun) intensity matrix for volume heatmaps. */
export function CalendarHeatmap({
  cells,
  onCellClick,
}: {
  cells: { weekday: number; hour: number; value: number }[];
  onCellClick?: (cell: { weekday: number; hour: number; value: number }) => void;
}) {
  const days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  const max = Math.max(1, ...cells.map((c) => c.value));
  const lookup = new Map(cells.map((c) => [`${c.weekday}-${c.hour}`, c.value]));
  return (
    <div className="calendar-heatmap" role="img" aria-label="Hour by weekday heatmap">
      <div className="calendar-heatmap-grid">
        <div className="calendar-heatmap-corner" />
        {Array.from({ length: 24 }, (_, hour) => (
          <div key={`h-${hour}`} className="calendar-heatmap-hour">{hour % 3 === 0 ? hour : ""}</div>
        ))}
        {days.map((day, weekday) => (
          <React.Fragment key={day}>
            <div className="calendar-heatmap-day">{day}</div>
            {Array.from({ length: 24 }, (_, hour) => {
              const value = lookup.get(`${weekday}-${hour}`) || 0;
              const alpha = value ? 0.12 + (value / max) * 0.88 : 0.04;
              return (
                <button
                  type="button"
                  key={`${weekday}-${hour}`}
                  className="calendar-heatmap-cell"
                  title={`${day} ${hour}:00 — ${value}`}
                  style={{ background: `color-mix(in srgb, var(--accent) ${Math.round(alpha * 100)}%, transparent)`, cursor: onCellClick ? "pointer" : "default" }}
                  onClick={() => onCellClick?.({ weekday, hour, value })}
                />
              );
            })}
          </React.Fragment>
        ))}
      </div>
    </div>
  );
}
