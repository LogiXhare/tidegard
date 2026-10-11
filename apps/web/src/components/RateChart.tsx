// A small line chart drawn as SVG, with no chart library and no inline
// style (the Content-Security-Policy forbids it). Two series, told apart by
// line pattern as well as colour (FR-10.2), each named in a legend.
import type { TrafficPoint } from "../api";

const WIDTH = 720;
const HEIGHT = 180;
const PAD = 28;

/** "1.2 Gbit/s", for an axis label or a reading. */
export function bitsPerSecond(value: number): string {
  const units = ["bit/s", "kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"];
  let scaled = value;
  let unit = 0;
  while (scaled >= 1000 && unit < units.length - 1) {
    scaled /= 1000;
    unit += 1;
  }
  return `${scaled.toFixed(scaled >= 100 || unit === 0 ? 0 : 1)} ${units[unit]}`;
}

export function RateChart({ points }: { points: TrafficPoint[] }) {
  if (points.length === 0) {
    return <p className="muted">No traffic recorded in the last hour.</p>;
  }
  const times = points.map((point) => Date.parse(point.time));
  const first = Math.min(...times);
  const span = Math.max(Math.max(...times) - first, 1);
  const peak = Math.max(1, ...points.map((point) => Math.max(point.ipv4_bps, point.ipv6_bps)));
  const x = (time: number) => PAD + ((time - first) / span) * (WIDTH - 2 * PAD);
  const y = (value: number) => HEIGHT - PAD - (value / peak) * (HEIGHT - 2 * PAD);
  const line = (pick: (point: TrafficPoint) => number) =>
    points.map((point, index) => `${x(times[index] ?? first)},${y(pick(point))}`).join(" ");

  return (
    <figure className="chart">
      <svg
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        role="img"
        aria-label={`Traffic over the last hour, peak ${bitsPerSecond(peak)}`}
      >
        <line x1={PAD} y1={HEIGHT - PAD} x2={WIDTH - PAD} y2={HEIGHT - PAD} className="axis" />
        <line x1={PAD} y1={PAD} x2={PAD} y2={HEIGHT - PAD} className="axis" />
        <text x={PAD + 4} y={PAD - 8} className="axis-label">
          {bitsPerSecond(peak)}
        </text>
        <polyline points={line((point) => point.ipv4_bps)} className="series ipv4" />
        <polyline points={line((point) => point.ipv6_bps)} className="series ipv6" />
      </svg>
      <figcaption>
        <span className="key ipv4">── IPv4</span> <span className="key ipv6">- - IPv6</span>
      </figcaption>
    </figure>
  );
}
