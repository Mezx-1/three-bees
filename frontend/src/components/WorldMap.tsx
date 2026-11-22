"use client";

import { tr } from "@/lib/i18n";
import { geoNaturalEarth1, geoPath } from "d3-geo";
import { useMemo, useState } from "react";
import { feature } from "topojson-client";
import world from "world-atlas/countries-110m.json";

export type MapPoint = { lat: number; lon: number; city?: string | null; country?: string | null; count: number; max_risk: number };

const W = 900;
const H = 440;

export function WorldMap({ points }: { points: MapPoint[] }) {
  const [hover, setHover] = useState<MapPoint | null>(null);
  const { paths, project } = useMemo(() => {
    const geo: any = feature(world as any, (world as any).objects.countries);
    const projection = geoNaturalEarth1().fitSize([W, H], geo);
    const path = geoPath(projection);
    return { paths: geo.features.map((f: any, i: number) => <path key={i} d={path(f) || ""} />), project: projection };
  }, []);
  const max = Math.max(1, ...points.map((p) => p.count));
  return (
    <div className="relative">
      <svg viewBox={`0 0 ${W} ${H}`} className="h-auto w-full" role="img" aria-label={tr("Map of where this device's connections go")}>
        <g fill="#e8edf3" stroke="#ffffff" strokeWidth={0.6}>{paths}</g>
        {points.map((p, i) => {
          const xy = project([p.lon, p.lat]);
          if (!xy) return null;
          const r = 4 + 10 * Math.sqrt(p.count / max);
          const color = p.max_risk >= 60 ? "#d92d20" : p.max_risk >= 30 ? "#dc6803" : "#a15c07";
          return (
            <g key={i} onMouseEnter={() => setHover(p)} onMouseLeave={() => setHover(null)} className="cursor-pointer">
              <circle cx={xy[0]} cy={xy[1]} r={r} fill={color} fillOpacity={0.25} stroke={color} strokeWidth={1.5} />
              <circle cx={xy[0]} cy={xy[1]} r={2.2} fill={color} />
            </g>
          );
        })}
      </svg>
      {hover && (
        <div className="pointer-events-none absolute start-3 top-3 rounded-lg border border-ink-700 bg-ink-900 px-3 py-2 text-xs shadow-sm">
          <div className="font-medium text-ink-100">{[hover.city, hover.country].filter(Boolean).join(", ") || tr("Unknown place")}</div>
          <div className="text-ink-400">{hover.count} {tr("connection(s)")}</div>
        </div>
      )}
    </div>
  );
}
