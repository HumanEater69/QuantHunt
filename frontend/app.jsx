const { useState, useEffect, useRef, useMemo } = React;
const RCH = window.Recharts || {};
const Radar = RCH.Radar || (() => null);
const RadarChart = RCH.RadarChart || ((props) => <div>{props.children}</div>);
const PolarGrid = RCH.PolarGrid || (() => null);
const PolarAngleAxis = RCH.PolarAngleAxis || (() => null);
const ResponsiveContainer =
  RCH.ResponsiveContainer ||
  ((props) => (
    <div style={{ width: "100%", height: props.height || 280 }}>
      {props.children}
    </div>
  ));
const BarChart = RCH.BarChart || ((props) => <div>{props.children}</div>);
const Bar = RCH.Bar || ((props) => <div>{props.children}</div>);
const AreaChart = RCH.AreaChart || ((props) => <div>{props.children}</div>);
const Area = RCH.Area || ((props) => <div>{props.children}</div>);
const CartesianGrid = RCH.CartesianGrid || (() => null);
const XAxis = RCH.XAxis || (() => null);
const YAxis = RCH.YAxis || (() => null);
const Tooltip = RCH.Tooltip || (() => null);
const Cell = RCH.Cell || (() => null);

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1"]);
const sanitizeApiBase = (value) => String(value || "").trim().replace(/\/+$/, "");
const resolveApiBase = () => {
  try {
    const queryApi = sanitizeApiBase(
      new URLSearchParams(window.location.search).get("api"),
    );
    if (queryApi) {
      window.localStorage.setItem("qh_api_base", queryApi);
      return queryApi;
    }
    const savedApi = sanitizeApiBase(window.localStorage.getItem("qh_api_base"));
    if (savedApi) return savedApi;
  } catch {
    // Ignore storage/query failures and fall back to default local behavior.
  }
  return LOCAL_HOSTS.has(window.location.hostname) ? "" : "";
};
const API = resolveApiBase();

const SCAN_MODELS = ["general", "banking"];
const normalizeScanModel = (value) =>
  SCAN_MODELS.includes(String(value || "").toLowerCase())
    ? String(value).toLowerCase()
    : "general";
const scanModelParam = (scanModel) =>
  `scan_model=${encodeURIComponent(normalizeScanModel(scanModel))}`;
const normalizeDomain = (value) =>
  String(value || "")
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/\/+$/, "");
const isBankingDomainName = (domain) => {
  const host = normalizeDomain(domain);
  return host === "bank.in" || host.endsWith(".bank.in");
};
const effectiveScanModelForDomain = (domain, _selectedScanModel) =>
  isBankingDomainName(domain) ? "banking" : "general";
const scanModelUiLabel = (scanModel) =>
  normalizeScanModel(scanModel) === "banking" ? "BANKING" : "NON-BANK";
const domainBelongsToMode = (domain, scanModel) => {
  const banking = isBankingDomainName(domain);
  return normalizeScanModel(scanModel) === "banking" ? banking : !banking;
};
const filterRowsByMode = (
  rows,
  scanModel,
  domainGetter = (row) => row?.domain,
) =>
  (rows || []).filter((row) =>
    domainBelongsToMode(domainGetter(row), scanModel),
  );

const rawFetch = window.fetch.bind(window);
window.fetch = async (...args) => {
  const response = await rawFetch(...args);
  if (response.status === 403) {
    const body = await response
      .clone()
      .json()
      .catch(() => null);
    const detail =
      typeof body?.detail === "string"
        ? body.detail
        : "Access blocked: disable VPN/Proxy and retry.";
    const isVpnBlocked =
      body?.code === "VPN_BLOCKED" || /vpn|proxy/i.test(detail);
    if (isVpnBlocked) {
      alert(detail);
    }
  }
  return response;
};

const HAS_RECHARTS = Boolean(
  window.Recharts &&
  window.Recharts.BarChart &&
  window.Recharts.AreaChart &&
  window.Recharts.RadarChart,
);
const THEMES = {
  light: {
    mode: "light",
    bg: "#efe4cd",
    card: "#f4ead8",
    blue: "#c6a04b",
    cyan: "#d4b87a",
    orange: "#b88b33",
    red: "#8f4150",
    green: "#2f7f58",
    yellow: "#c6a04b",
    text: "#2c3428",
    dim: "#6d6c55",
    border: "rgba(116,103,63,0.3)",
  },
  dark: {
    mode: "dark",
    bg: "#121c17",
    card: "#1a2a22",
    blue: "#d6b66a",
    cyan: "#e5cc8f",
    orange: "#d2af59",
    red: "#b66f7b",
    green: "#7cc49a",
    yellow: "#d9c178",
    text: "#e5eddc",
    dim: "#aeb69e",
    border: "rgba(171,153,101,0.35)",
  },
};
const C = { ...THEMES.light };

function applyTheme(mode) {
  Object.assign(C, THEMES[mode] || THEMES.light);
}

const riskColor = (s) =>
  s > 75
    ? C.red
    : s > 55
      ? C.orange
      : s > 35
        ? C.yellow
        : s > 15
          ? C.cyan
          : C.green;
const isDarkTheme = () => C.mode === "dark";
const statusColor = {
  CRITICAL: C.red,
  HIGH_RISK: C.orange,
  TRANSITIONING: C.yellow,
  PQC_READY: C.cyan,
  QUANTUM_SAFE: C.green,
  WARNING: C.yellow,
  ACCEPTABLE: C.cyan,
  SAFE: C.green,
};

const BANK_PRESETS = [
  { bank: "Template A", domain: "example.com", region: "GLOBAL" },
  { bank: "Template B", domain: "example.org", region: "GLOBAL" },
  { bank: "Template C", domain: "example.net", region: "GLOBAL" },
  { bank: "Template D", domain: "api.example.com", region: "GLOBAL" },
  { bank: "Template E", domain: "secure.example.com", region: "GLOBAL" },
  { bank: "Template F", domain: "gateway.example.org", region: "GLOBAL" },
  { bank: "Template G", domain: "portal.example.net", region: "GLOBAL" },
  { bank: "Template H", domain: "www.example.com", region: "GLOBAL" },
  { bank: "Template I", domain: "status.example.org", region: "GLOBAL" },
  { bank: "Template J", domain: "auth.example.net", region: "GLOBAL" },
];

const BANK_DEMO_ROWS = [
  {
    scan_id: "demo-1",
    domain: "example.com",
    asset_count: 11,
    avg_risk: 39,
    safe_score: 24,
    risk_score: 64,
  },
  {
    scan_id: "demo-2",
    domain: "example.org",
    asset_count: 10,
    avg_risk: 55,
    safe_score: 36,
    risk_score: 83,
  },
  {
    scan_id: "demo-3",
    domain: "example.net",
    asset_count: 12,
    avg_risk: 51,
    safe_score: 34,
    risk_score: 80,
  },
  {
    scan_id: "demo-4",
    domain: "api.example.com",
    asset_count: 10,
    avg_risk: 44,
    safe_score: 29,
    risk_score: 71,
  },
  {
    scan_id: "demo-5",
    domain: "secure.example.com",
    asset_count: 11,
    avg_risk: 43,
    safe_score: 28,
    risk_score: 69,
  },
  {
    scan_id: "demo-6",
    domain: "gateway.example.org",
    asset_count: 9,
    avg_risk: 46,
    safe_score: 31,
    risk_score: 74,
  },
  {
    scan_id: "demo-7",
    domain: "portal.example.net",
    asset_count: 9,
    avg_risk: 52,
    safe_score: 35,
    risk_score: 81,
  },
  {
    scan_id: "demo-8",
    domain: "www.example.com",
    asset_count: 9,
    avg_risk: 50,
    safe_score: 33,
    risk_score: 78,
  },
  {
    scan_id: "demo-9",
    domain: "status.example.org",
    asset_count: 8,
    avg_risk: 48,
    safe_score: 32,
    risk_score: 76,
  },
  {
    scan_id: "demo-10",
    domain: "auth.example.net",
    asset_count: 8,
    avg_risk: 42,
    safe_score: 27,
    risk_score: 68,
  },
];

const BANK_REQUIREMENTS = {
  "example.com": [
    "Harden internet-facing TLS policies and disable weak fallback ciphers.",
    "Run weekly cert-expiry and signature hygiene checks.",
    "Prioritize high-risk assets tied to authentication paths.",
  ],
  "example.org": [
    "Reduce high-risk endpoints by enforcing strict transport headers and key lifecycle controls.",
    "Patch legacy crypto dependencies in public-facing services first.",
    "Establish monthly risk-drift review against baseline scans.",
  ],
  "example.net": [
    "Focus on largest exposed asset clusters and rotate weak certificate chains.",
    "Increase scan cadence for critical APIs.",
    "Apply staged remediation with proof-of-fix rescans.",
  ],
};

const getBankLabel = (domain) =>
  BANK_PRESETS.find((b) => b.domain === domain)?.bank || domain;
const securityScore = (avgRisk) => Math.max(0, 100 - Number(avgRisk || 0));

const uniqueCompletedScansByDomain = (scanRows) => {
  return uniqueLatestByDomain(
    (scanRows || []).filter((scan) => scan?.status === "completed"),
    "domain",
    "updated_at",
  );
};

const uniqueLatestLeaderboardByDomain = (rows) => {
  const sorted = [...(rows || [])].sort((a, b) => {
    const da = new Date(a?.created_at || 0).getTime();
    const db = new Date(b?.created_at || 0).getTime();
    return db - da;
  });
  const seen = new Set();
  const out = [];
  for (const row of sorted) {
    const key = String(row?.domain || "")
      .trim()
      .toLowerCase();
    if (!key || seen.has(key)) continue;
    seen.add(key);
    out.push(row);
  }
  return out;
};

const uniqueLatestByDomain = (
  rows,
  domainKey = "domain",
  timeKey = "created_at",
) => {
  const sorted = [...(rows || [])].sort((a, b) => {
    const da = new Date(a?.[timeKey] || 0).getTime();
    const db = new Date(b?.[timeKey] || 0).getTime();
    return db - da;
  });
  const seen = new Set();
  const out = [];
  for (const row of sorted) {
    const key = String(row?.[domainKey] || "")
      .trim()
      .toLowerCase();
    if (!key || seen.has(key)) continue;
    seen.add(key);
    out.push(row);
  }
  return out;
};

function RadarFallback({ data = [], color = C.cyan }) {
  const compact = typeof window !== "undefined" && window.innerWidth < 560;
  const size = compact ? 244 : 292;
  const center = size / 2;
  const outer = compact ? 88 : 108;
  const safeData = (data || []).filter((d) => d && d.axis);
  const steps = 5;
  const count = safeData.length || 1;
  const labels = safeData.map((d) => String(d.axis));
  const angleFor = (idx) => ((Math.PI * 2) / count) * idx - Math.PI / 2;
  const pointAt = (idx, value, radius = outer) => {
    const ang = angleFor(idx);
    const r = (Math.max(0, Math.min(100, Number(value || 0))) / 100) * radius;
    return {
      x: center + Math.cos(ang) * r,
      y: center + Math.sin(ang) * r,
    };
  };
  const polyPoints = safeData
    .map((d, i) => {
      const p = pointAt(i, d.value);
      return `${p.x.toFixed(2)},${p.y.toFixed(2)}`;
    })
    .join(" ");

  return (
    <div style={{ display: "grid", gap: 10, justifyItems: "center" }}>
      <svg
        width={size}
        height={size}
        viewBox={`0 0 ${size} ${size}`}
        role="img"
        aria-label="Crypto readiness radar"
        style={{ maxWidth: "100%", height: "auto" }}
      >
        <defs>
          <radialGradient id="qhRadarGlow" cx="50%" cy="50%" r="55%">
            <stop offset="0%" stopColor={`${color}66`} />
            <stop offset="100%" stopColor={`${color}0A`} />
          </radialGradient>
          <linearGradient id="qhRadarFill" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor={`${color}66`} />
            <stop offset="100%" stopColor={`${color}1E`} />
          </linearGradient>
        </defs>
        <circle
          cx={center}
          cy={center}
          r={outer + 10}
          fill="url(#qhRadarGlow)"
        />
        {Array.from({ length: steps }).map((_, idx) => {
          const ringR = ((idx + 1) / steps) * outer;
          const ring = labels
            .map((_, i) => {
              const p = pointAt(i, 100, ringR);
              return `${p.x.toFixed(2)},${p.y.toFixed(2)}`;
            })
            .join(" ");
          return (
            <polygon
              key={`ring-${idx}`}
              points={ring}
              fill="none"
              stroke="rgba(127,158,191,0.28)"
              strokeWidth="1"
            />
          );
        })}
        {labels.map((lbl, i) => {
          const end = pointAt(i, 100, outer + 4);
          return (
            <g key={`axis-${lbl}`}>
              <line
                x1={center}
                y1={center}
                x2={end.x}
                y2={end.y}
                stroke="rgba(110,136,168,0.34)"
                strokeWidth="1"
              />
              <text
                x={pointAt(i, 100, outer + 24).x}
                y={pointAt(i, 100, outer + 24).y}
                textAnchor="middle"
                dominantBaseline="middle"
                fill={C.dim}
                style={{
                  fontFamily: "JetBrains Mono",
                  fontSize: compact ? 9 : 10,
                }}
              >
                {lbl}
              </text>
            </g>
          );
        })}
        <polygon
          points={polyPoints}
          fill="url(#qhRadarFill)"
          stroke={color}
          strokeWidth="2"
        />
        {safeData.map((d, i) => {
          const p = pointAt(i, d.value);
          return (
            <g key={`dot-${d.axis}`}>
              <circle cx={p.x} cy={p.y} r="4" fill={color} />
              <circle
                cx={p.x}
                cy={p.y}
                r="8"
                fill="none"
                stroke={`${color}66`}
                strokeWidth="1"
              />
            </g>
          );
        })}
      </svg>
      <div style={{ color: C.dim, fontFamily: "JetBrains Mono", fontSize: 10 }}>
        Radar view (0-100): further out means stronger cryptographic readiness.
      </div>
    </div>
  );
}

function RiskTrendFallback({ data = [] }) {
  const rows = (data || []).filter(
    (d) =>
      d && d.domain && Number.isFinite(Number(d.avg_score ?? d.avg_risk ?? 0)),
  );
  if (!rows.length) {
    return (
      <div style={{ color: C.dim, fontFamily: "JetBrains Mono", fontSize: 12 }}>
        No risk trend data available yet.
      </div>
    );
  }
  const w = 860;
  const h = 240;
  const padX = 32;
  const padY = 24;
  const usableW = w - padX * 2;
  const usableH = h - padY * 2;
  const points = rows.map((r, idx) => {
    const x = padX + (idx / Math.max(1, rows.length - 1)) * usableW;
    const v = Number(r.avg_score ?? r.avg_risk ?? 0);
    const y = padY + ((100 - Math.max(0, Math.min(100, v))) / 100) * usableH;
    return { x, y, label: r.domain, value: v };
  });
  const linePath = points
    .map((p, i) => `${i === 0 ? "M" : "L"}${p.x.toFixed(2)},${p.y.toFixed(2)}`)
    .join(" ");
  const areaPath = `${linePath} L ${padX + usableW} ${padY + usableH} L ${padX} ${padY + usableH} Z`;
  return (
    <div style={{ overflowX: "auto" }}>
      <svg
        width="100%"
        height="250"
        viewBox={`0 0 ${w} ${h}`}
        preserveAspectRatio="xMidYMid meet"
      >
        <defs>
          <linearGradient id="riskFallbackArea" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={`${C.blue}77`} />
            <stop offset="100%" stopColor={`${C.blue}10`} />
          </linearGradient>
        </defs>
        <rect
          x="0"
          y="0"
          width={w}
          height={h}
          rx="12"
          fill={
            isDarkTheme() ? "rgba(16,35,61,0.55)" : "rgba(233,240,250,0.65)"
          }
        />
        {[0, 25, 50, 75, 100].map((tick) => {
          const y = padY + ((100 - tick) / 100) * usableH;
          return (
            <line
              key={`grid-${tick}`}
              x1={padX}
              x2={padX + usableW}
              y1={y}
              y2={y}
              stroke="rgba(106,129,161,0.22)"
              strokeDasharray="3 4"
            />
          );
        })}
        <path d={areaPath} fill="url(#riskFallbackArea)" />
        <path
          d={linePath}
          fill="none"
          stroke={C.blue}
          strokeWidth="2.4"
          strokeLinecap="round"
        />
        {points.map((p) => (
          <g key={p.label}>
            <circle cx={p.x} cy={p.y} r="3.3" fill={riskColor(p.value)} />
            <text
              x={p.x}
              y={padY + usableH + 13}
              textAnchor="middle"
              fill={C.dim}
              style={{ fontFamily: "JetBrains Mono", fontSize: 9 }}
            >
              {p.label.length > 12 ? `${p.label.slice(0, 12)}...` : p.label}
            </text>
          </g>
        ))}
      </svg>
      <div
        style={{
          color: C.dim,
          fontFamily: "JetBrains Mono",
          fontSize: 10,
          marginTop: 6,
        }}
      >
        Fallback visual active: showing risk trend image for all banks/domains.
      </div>
    </div>
  );
}

function ParticleField() {
  const ref = useRef(null);
  useEffect(() => {
    const c = ref.current;
    const x = c.getContext("2d");
    const setSize = () => {
      c.width = innerWidth;
      c.height = innerHeight;
    };
    setSize();
    const pts = Array.from({ length: 80 }, () => ({
      x: Math.random() * c.width,
      y: Math.random() * c.height,
      vx: (Math.random() - 0.5) * 0.35,
      vy: (Math.random() - 0.5) * 0.35,
      r: Math.random() * 1.4 + 0.2,
    }));
    let id;
    const draw = () => {
      x.clearRect(0, 0, c.width, c.height);
      for (const p of pts) {
        p.x += p.vx;
        p.y += p.vy;
        if (p.x < 0) p.x = c.width;
        if (p.x > c.width) p.x = 0;
        if (p.y < 0) p.y = c.height;
        if (p.y > c.height) p.y = 0;
        x.beginPath();
        x.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        x.fillStyle = "rgba(132,170,208,0.6)";
        x.fill();
      }
      id = requestAnimationFrame(draw);
    };
    draw();
    addEventListener("resize", setSize);
    return () => {
      cancelAnimationFrame(id);
      removeEventListener("resize", setSize);
    };
  }, []);
  return (
    <canvas
      ref={ref}
      style={{ position: "fixed", inset: 0, zIndex: 0, pointerEvents: "none" }}
    />
  );
}

function Logo({ size = 46, animated = true, lockTheme = false, clay = false }) {
  const gid = useRef(`g1_${Math.random().toString(36).slice(2, 9)}`);
  const clayId = useRef(`g2_${Math.random().toString(36).slice(2, 9)}`);
  const dark = isDarkTheme();
  const primary = clay
    ? dark
      ? "#d6b66a"
      : "#a77d1f"
    : lockTheme
      ? dark
        ? "#b9cae0"
        : "#5f728c"
      : C.blue;
  const accent = clay
    ? dark
      ? "#8fc1a8"
      : "#2f7f58"
    : lockTheme
      ? dark
        ? "#9fb4ce"
        : "#6d819d"
      : C.orange;
  const shellFill = lockTheme
    ? dark
      ? "rgba(168,187,214,0.15)"
      : "rgba(116,138,166,0.14)"
    : clay
      ? dark
        ? "rgba(179,148,85,0.28)"
        : "rgba(191,158,92,0.22)"
      : dark
        ? "rgba(122,149,184,0.16)"
        : "rgba(127,154,188,0.14)";
  const orbitA = clay
    ? dark
      ? "rgba(219,188,118,0.46)"
      : "rgba(182,146,72,0.36)"
    : lockTheme
      ? "rgba(120,141,168,0.34)"
      : "rgba(132,170,208,0.4)";
  const orbitB = clay
    ? dark
      ? "rgba(151,201,176,0.34)"
      : "rgba(75,146,112,0.3)"
    : lockTheme
      ? "rgba(102,124,151,0.28)"
      : "rgba(152,186,224,0.34)";
  const shadowFilter = lockTheme
    ? "none"
    : clay
      ? dark
        ? "drop-shadow(0 3px 8px rgba(11,9,5,0.45))"
        : "drop-shadow(0 3px 8px rgba(163,137,81,0.38))"
      : dark
        ? "drop-shadow(0 2px 7px rgba(6,12,20,0.4))"
        : "drop-shadow(0 2px 7px rgba(145,160,180,0.36))";
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      style={{
        filter: shadowFilter,
        animation: animated ? "logoBreath 4.5s ease-in-out infinite" : "none",
        transformOrigin: "50% 50%",
      }}
    >
      <defs>
        <linearGradient id={gid.current} x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor={primary} />
          <stop offset="100%" stopColor={accent} />
        </linearGradient>
        <radialGradient id={clayId.current} cx="34%" cy="26%" r="72%">
          <stop
            offset="0%"
            stopColor={dark ? "rgba(255,246,220,0.6)" : "rgba(255,248,230,0.9)"}
          />
          <stop
            offset="100%"
            stopColor={dark ? "rgba(97,80,43,0.6)" : "rgba(186,159,98,0.62)"}
          />
        </radialGradient>
      </defs>
      <circle
        cx="32"
        cy="32"
        r="24"
        fill={
          clay
            ? `url(#${clayId.current})`
            : dark
              ? "rgba(32,44,62,0.3)"
              : "rgba(233,238,246,0.66)"
        }
      />
      {clay && <circle cx="25" cy="21" r="8" fill="rgba(255,255,255,0.2)" />}
      <path
        d="M32 4 L54 14 L54 36 Q54 52 32 60 Q10 52 10 36 L10 14 Z"
        fill={shellFill}
        stroke={`url(#${gid.current})`}
        strokeWidth="2"
      />
      <circle
        cx="32"
        cy="32"
        r="6"
        fill="none"
        stroke={primary}
        strokeWidth="1.5"
      />
      <path d="M20 28 H44 M20 36 H44" stroke={accent} strokeWidth="1.2" />
      <ellipse
        cx="32"
        cy="32"
        rx="16"
        ry="6"
        fill="none"
        stroke={orbitA}
        strokeWidth="1"
      >
        {animated && !lockTheme && (
          <animateTransform
            attributeName="transform"
            type="rotate"
            from="0 32 32"
            to="360 32 32"
            dur="6s"
            repeatCount="indefinite"
          />
        )}
      </ellipse>
      <ellipse
        cx="32"
        cy="32"
        rx="16"
        ry="6"
        fill="none"
        stroke={orbitB}
        strokeWidth="1"
      >
        {animated && !lockTheme && (
          <animateTransform
            attributeName="transform"
            type="rotate"
            from="360 32 32"
            to="0 32 32"
            dur="4.2s"
            repeatCount="indefinite"
          />
        )}
      </ellipse>
      <circle cx="46" cy="32" r="1.8" fill={primary}>
        {animated && (
          <animate
            attributeName="opacity"
            values="0.3;1;0.3"
            dur="1.2s"
            repeatCount="indefinite"
          />
        )}
      </circle>
      {clay && animated && (
        <animateTransform
          attributeName="transform"
          type="rotate"
          from="0 32 32"
          to="360 32 32"
          dur="11s"
          repeatCount="indefinite"
        />
      )}
      <animate
        attributeName="opacity"
        values={animated ? "0.94;1;0.94" : "1"}
        dur="3.2s"
        repeatCount="indefinite"
      />
      <style>{`@keyframes logoBreath{0%,100%{transform:translateY(0) scale(1)}50%{transform:translateY(-1px) scale(1.012)}}`}</style>
    </svg>
  );
}

function MatrixRain({ opacity = 0.42, zIndex = 0 }) {
  const ref = useRef(null);
  useEffect(() => {
    const canvas = ref.current;
    const ctx = canvas.getContext("2d");
    const chars = "01ABCDEFHJKMNPQRTUVWXYZ";
    let cols = 0;
    let drops = [];

    const resize = () => {
      canvas.width = innerWidth;
      canvas.height = innerHeight;
      cols = Math.floor(canvas.width / 14);
      drops = Array.from({ length: cols }, () =>
        Math.floor(Math.random() * 20),
      );
    };
    resize();

    let frame;
    const draw = () => {
      ctx.fillStyle = "rgba(2, 8, 14, 0.16)";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.font = "12px JetBrains Mono, monospace";
      for (let i = 0; i < cols; i += 1) {
        const txt = chars[Math.floor(Math.random() * chars.length)];
        const x = i * 14;
        const y = drops[i] * 14;
        ctx.fillStyle =
          i % 4 === 0 ? "rgba(141,181,220,0.6)" : "rgba(132,170,208,0.45)";
        ctx.fillText(txt, x, y);
        if (y > canvas.height && Math.random() > 0.98) drops[i] = 0;
        drops[i] += 1;
      }
      frame = requestAnimationFrame(draw);
    };
    draw();
    addEventListener("resize", resize);
    return () => {
      cancelAnimationFrame(frame);
      removeEventListener("resize", resize);
    };
  }, []);
  return (
    <canvas
      ref={ref}
      style={{
        position: "absolute",
        inset: 0,
        pointerEvents: "none",
        zIndex,
        opacity,
      }}
    />
  );
}

function FingerprintUnlock({ active, progress }) {
  const color = active ? C.cyan : C.dim;
  return (
    <div style={{ margin: "0 auto", width: 132 }}>
      <svg
        viewBox="0 0 120 120"
        width="120"
        height="120"
        style={{
          filter: `drop-shadow(0 0 14px ${active ? "rgba(141,181,220,0.55)" : "rgba(132,170,208,0.2)"})`,
        }}
      >
        <circle
          cx="60"
          cy="60"
          r="54"
          fill="none"
          stroke="rgba(141,181,220,0.2)"
          strokeWidth="1.2"
        />
        <path
          d="M30 74c0-20 12-34 30-34s30 14 30 34"
          fill="none"
          stroke={color}
          strokeWidth="2.2"
          strokeLinecap="round"
        />
        <path
          d="M37 74c0-15 9-26 23-26s23 11 23 26"
          fill="none"
          stroke={color}
          strokeWidth="2"
          strokeLinecap="round"
        />
        <path
          d="M44 74c0-10 6-17 16-17s16 7 16 17"
          fill="none"
          stroke={color}
          strokeWidth="2"
          strokeLinecap="round"
        />
        <path
          d="M30 78c0 18 12 32 30 32s30-14 30-32"
          fill="none"
          stroke={color}
          strokeWidth="2.2"
          strokeLinecap="round"
        />
        <path
          d="M38 78c0 13 9 24 22 24s22-11 22-24"
          fill="none"
          stroke={color}
          strokeWidth="2"
          strokeLinecap="round"
        />
        <path
          d="M46 78c0 9 6 16 14 16s14-7 14-16"
          fill="none"
          stroke={color}
          strokeWidth="2"
          strokeLinecap="round"
        />
        <rect
          x="18"
          y={18 + (100 - progress) * 0.84}
          width="84"
          height="8"
          rx="4"
          fill="rgba(141,181,220,0.35)"
          style={{ transition: "y 0.08s linear" }}
        />
      </svg>
      <div
        style={{
          fontFamily: "JetBrains Mono",
          fontSize: 10,
          letterSpacing: 1.5,
          color,
          textAlign: "center",
        }}
      >
        {active ? `FINGERPRINT VERIFY ${progress}%` : "FINGERPRINT IDLE"}
      </div>
    </div>
  );
}

function TrendSpark({ label, color, values }) {
  const h = 36;
  const w = 130;
  const dark = isDarkTheme();
  const max = Math.max(...values, 1);
  const gid = useRef(`trend_grad_${Math.random().toString(36).slice(2, 9)}`);
  const points = values.map((v, i) => {
    const x = (i / (values.length - 1 || 1)) * w;
    const y = h - (v / max) * (h - 4);
    return { x, y };
  });
  const linePath = points
    .map(
      (p, idx) =>
        `${idx === 0 ? "M" : "L"} ${p.x.toFixed(2)} ${p.y.toFixed(2)}`,
    )
    .join(" ");
  const areaPath = `${linePath} L ${w} ${h} L 0 ${h} Z`;
  return (
    <div
      style={{
        padding: "8px 10px",
        borderRadius: 12,
        background: dark
          ? "linear-gradient(155deg, #142543, #0f1f39)"
          : "linear-gradient(155deg, #eef3fb, #e3ebf8)",
        border: `1px solid ${dark ? `${color}66` : `${color}33`}`,
        boxShadow: dark
          ? "inset 0 0 10px rgba(152,186,224,0.12)"
          : "inset 2px 2px 5px rgba(168,184,206,0.3), inset -2px -2px 5px rgba(255,255,255,0.85)",
      }}
    >
      <div
        style={{
          fontFamily: "JetBrains Mono",
          color,
          fontSize: 10,
          letterSpacing: 1,
        }}
      >
        {label}
      </div>
      <svg
        width={w}
        height={h}
        viewBox={`0 0 ${w} ${h}`}
        style={{ marginTop: 4 }}
      >
        <defs>
          <linearGradient id={gid.current} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={`${color}AA`} />
            <stop offset="100%" stopColor={`${color}10`} />
          </linearGradient>
        </defs>
        <path d={areaPath} fill={`url(#${gid.current})`} />
        <path
          d={linePath}
          fill="none"
          stroke={color}
          strokeWidth="2.2"
          strokeLinecap="round"
        />
      </svg>
    </div>
  );
}

function ClayBankAnalysisGraph({ selectedRow, lineUp }) {
  const dark = isDarkTheme();
  if (!selectedRow) return null;

  const selectedRisk = Number(selectedRow.avg_risk || 0);
  const selectedSecurity = Number(securityScore(selectedRisk).toFixed(1));
  const peers = (lineUp || []).filter((x) => x.domain !== selectedRow.domain);

  const average = (list, key, fallback = 0) => {
    if (!list.length) return fallback;
    const total = list.reduce((sum, item) => sum + Number(item[key] || 0), 0);
    return total / list.length;
  };

  const peerRisk = average(peers, "risk", selectedRisk);
  const peerSecurity = average(peers, "security", selectedSecurity);
  const maxAssetCount = Math.max(
    1,
    ...(lineUp || []).map((x) => Number(x.asset_count || 0)),
    Number(selectedRow.asset_count || 0),
  );
  const assetLoad =
    (Number(selectedRow.asset_count || 0) / maxAssetCount) * 100;
  const peerAssetLoad =
    (average(peers, "asset_count", Number(selectedRow.asset_count || 0)) /
      maxAssetCount) *
    100;
  const controlStability = Math.max(
    0,
    Math.min(100, 100 - Math.abs(selectedRisk - peerRisk) * 1.35),
  );

  const metrics = [
    {
      id: "security",
      label: "Security posture",
      value: selectedSecurity,
      peer: peerSecurity,
      color: C.green,
    },
    {
      id: "risk",
      label: "Risk pressure",
      value: selectedRisk,
      peer: peerRisk,
      color: C.red,
    },
    {
      id: "assets",
      label: "Asset exposure",
      value: assetLoad,
      peer: peerAssetLoad,
      color: C.blue,
    },
    {
      id: "stability",
      label: "Control stability",
      value: controlStability,
      peer: 72,
      color: C.cyan,
    },
  ];

  const clamp = (v) => Math.max(2, Math.min(100, Number(v || 0)));
  const selectedName = getBankLabel(selectedRow.domain);

  return (
    <Card style={{ padding: 18 }}>
      <div
        style={{
          color: C.blue,
          fontFamily: "Orbitron",
          fontSize: 12,
          letterSpacing: 1.2,
          marginBottom: 5,
        }}
      >
        <PressureText glow={C.blue}>BANK GRAPHICAL ANALYSIS</PressureText>
      </div>
      <div
        style={{
          color: C.dim,
          fontFamily: "JetBrains Mono",
          fontSize: 10,
          marginBottom: 11,
        }}
      >
        Claymorphic bars for {selectedName}. Vertical marker = peer baseline.
      </div>
      <div style={{ display: "grid", gap: 10 }}>
        {metrics.map((m) => (
          <div
            key={m.id}
            style={{
              display: "grid",
              gridTemplateColumns: "130px 1fr 52px",
              gap: 10,
              alignItems: "center",
            }}
          >
            <div
              style={{
                color: C.dim,
                fontFamily: "JetBrains Mono",
                fontSize: 10,
              }}
            >
              {m.label}
            </div>
            <div
              style={{
                position: "relative",
                height: 24,
                borderRadius: 999,
                overflow: "hidden",
                background: dark
                  ? "linear-gradient(155deg, #11233e, #0b182b)"
                  : "linear-gradient(155deg, #dfe8f5, #f7fbff)",
                boxShadow: dark
                  ? "inset 5px 5px 12px rgba(2,8,16,0.84), inset -4px -4px 9px rgba(67,104,150,0.25)"
                  : "inset 5px 5px 11px rgba(163,180,203,0.5), inset -5px -5px 11px rgba(255,255,255,0.92)",
              }}
            >
              <div
                style={{
                  position: "absolute",
                  left: 3,
                  top: 3,
                  bottom: 3,
                  width: `${clamp(m.value)}%`,
                  borderRadius: 999,
                  background: dark
                    ? `linear-gradient(145deg, ${m.color}, ${m.color}99)`
                    : `linear-gradient(145deg, ${m.color}cc, ${m.color}88)`,
                  boxShadow: dark
                    ? "4px 4px 9px rgba(2,8,16,0.75), -2px -2px 7px rgba(130,176,230,0.2), inset 0 1px 0 rgba(255,255,255,0.22)"
                    : "4px 4px 9px rgba(168,184,206,0.36), -3px -3px 8px rgba(255,255,255,0.82), inset 0 1px 0 rgba(255,255,255,0.75)",
                  transition: "width 300ms ease",
                }}
              />
              <div
                style={{
                  position: "absolute",
                  left: `calc(${clamp(m.peer)}% - 1px)`,
                  top: 4,
                  bottom: 4,
                  width: 2,
                  borderRadius: 2,
                  background: dark
                    ? "rgba(230,244,255,0.85)"
                    : "rgba(53,80,116,0.75)",
                  boxShadow: dark ? "0 0 8px rgba(152,186,224,0.35)" : "none",
                }}
              />
            </div>
            <div style={{ textAlign: "right" }}>
              <ClayNumber
                value={Number(m.value).toFixed(1)}
                tone={m.color}
                size={10}
                minWidth={50}
              />
            </div>
          </div>
        ))}
      </div>
      <div
        style={{
          marginTop: 12,
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit,minmax(165px,1fr))",
          gap: 8,
        }}
      >
        <div
          style={{
            borderRadius: 12,
            padding: "8px 10px",
            color: C.dim,
            fontFamily: "JetBrains Mono",
            fontSize: 10,
            background: dark ? "rgba(14,30,52,0.68)" : "rgba(233,238,244,0.76)",
            boxShadow: dark
              ? "inset 0 0 10px rgba(152,186,224,0.08)"
              : "inset 2px 2px 6px rgba(167,183,206,0.34), inset -2px -2px 6px rgba(238,243,248,0.74)",
          }}
        >
          Peer risk avg:{" "}
          <ClayNumber
            value={peerRisk.toFixed(1)}
            tone={C.red}
            size={10}
            minWidth={48}
            style={{ marginLeft: 6 }}
          />
        </div>
        <div
          style={{
            borderRadius: 12,
            padding: "8px 10px",
            color: C.dim,
            fontFamily: "JetBrains Mono",
            fontSize: 10,
            background: dark ? "rgba(14,30,52,0.68)" : "rgba(233,238,244,0.76)",
            boxShadow: dark
              ? "inset 0 0 10px rgba(152,186,224,0.08)"
              : "inset 2px 2px 6px rgba(167,183,206,0.34), inset -2px -2px 6px rgba(238,243,248,0.74)",
          }}
        >
          Selected assets:{" "}
          <ClayNumber
            value={selectedRow.asset_count ?? 0}
            tone={C.blue}
            size={10}
            minWidth={48}
            style={{ marginLeft: 6 }}
          />
        </div>
      </div>
    </Card>
  );
}

function BlockchainMeshOverlay({ opacity = 0.22, zIndex = 1 }) {
  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        zIndex,
        pointerEvents: "none",
        opacity,
        background:
          "radial-gradient(circle at 12% 16%, rgba(141,181,220,0.09), transparent 35%), radial-gradient(circle at 88% 70%, rgba(185,152,112,0.08), transparent 34%), repeating-linear-gradient(0deg, rgba(132,170,208,0.07) 0px, rgba(132,170,208,0.07) 1px, transparent 1px, transparent 34px), repeating-linear-gradient(90deg, rgba(141,181,220,0.06) 0px, rgba(141,181,220,0.06) 1px, transparent 1px, transparent 34px)",
      }}
    />
  );
}

function CyanPulseVeil({ zIndex = 1 }) {
  return (
    <>
      <div
        style={{
          position: "fixed",
          inset: 0,
          zIndex,
          pointerEvents: "none",
          background:
            "radial-gradient(circle at 18% 24%, rgba(141,181,220,0.13), transparent 34%), radial-gradient(circle at 78% 70%, rgba(132,170,208,0.12), transparent 36%), radial-gradient(circle at 50% 8%, rgba(141,181,220,0.08), transparent 26%)",
          animation: "cyanPulse 8s ease-in-out infinite",
        }}
      />
      <style>{`@keyframes cyanPulse{0%,100%{opacity:.6}50%{opacity:1}}`}</style>
    </>
  );
}

function CyborgCore({ active, progress }) {
  return (
    <div
      style={{
        position: "relative",
        width: 150,
        height: 150,
        display: "grid",
        placeItems: "center",
      }}
    >
      <div
        style={{
          position: "absolute",
          inset: 0,
          borderRadius: "50%",
          border: "1px solid rgba(141,181,220,0.35)",
          boxShadow: "0 0 24px rgba(141,181,220,0.25)",
          animation: "coreSpin 8s linear infinite",
        }}
      />
      <div
        style={{
          position: "absolute",
          width: 108,
          height: 108,
          borderRadius: "50%",
          border: "1px dashed rgba(132,170,208,0.45)",
          animation: "coreSpinRev 5s linear infinite",
        }}
      />
      <svg
        width="112"
        height="112"
        viewBox="0 0 112 112"
        style={{ filter: "drop-shadow(0 0 16px rgba(141,181,220,0.45))" }}
      >
        <circle
          cx="56"
          cy="56"
          r="42"
          fill="rgba(141,181,220,0.06)"
          stroke="rgba(141,181,220,0.55)"
          strokeWidth="1.5"
        />
        <circle
          cx="56"
          cy="56"
          r="26"
          fill="none"
          stroke="rgba(132,170,208,0.7)"
          strokeWidth="2"
        />
        <circle
          cx="56"
          cy="56"
          r="8"
          fill={active ? "rgba(141,181,220,0.9)" : "rgba(132,170,208,0.8)"}
        />
        <path
          d="M18 56 H94 M56 18 V94"
          stroke="rgba(132,170,208,0.6)"
          strokeWidth="1.2"
        />
        <rect
          x="16"
          y={16 + (100 - progress) * 0.8}
          width="80"
          height="6"
          rx="3"
          fill="rgba(141,181,220,0.35)"
        />
      </svg>
    </div>
  );
}

const LOCK_CODE_XOR = [17, 23, 31, 11, 13, 19];
const LOCK_CODE_ENC = [64, 95, 45, 59, 63, 37];
const LOCK_ACCESS_CODE = LOCK_CODE_ENC.map((n, i) =>
  String.fromCharCode(n ^ LOCK_CODE_XOR[i]),
).join("");

function CursorTrail({ turbo = false }) {
  const [pos, setPos] = useState({ x: 0, y: 0 });
  const targetRef = useRef({ x: 0, y: 0 });
  const dark = isDarkTheme();

  useEffect(() => {
    const start = { x: innerWidth * 0.5, y: innerHeight * 0.4 };
    targetRef.current = start;
    setPos(start);
  }, []);

  useEffect(() => {
    let raf = 0;
    const onMove = (e) => {
      targetRef.current = { x: e.clientX, y: e.clientY };
    };
    const onTouch = (e) => {
      const t = e.touches && e.touches[0];
      if (!t) return;
      targetRef.current = { x: t.clientX, y: t.clientY };
    };

    const tick = () => {
      const ease = turbo ? 0.5 : 0.38;
      setPos((p) => ({
        x: p.x + (targetRef.current.x - p.x) * ease,
        y: p.y + (targetRef.current.y - p.y) * ease,
      }));
      raf = requestAnimationFrame(tick);
    };

    addEventListener("mousemove", onMove);
    addEventListener("touchmove", onTouch, { passive: true });
    raf = requestAnimationFrame(tick);
    return () => {
      cancelAnimationFrame(raf);
      removeEventListener("mousemove", onMove);
      removeEventListener("touchmove", onTouch);
    };
  }, [turbo]);

  return (
    <div
      style={{ position: "fixed", inset: 0, pointerEvents: "none", zIndex: 40 }}
    >
      <div
        style={{
          position: "absolute",
          left: pos.x - 10,
          top: pos.y - 10,
          width: 20,
          height: 20,
          borderRadius: "50%",
          border: dark
            ? "1px solid rgba(152,186,224,0.95)"
            : "1px solid rgba(79,140,255,0.85)",
          background: dark
            ? "radial-gradient(circle at 36% 30%, rgba(152,186,224,0.5), rgba(152,186,224,0.05) 65%, transparent 75%)"
            : "radial-gradient(circle at 36% 30%, rgba(79,140,255,0.45), rgba(79,140,255,0.08) 65%, transparent 75%)",
          boxShadow: dark
            ? "0 0 15px rgba(152,186,224,0.72), inset 0 0 9px rgba(152,186,224,0.32)"
            : "4px 4px 10px rgba(153,170,195,0.38), -3px -3px 8px rgba(255,255,255,0.78), 0 0 11px rgba(79,140,255,0.32)",
          transform: turbo ? "scale(1.14)" : "scale(1)",
          transition: "transform 120ms ease",
        }}
      />
      <div
        style={{
          position: "absolute",
          left: pos.x - 2.5,
          top: pos.y - 2.5,
          width: 5,
          height: 5,
          borderRadius: "50%",
          background: dark ? "rgba(152,186,224,0.95)" : "rgba(79,140,255,0.9)",
          boxShadow: dark
            ? "0 0 10px rgba(152,186,224,0.88)"
            : "0 0 7px rgba(79,140,255,0.56)",
        }}
      />
    </div>
  );
}

function LockScreen({ onUnlock, theme = "light", onThemeChange = () => {} }) {
  const [entry, setEntry] = useState("");
  const [bad, setBad] = useState(false);
  const [unlocking, setUnlocking] = useState(false);
  const [unlockProgress, setUnlockProgress] = useState(0);
  const inputRef = useRef(null);
  const dark = theme === "dark";

  useEffect(() => {
    if (!unlocking) return undefined;
    const id = setInterval(() => {
      setUnlockProgress((p) => {
        const next = Math.min(100, p + 5);
        if (next >= 100) {
          clearInterval(id);
          setTimeout(onUnlock, 140);
        }
        return next;
      });
    }, 40);
    return () => clearInterval(id);
  }, [unlocking, onUnlock]);

  const rejectEntry = () => {
    setBad(true);
    setTimeout(() => {
      setEntry("");
      setBad(false);
    }, 620);
  };

  const validate = (candidate) => {
    if (candidate === LOCK_ACCESS_CODE) {
      setUnlocking(true);
      setUnlockProgress(0);
      return;
    }
    rejectEntry();
  };

  const sanitizeEntry = (value) =>
    String(value || "")
      .toUpperCase()
      .replace(/[^A-Z0-9]/g, "")
      .slice(0, LOCK_ACCESS_CODE.length);

  const onEntryChange = (rawValue) => {
    if (unlocking) return;
    const next = sanitizeEntry(rawValue);
    setEntry(next);
    if (next.length === LOCK_ACCESS_CODE.length) {
      validate(next);
    }
  };

  const blockClipboard = (e) => {
    e.preventDefault();
  };

  useEffect(() => {
    if (unlocking) return;
    const id = setTimeout(() => {
      if (inputRef.current) inputRef.current.focus();
    }, 10);
    return () => clearTimeout(id);
  }, [unlocking]);

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        background: dark
          ? "linear-gradient(160deg, #1b251f 0%, #161f1a 56%, #121914 100%)"
          : "linear-gradient(160deg, #f4e9d2 0%, #e9dcc1 56%, #deceb0 100%)",
        display: "grid",
        placeItems: "center",
        zIndex: 9999,
        overflow: "hidden",
      }}
    >
      <div
        style={{
          zIndex: 1,
          width: 700,
          maxWidth: "94vw",
          borderRadius: 38,
          padding: "28px 30px 24px",
          background: dark
            ? "linear-gradient(165deg, #2d3c33 0%, #27352d 62%, #212d26 100%)"
            : "linear-gradient(165deg, #f7ecd8 0%, #ecdfc4 62%, #e3d3b5 100%)",
          border: dark
            ? "1px solid rgba(169,154,111,0.44)"
            : "1px solid rgba(177,151,94,0.5)",
          boxShadow: dark
            ? "30px 30px 60px rgba(6,10,8,0.58), -20px -20px 50px rgba(67,86,73,0.3), inset 0 2px 0 rgba(205,190,145,0.17), inset 0 -4px 12px rgba(7,10,8,0.5)"
            : "30px 30px 56px rgba(186,167,126,0.42), -20px -20px 48px rgba(255,251,240,0.86), inset 0 2px 0 rgba(255,255,252,0.85), inset 0 -4px 12px rgba(188,166,120,0.35)",
          transform: bad ? "translateX(-8px)" : "none",
          transition: "transform 140ms ease",
        }}
      >
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: 20,
            gap: 12,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span
              style={{
                width: 26,
                height: 26,
                borderRadius: "50%",
                background: dark
                  ? "linear-gradient(160deg, #3d5044, #314136)"
                  : "linear-gradient(160deg, #f5ecd8, #e7dcc2)",
                border: dark
                  ? "1px solid rgba(169,154,111,0.44)"
                  : "1px solid rgba(183,159,102,0.56)",
                boxShadow: dark
                  ? "5px 5px 10px rgba(10,15,12,0.58), -3px -3px 8px rgba(73,94,81,0.32), inset 0 1px 0 rgba(219,204,160,0.22)"
                  : "5px 5px 10px rgba(181,166,131,0.4), -3px -3px 8px rgba(255,255,255,0.9), inset 0 1px 0 rgba(255,255,255,0.95)",
                display: "grid",
                placeItems: "center",
              }}
            >
              <span
                style={{
                  width: 7,
                  height: 7,
                  borderRadius: "50%",
                  background: dark ? "#d1ba7a" : "#b08a3b",
                }}
              />
            </span>
            <div
              style={{
                fontFamily: "JetBrains Mono",
                color: dark ? "#e6e8d8" : "#6f5f3b",
                fontSize: 11,
                letterSpacing: 2,
                padding: "7px 16px",
                borderRadius: 999,
                background: dark
                  ? "linear-gradient(165deg, #36473c, #2f3f35)"
                  : "linear-gradient(165deg, #f5ebd6, #e8dcc1)",
                boxShadow: dark
                  ? "inset 3px 3px 6px rgba(14,18,16,0.5), inset -3px -3px 6px rgba(73,94,81,0.26)"
                  : "inset 3px 3px 6px rgba(188,171,132,0.32), inset -3px -3px 6px rgba(255,255,255,0.92)",
              }}
            >
              SECURE LOCK
            </div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <button
              onClick={() => onThemeChange("light")}
              style={{
                borderRadius: 999,
                border:
                  theme === "light"
                    ? "1px solid rgba(143,159,182,0.72)"
                    : "1px solid rgba(170,182,201,0.44)",
                background:
                  theme === "light"
                    ? "linear-gradient(165deg, #ebf0f6, #dde5ef)"
                    : "linear-gradient(165deg, #e4eaf2, #d8e0eb)",
                color: "#5b6f8b",
                padding: "5px 14px",
                fontFamily: "JetBrains Mono",
                fontSize: 10,
                letterSpacing: 0.8,
                cursor: "pointer",
                boxShadow:
                  "inset 1px 1px 2px rgba(255,255,255,0.85), inset -1px -1px 2px rgba(173,185,201,0.35)",
              }}
            >
              Light
            </button>
            <button
              onClick={() => onThemeChange("dark")}
              style={{
                borderRadius: 999,
                border:
                  theme === "dark"
                    ? "1px solid rgba(158,169,184,0.72)"
                    : "1px solid rgba(126,136,151,0.42)",
                background: dark
                  ? "linear-gradient(165deg, #3c4451, #333b48)"
                  : "linear-gradient(165deg, #e4eaf2, #d8e0eb)",
                color: dark ? "#c3cfde" : "#72869f",
                padding: "5px 14px",
                fontFamily: "JetBrains Mono",
                fontSize: 10,
                letterSpacing: 0.8,
                cursor: "pointer",
                boxShadow: dark
                  ? "inset 1px 1px 2px rgba(217,225,238,0.13), inset -1px -1px 2px rgba(19,24,33,0.56)"
                  : "inset 1px 1px 2px rgba(255,255,255,0.85), inset -1px -1px 2px rgba(173,185,201,0.35)",
              }}
            >
              Dark
            </button>
          </div>
        </div>

        <div
          style={{ display: "grid", placeItems: "center", marginBottom: 10 }}
        >
          <div
            style={{
              width: 120,
              height: 120,
              borderRadius: "50%",
              background: dark
                ? "linear-gradient(160deg, #3f4754, #343b47)"
                : "linear-gradient(160deg, #e2e8f1, #d4deea)",
              border: dark
                ? "1px solid rgba(145,156,172,0.42)"
                : "1px solid rgba(177,190,208,0.68)",
              display: "grid",
              placeItems: "center",
              boxShadow: dark
                ? "inset 8px 8px 14px rgba(15,19,27,0.52), inset -8px -8px 14px rgba(80,92,109,0.24)"
                : "inset 8px 8px 14px rgba(173,185,201,0.36), inset -8px -8px 14px rgba(255,255,255,0.92)",
            }}
          >
            <Logo size={64} animated={false} lockTheme />
          </div>
        </div>

        <h1
          className="vault-access-btn"
          onClick={() => inputRef.current && inputRef.current.focus()}
          style={{
            margin: "10px 0 8px",
            textAlign: "center",
            fontFamily: "Orbitron",
            letterSpacing: 2.8,
            color: dark ? "#d4deeb" : "#425974",
            textShadow: "none",
            fontWeight: 800,
          }}
        >
          SECURE VAULT ACCESS
        </h1>
        <div style={{ marginBottom: 10 }}>
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              color: dark ? "#9bb2d0" : "#6f89ad",
              fontFamily: "JetBrains Mono",
              fontSize: 10,
              marginBottom: 8,
              letterSpacing: 1.5,
            }}
          >
            <span>ACCESS KEY</span>
            <span>
              {entry.length}/{LOCK_ACCESS_CODE.length}
            </span>
          </div>
          <div
            style={{
              height: 42,
              borderRadius: 12,
              border: `1px solid ${bad ? "rgba(199,102,122,0.65)" : dark ? "rgba(131,153,183,0.5)" : "rgba(162,182,209,0.62)"}`,
              background: dark
                ? "linear-gradient(165deg, #333e4f, #2b3544)"
                : "linear-gradient(165deg, #e5ebf4, #d9e2ee)",
              boxShadow: dark
                ? "inset 4px 4px 9px rgba(15,20,29,0.58), inset -4px -4px 9px rgba(84,101,127,0.32)"
                : "inset 4px 4px 9px rgba(179,194,214,0.4), inset -4px -4px 9px rgba(255,255,255,0.9)",
              display: "grid",
              placeItems: "center",
              fontFamily: "JetBrains Mono",
              color: dark ? "#cfe0f8" : "#5d7ea8",
              letterSpacing: 2,
              fontWeight: 700,
              fontSize: 14,
            }}
          >
            {"*".repeat(entry.length).padEnd(LOCK_ACCESS_CODE.length, "_")}
          </div>
        </div>

        <div
          style={{ display: "grid", gap: 10, position: "relative" }}
          onClick={() => inputRef.current && inputRef.current.focus()}
        >
          <div
            style={{
              width: "100%",
              height: 56,
              borderRadius: 16,
              border: dark
                ? "1px solid rgba(132,154,183,0.5)"
                : "1px solid rgba(167,187,213,0.65)",
              background: dark
                ? "linear-gradient(165deg, #333e4f, #2a3443)"
                : "linear-gradient(165deg, #e6edf5, #dae3ef)",
              color: dark ? "#b7c9e1" : "#6a87ad",
              letterSpacing: 2,
              textAlign: "center",
              fontFamily: "Orbitron",
              fontWeight: 700,
              fontSize: 16,
              display: "grid",
              placeItems: "center",
              boxShadow: dark
                ? "inset 6px 6px 12px rgba(13,18,26,0.62), inset -6px -6px 12px rgba(82,99,126,0.3)"
                : "inset 6px 6px 12px rgba(179,194,214,0.42), inset -6px -6px 12px rgba(255,255,255,0.9)",
              userSelect: "none",
            }}
          >
            {entry.length ? "INPUT MASKED" : "TYPE ACCESS KEY"}
          </div>
          <input
            ref={inputRef}
            type="password"
            disabled={unlocking}
            value={entry}
            onChange={(e) => onEntryChange(e.target.value)}
            onCopy={blockClipboard}
            onCut={blockClipboard}
            onPaste={blockClipboard}
            onKeyDown={(e) => {
              if (
                e.key === "Enter" &&
                entry.length === LOCK_ACCESS_CODE.length
              ) {
                e.preventDefault();
                validate(entry);
              }
              if (e.key === "Escape") {
                e.preventDefault();
                setEntry("");
              }
            }}
            maxLength={LOCK_ACCESS_CODE.length}
            autoCapitalize="characters"
            autoCorrect="off"
            autoComplete="new-password"
            inputMode="text"
            aria-label="Access key"
            spellCheck={false}
            placeholder=""
            style={{
              position: "absolute",
              left: 0,
              top: 0,
              width: "100%",
              height: 56,
              opacity: 0.02,
              border: "none",
              outline: "none",
              background: "transparent",
              color: "transparent",
              caretColor: "transparent",
              WebkitTextSecurity: "disc",
            }}
          />
          <div
            style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}
          >
            <button
              disabled={unlocking}
              onClick={() => setEntry("")}
              style={{
                width: "100%",
                height: 50,
                borderRadius: 14,
                border: dark
                  ? "1px solid rgba(132,154,183,0.5)"
                  : "1px solid rgba(167,187,213,0.64)",
                background: dark
                  ? "linear-gradient(165deg, #343f51, #2d3748)"
                  : "linear-gradient(165deg, #e6edf5, #dae3ef)",
                color: dark ? "#c5d8f2" : "#4e6f99",
                fontFamily: "Orbitron",
                fontWeight: 700,
                letterSpacing: 1,
                fontSize: 12,
                cursor: unlocking ? "default" : "pointer",
                opacity: unlocking ? 0.55 : 1,
                boxShadow: dark
                  ? "6px 6px 12px rgba(12,16,24,0.55), -4px -4px 10px rgba(84,101,126,0.28), inset 0 1px 0 rgba(203,220,246,0.18)"
                  : "6px 6px 12px rgba(176,191,212,0.4), -4px -4px 10px rgba(255,255,255,0.9), inset 0 1px 0 rgba(255,255,255,0.9)",
              }}
            >
              CLEAR
            </button>
            <button
              disabled={unlocking || entry.length !== LOCK_ACCESS_CODE.length}
              onClick={() => validate(entry)}
              style={{
                width: "100%",
                height: 50,
                borderRadius: 14,
                border: dark
                  ? "1px solid rgba(146,169,200,0.58)"
                  : "1px solid rgba(153,176,207,0.68)",
                background: dark
                  ? "linear-gradient(165deg, #3a475c, #313c4d)"
                  : "linear-gradient(165deg, #dde6f2, #d2dcea)",
                color: dark ? "#cfe0f7" : "#5a7ca7",
                fontFamily: "Orbitron",
                fontWeight: 700,
                letterSpacing: 1,
                fontSize: 12,
                cursor:
                  unlocking || entry.length !== LOCK_ACCESS_CODE.length
                    ? "default"
                    : "pointer",
                opacity:
                  unlocking || entry.length !== LOCK_ACCESS_CODE.length
                    ? 0.5
                    : 1,
                boxShadow: dark
                  ? "6px 6px 12px rgba(12,16,24,0.55), -4px -4px 10px rgba(84,101,126,0.28), inset 0 1px 0 rgba(203,220,246,0.18)"
                  : "6px 6px 12px rgba(176,191,212,0.4), -4px -4px 10px rgba(255,255,255,0.9), inset 0 1px 0 rgba(255,255,255,0.9)",
              }}
            >
              UNLOCK
            </button>
          </div>
        </div>

        <div style={{ marginTop: 12, marginBottom: 4 }}>
          <div
            style={{
              height: 14,
              borderRadius: 999,
              background: dark
                ? "linear-gradient(165deg, #313c4d, #2a3443)"
                : "linear-gradient(165deg, #dce5f1, #d1dcea)",
              boxShadow: dark
                ? "inset 4px 4px 8px rgba(14,18,26,0.58), inset -4px -4px 8px rgba(82,99,126,0.28)"
                : "inset 4px 4px 8px rgba(180,195,215,0.4), inset -4px -4px 8px rgba(255,255,255,0.9)",
              overflow: "hidden",
            }}
          >
            <div
              style={{
                width: `${unlockProgress}%`,
                height: "100%",
                borderRadius: 999,
                background: dark
                  ? "linear-gradient(90deg, #8fa6c7, #a7bad5)"
                  : "linear-gradient(90deg, #8cabd2, #a9c1df)",
                transition: "width 80ms linear",
              }}
            />
          </div>
        </div>

        <div
          style={{
            marginTop: 6,
            textAlign: "center",
            fontFamily: "JetBrains Mono",
            color: bad
              ? dark
                ? "#d6a1ad"
                : "#b36c7b"
              : dark
                ? "#a8bdd9"
                : "#6685ad",
            fontSize: 11,
            letterSpacing: 1.6,
            minHeight: 16,
          }}
        >
          {unlocking
            ? "Access granted. Opening QUANTHUNT dashboard..."
            : bad
              ? "Invalid access key"
              : "Type the access key and press unlock"}
        </div>
      </div>
    </div>
  );
}
function PressureText({ children, style = {}, glow = C.cyan }) {
  const [hovered, setHovered] = useState(false);
  const [offset, setOffset] = useState({ x: 0, y: 0 });
  const dark = isDarkTheme();
  const onMove = (e) => {
    const r = e.currentTarget.getBoundingClientRect();
    const x = ((e.clientX - (r.left + r.width / 2)) / r.width) * 4;
    const y = ((e.clientY - (r.top + r.height / 2)) / r.height) * 4;
    setOffset({ x, y });
  };
  return (
    <span
      onMouseEnter={() => setHovered(true)}
      onMouseMove={onMove}
      onMouseLeave={() => {
        setHovered(false);
        setOffset({ x: 0, y: 0 });
      }}
      style={{
        display: "inline-block",
        transform: `translate(${offset.x}px, ${offset.y}px) scale(${hovered ? 1.05 : 1})`,
        transition:
          "transform 140ms cubic-bezier(0.175, 0.885, 0.32, 1.275), text-shadow 140ms ease",
        fontWeight: 800,
        letterSpacing: "0.08em",
        textTransform: "uppercase",
        textShadow: hovered
          ? `0 0 25px ${glow}99, 0 0 10px ${glow}55, 2px 2px 4px rgba(0,0,0,0.2)`
          : dark
            ? "0 1px 0 rgba(223,231,242,0.2)"
            : "0 1px 0 rgba(255,255,255,0.76)",
        ...style,
      }}
    >
      {children}
    </span>
  );
}

function ClayNumber({
  value,
  tone = C.blue,
  size = 12,
  minWidth = 48,
  style = {},
}) {
  const dark = isDarkTheme();
  const pad = size >= 18 ? "6px 12px" : "4px 9px";
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        minWidth,
        padding: pad,
        borderRadius: 999,
        border: `1px solid ${dark ? `${tone}88` : `${tone}66`}`,
        background: dark
          ? `linear-gradient(145deg, rgba(13,28,50,0.94), ${tone}20)`
          : `linear-gradient(145deg, #f8fbff, ${tone}20)`,
        boxShadow: dark
          ? "4px 4px 10px rgba(2,8,16,0.8), -3px -3px 8px rgba(112,158,207,0.16), inset 0 1px 0 rgba(255,255,255,0.2)"
          : "4px 4px 10px rgba(170,186,208,0.36), -3px -3px 8px rgba(255,255,255,0.9), inset 0 1px 0 rgba(255,255,255,0.86)",
        color: dark ? "#e7f6ff" : "#27446f",
        fontFamily: "Orbitron",
        fontSize: size,
        fontWeight: 700,
        letterSpacing: 0.8,
        textShadow: dark ? `0 0 10px ${tone}44` : "none",
        ...style,
      }}
    >
      {value}
    </span>
  );
}

function ClayMetric({ label, value, tone = C.blue, size = 18, style = {} }) {
  return (
    <div style={style}>
      <div
        style={{
          color: C.dim,
          fontFamily: "JetBrains Mono",
          fontSize: 10,
          marginBottom: 6,
        }}
      >
        {label}
      </div>
      <ClayNumber
        value={value}
        tone={tone}
        size={size}
        minWidth={size >= 18 ? 76 : 56}
      />
    </div>
  );
}

function Card({ children, style = {} }) {
  const [hover, setHover] = useState(false);
  const dark = isDarkTheme();
  return (
    <div
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        position: "relative",
        zIndex: hover ? 40 : 1,
        background: dark
          ? "linear-gradient(160deg, #15243f 0%, #111d34 100%)"
          : "linear-gradient(160deg, #ebeff4 0%, #e1e6ed 100%)",
        border: `1px solid ${hover ? (dark ? "rgba(144,166,198,0.45)" : "rgba(112,136,166,0.35)") : C.border}`,
        borderRadius: 20,
        boxShadow: hover
          ? dark
            ? "0 20px 36px rgba(4,9,18,0.64), inset 0 1px 0 rgba(165,188,215,0.2), inset 0 -1px 0 rgba(6,17,31,0.6)"
            : "14px 14px 26px rgba(164,180,203,0.43), -10px -10px 24px rgba(239,243,248,0.72), inset 0 1px 0 rgba(241,245,248,0.8), inset 0 -1px 0 rgba(180,196,217,0.45)"
          : dark
            ? "0 14px 28px rgba(3,8,16,0.58), inset 0 1px 0 rgba(144,166,194,0.14), inset 0 -1px 0 rgba(6,17,31,0.56)"
            : "9px 9px 19px rgba(168,184,206,0.4), -8px -8px 18px rgba(239,243,248,0.72), inset 0 1px 0 rgba(241,245,248,0.8), inset 0 -1px 0 rgba(183,198,219,0.4)",
        transform: hover ? "translateY(-1px)" : "none",
        transition: "all 180ms ease",
        ...style,
      }}
    >
      {children}
    </div>
  );
}

const Btn = ({ children, onClick, disabled }) => {
  const dark = isDarkTheme();
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      style={{
        borderRadius: 12,
        border: dark
          ? "1px solid rgba(128,155,186,0.44)"
          : "1px solid rgba(104,131,166,0.3)",
        padding: "10px 16px",
        background: dark
          ? "linear-gradient(155deg, #233754, #1b2e49)"
          : "linear-gradient(155deg, #e4e9ef, #d6dde6)",
        color: dark ? "#d3e1f2" : "#2f4f79",
        fontFamily: "Orbitron",
        cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled ? 0.45 : 1,
        boxShadow: dark
          ? "0 12px 24px rgba(5,10,18,0.42), inset 0 1px 0 rgba(177,196,221,0.2)"
          : "6px 6px 12px rgba(170,186,208,0.42), -5px -5px 12px rgba(238,243,248,0.72)",
      }}
    >
      <PressureText
        glow={dark ? C.cyan : C.blue}
        style={{ pointerEvents: "none" }}
      >
        {children}
      </PressureText>
    </button>
  );
};

function SearchGlyph({ color = "#6f7d62", size = 14 }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <circle cx="11" cy="11" r="7" stroke={color} strokeWidth="2" />
      <path d="M16.65 16.65L21 21" stroke={color} strokeWidth="2" strokeLinecap="round" />
    </svg>
  );
}

function LiquidSearchSelect({
  value,
  onChange,
  options,
  minWidth = 260,
  buttonLabel = "Select option",
  searchPlaceholder = "Search...",
  emptyLabel = "No matching options",
}) {
  const dark = isDarkTheme();
  const rootRef = useRef(null);
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");

  const selected = useMemo(
    () => (options || []).find((opt) => String(opt.value) === String(value)) || null,
    [options, value],
  );

  const filtered = useMemo(() => {
    const q = String(query || "").trim().toLowerCase();
    if (!q) return options || [];
    return (options || []).filter((opt) =>
      String(opt.label || "").toLowerCase().includes(q),
    );
  }, [options, query]);

  useEffect(() => {
    if (!open) return;
    const onDocDown = (e) => {
      if (!rootRef.current) return;
      if (!rootRef.current.contains(e.target)) {
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", onDocDown);
    return () => document.removeEventListener("mousedown", onDocDown);
  }, [open]);

  return (
    <div
      ref={rootRef}
      style={{
        position: "relative",
        minWidth,
        zIndex: open ? 180 : "auto",
      }}
    >
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        style={{
          width: "100%",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 8,
          borderRadius: 12,
          border: dark
            ? "1px solid rgba(121,189,159,0.44)"
            : "1px solid rgba(146,129,80,0.36)",
          background: dark
            ? "linear-gradient(152deg, rgba(18,53,42,0.84), rgba(16,42,34,0.72))"
            : "linear-gradient(152deg, rgba(255,244,211,0.86), rgba(206,238,220,0.7))",
          boxShadow: dark
            ? "0 10px 18px rgba(4,12,10,0.42), inset 0 1px 0 rgba(160,222,193,0.14)"
            : "0 9px 16px rgba(166,152,109,0.26), inset 0 1px 0 rgba(255,255,255,0.8)",
          color: C.text,
          padding: "9px 10px",
          cursor: "pointer",
          fontFamily: "JetBrains Mono",
          fontSize: 11,
          letterSpacing: 0.25,
          textAlign: "left",
        }}
      >
        <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {selected?.label || buttonLabel}
        </span>
        <span style={{ color: C.dim, fontSize: 10 }}>{open ? "^" : "v"}</span>
      </button>

      {open && (
        <div
          style={{
            position: "absolute",
            top: "calc(100% + 6px)",
            left: 0,
            right: 0,
            zIndex: 220,
            borderRadius: 12,
            border: dark
              ? "1px solid rgba(121,189,159,0.42)"
              : "1px solid rgba(146,129,80,0.34)",
            background: dark
              ? "linear-gradient(160deg, rgba(16,44,35,0.96), rgba(12,33,27,0.94))"
              : "linear-gradient(160deg, rgba(255,247,223,0.96), rgba(221,244,230,0.94))",
            boxShadow: dark
              ? "0 20px 30px rgba(2,10,8,0.58)"
              : "0 18px 28px rgba(134,117,66,0.22)",
            backdropFilter: "blur(12px) saturate(120%)",
            WebkitBackdropFilter: "blur(12px) saturate(120%)",
            overflow: "hidden",
          }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              padding: 8,
              borderBottom: dark
                ? "1px solid rgba(121,189,159,0.2)"
                : "1px solid rgba(146,129,80,0.2)",
            }}
          >
            <SearchGlyph color={dark ? "#93c9ab" : "#7a6b3c"} />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={searchPlaceholder}
              autoFocus
              style={{
                flex: 1,
                border: "none",
                outline: "none",
                borderRadius: 8,
                background: dark ? "rgba(17,57,44,0.62)" : "rgba(255,252,236,0.8)",
                color: C.text,
                padding: "7px 8px",
                fontFamily: "JetBrains Mono",
                fontSize: 11,
              }}
            />
          </div>
          <div
            className="qh-soft-scroll"
            style={{ maxHeight: 220, overflowY: "auto", padding: 6, display: "grid", gap: 6 }}
          >
            {filtered.length ? (
              filtered.map((opt) => {
                const active = String(opt.value) === String(value);
                return (
                  <button
                    type="button"
                    key={String(opt.value)}
                    onClick={() => {
                      onChange(String(opt.value));
                      setOpen(false);
                      setQuery("");
                    }}
                    style={{
                      textAlign: "left",
                      borderRadius: 10,
                      border: active
                        ? dark
                          ? "1px solid rgba(127,206,170,0.68)"
                          : "1px solid rgba(152,122,49,0.64)"
                        : dark
                          ? "1px solid rgba(126,166,145,0.36)"
                          : "1px solid rgba(167,147,92,0.36)",
                      background: active
                        ? dark
                          ? "linear-gradient(140deg, rgba(33,88,69,0.7), rgba(18,65,48,0.58))"
                          : "linear-gradient(140deg, rgba(255,233,171,0.8), rgba(183,230,206,0.62))"
                        : dark
                          ? "rgba(16,44,35,0.52)"
                          : "rgba(255,250,234,0.62)",
                      color: C.text,
                      padding: "8px 10px",
                      fontFamily: "JetBrains Mono",
                      fontSize: 12,
                      cursor: "pointer",
                    }}
                  >
                    {opt.label}
                  </button>
                );
              })
            ) : (
              <div
                style={{
                  borderRadius: 10,
                  border: dark
                    ? "1px dashed rgba(126,166,145,0.42)"
                    : "1px dashed rgba(167,147,92,0.42)",
                  color: C.dim,
                  padding: "10px",
                  fontFamily: "JetBrains Mono",
                  fontSize: 11,
                }}
              >
                {emptyLabel}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

const Badge = ({ status }) => (
  <span
    style={{
      padding: "4px 10px",
      borderRadius: 8,
      border: `1px solid ${statusColor[status] || C.dim}55`,
      color: statusColor[status] || C.dim,
      fontSize: 10,
      fontFamily: "JetBrains Mono",
      letterSpacing: 1,
    }}
  >
    {status}
  </span>
);

function TabModeAccent({ scanModel = "general", tabLabel = "" }) {
  const dark = isDarkTheme();
  const banking = normalizeScanModel(scanModel) === "banking";
  const tone = banking
    ? dark
      ? "#f2deaf"
      : "#6e4f17"
    : dark
      ? "#d7f4e4"
      : "#2f6a53";
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: 10,
        marginBottom: 10,
      }}
    >
      <div
        style={{
          color: C.dim,
          fontFamily: "Orbitron",
          fontSize: 11,
          letterSpacing: 1.1,
        }}
      >
        {tabLabel}
      </div>
      <div
        style={{
          borderRadius: 999,
          padding: "4px 11px",
          border: banking
            ? dark
              ? "1px solid rgba(211,181,112,0.66)"
              : "1px solid rgba(185,145,60,0.58)"
            : dark
              ? "1px solid rgba(116,201,166,0.62)"
              : "1px solid rgba(61,155,117,0.56)",
          background: banking
            ? dark
              ? "linear-gradient(160deg, rgba(112,84,31,0.72), rgba(84,62,21,0.62))"
              : "linear-gradient(160deg, rgba(250,234,198,0.9), rgba(233,209,151,0.78))"
            : dark
              ? "linear-gradient(160deg, rgba(30,100,73,0.72), rgba(22,77,56,0.62))"
              : "linear-gradient(160deg, rgba(220,247,233,0.9), rgba(187,233,208,0.78))",
          color: tone,
          fontFamily: "JetBrains Mono",
          fontSize: 10,
          letterSpacing: 0.9,
          boxShadow: dark
            ? "inset 0 1px 0 rgba(255,255,255,0.16), 0 8px 14px rgba(0,0,0,0.24)"
            : "inset 0 1px 0 rgba(255,255,255,0.72), 0 7px 12px rgba(132,146,128,0.22)",
        }}
      >
        {banking ? "BANKING PROFILE | PQC-S1" : "NON-BANK PROFILE | PQC-M2"}
      </div>
    </div>
  );
}

function TabGuide({ title, subtitle, bullets = [] }) {
  const compact = typeof window !== "undefined" && window.innerWidth < 760;
  return (
    <div
      style={{
        marginBottom: compact ? 9 : 12,
        borderRadius: compact ? 12 : 14,
        padding: compact ? "8px 10px" : "10px 12px",
        border: `1px solid ${C.border}`,
        background: isDarkTheme()
          ? "rgba(17,33,29,0.56)"
          : "rgba(255,250,238,0.72)",
      }}
    >
      <div
        style={{
          color: C.text,
          fontFamily: "Orbitron",
          fontSize: compact ? 11 : 12,
          letterSpacing: compact ? 0.7 : 0.9,
        }}
      >
        {title}
      </div>
      <div
        style={{
          marginTop: compact ? 3 : 4,
          color: C.dim,
          fontFamily: "JetBrains Mono",
          fontSize: compact ? 10 : 11,
          lineHeight: compact ? 1.42 : 1.5,
        }}
      >
        {subtitle}
      </div>
      {bullets.length > 0 &&
        (compact ? (
          <div
            style={{
              marginTop: 4,
              color: C.dim,
              fontFamily: "JetBrains Mono",
              fontSize: 9,
              lineHeight: 1.35,
            }}
          >
            {bullets.join(" | ")}
          </div>
        ) : (
          <div style={{ marginTop: 6, display: "grid", gap: 3 }}>
            {bullets.map((line) => (
              <div
                key={line}
                style={{
                  color: C.dim,
                  fontFamily: "JetBrains Mono",
                  fontSize: 10,
                }}
              >
                - {line}
              </div>
            ))}
          </div>
        ))}
    </div>
  );
}

function OpsStrip() {
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setTick((t) => t + 1), 1200);
    return () => clearInterval(id);
  }, []);

  const ai = Math.max(
    35,
    Math.min(95, Math.round(64 + Math.sin(tick * 0.9) * 16)),
  );
  const chain = Math.max(
    90,
    Math.min(100, Math.round(96 + Math.sin(tick * 0.5) * 2)),
  );
  const bot = Math.max(
    20,
    Math.min(90, Math.round(42 + Math.cos(tick * 0.8) * 20)),
  );

  const trendA = [44, 50, 53, 56, 60, 63, ai];
  const trendB = [96, 97, 95, 98, 97, 99, chain];
  const trendC = [58, 52, 49, 46, 44, 43, bot];

  return (
    <Card style={{ padding: 14, marginBottom: 14 }}>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: 10,
        }}
      >
        <div
          style={{
            fontFamily: "Orbitron",
            color: C.cyan,
            letterSpacing: 1.8,
            fontSize: 12,
          }}
        >
          <PressureText glow={C.blue}>QUANTHUNT COMMAND DECK</PressureText>
        </div>
        <div
          style={{
            fontFamily: "JetBrains Mono",
            color: C.dim,
            fontSize: 10,
            letterSpacing: 1.1,
          }}
        >
          LIVE SECURITY PULSE
        </div>
      </div>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit,minmax(180px,1fr))",
          gap: 10,
        }}
      >
        <TrendSpark
          label={`Threat Pulse ${ai}%`}
          color={C.blue}
          values={trendA}
        />
        <TrendSpark
          label={`Defense Health ${chain}%`}
          color={C.green}
          values={trendB}
        />
        <TrendSpark
          label={`Exposure Drift ${bot}%`}
          color={C.orange}
          values={trendC}
        />
      </div>
    </Card>
  );
}

function CyberIntelPanel({ scanModel = "general" }) {
  const [rows, setRows] = useState([]);
  useEffect(() => {
    const load = () =>
      fetch(`${API}/api/leaderboard?${scanModelParam(scanModel)}`)
        .then((r) => r.json())
        .then((d) =>
          setRows(filterRowsByMode(Array.isArray(d) ? d : [], scanModel)),
        )
        .catch(() => setRows([]));
    load();
    const id = setInterval(load, 6000);
    return () => clearInterval(id);
  }, [scanModel]);

  const normalizedRows = uniqueLatestLeaderboardByDomain(rows)
    .map((r) => ({
      ...r,
      avg: Number(r.avg_score ?? r.average_hndl_risk ?? 0),
    }))
    .filter((r) => Number.isFinite(r.avg));
  const normalized = normalizedRows.map((r) => r.avg);
  const avg = normalized.length
    ? (normalized.reduce((a, b) => a + b, 0) / normalized.length).toFixed(1)
    : "-";
  const highest = [...normalizedRows].sort((a, b) => b.avg - a.avg)[0] || null;
  const secure =
    normalizedRows.length > 1
      ? [...normalizedRows].sort((a, b) => a.avg - b.avg)[0]
      : null;
  const secureLabel =
    secure?.domain || (normalizedRows.length === 1 ? "Need 2+ domains" : "N/A");

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit,minmax(220px,1fr))",
        gap: 10,
        marginBottom: 14,
      }}
    >
      <Card style={{ padding: 14 }}>
        <ClayMetric
          label="AVERAGE RISK (ALL SCANNED DOMAINS)"
          value={avg}
          tone={C.cyan}
          size={20}
        />
        <div
          style={{
            marginTop: 6,
            color: C.dim,
            fontFamily: "JetBrains Mono",
            fontSize: 10,
          }}
        >
          Lower score means better security posture.
        </div>
      </Card>
      <Card style={{ padding: 14 }}>
        <div
          style={{ color: C.dim, fontFamily: "JetBrains Mono", fontSize: 10 }}
        >
          HIGHEST RISK DOMAIN
        </div>
        <div
          style={{
            color: C.red,
            fontFamily: "Orbitron",
            fontSize: 14,
            marginTop: 6,
          }}
        >
          <PressureText glow={C.red}>{highest?.domain || "N/A"}</PressureText>
        </div>
        <div
          style={{
            marginTop: 4,
            color: C.dim,
            fontFamily: "JetBrains Mono",
            fontSize: 10,
          }}
        >
          This domain currently has the highest average risk score.
        </div>
      </Card>
      <Card style={{ padding: 14 }}>
        <div
          style={{ color: C.dim, fontFamily: "JetBrains Mono", fontSize: 10 }}
        >
          SAFEST DOMAIN
        </div>
        <div
          style={{
            color: C.green,
            fontFamily: "Orbitron",
            fontSize: 14,
            marginTop: 6,
          }}
        >
          <PressureText glow={C.green}>{secureLabel}</PressureText>
        </div>
        <div
          style={{
            marginTop: 4,
            color: C.dim,
            fontFamily: "JetBrains Mono",
            fontSize: 10,
          }}
        >
          {normalizedRows.length === 1
            ? "Scan at least two domains to compare safely."
            : "This domain currently has the lowest average risk score."}
        </div>
      </Card>
    </div>
  );
}

function ScanOverlay({ domain, progress }) {
  const dark = isDarkTheme();
  const pct = Number(progress || 0);
  return (
    <div
      style={{ position: "fixed", inset: 0, zIndex: 45, pointerEvents: "none" }}
    >
      <div
        style={{
          position: "absolute",
          inset: 0,
          background: dark ? "rgba(6,15,28,0.62)" : "rgba(233,240,250,0.55)",
          backdropFilter: "blur(4px)",
        }}
      />
      <div
        style={{
          position: "absolute",
          left: "50%",
          top: "50%",
          transform: "translate(-50%, -50%)",
          width: 360,
          maxWidth: "88vw",
          borderRadius: 18,
          background: dark
            ? "linear-gradient(155deg, #14263f, #0f1f35)"
            : "linear-gradient(155deg, #e4e9ef, #d7dee6)",
          border: dark
            ? "1px solid rgba(107,178,240,0.36)"
            : "1px solid rgba(97,126,164,0.28)",
          boxShadow: dark
            ? "12px 12px 28px rgba(2,8,16,0.62), -10px -10px 22px rgba(24,48,80,0.5), inset 0 1px 0 rgba(168,218,255,0.18)"
            : "12px 12px 24px rgba(163,180,204,0.38), -10px -10px 22px rgba(255,255,255,0.9)",
          padding: 16,
        }}
      >
        <div
          style={{
            fontFamily: "JetBrains Mono",
            fontSize: 11,
            color: dark ? "#b8d2f4" : C.dim,
            marginBottom: 8,
          }}
        >
          Scanning target: {domain || "unknown"}
        </div>
        <div
          style={{
            height: 10,
            borderRadius: 999,
            background: dark ? "#1a2b43" : "#d9e4f3",
            boxShadow: dark
              ? "inset 2px 2px 6px rgba(2,9,16,0.75), inset -2px -2px 6px rgba(59,88,126,0.3)"
              : "inset 2px 2px 6px rgba(161,178,202,0.4), inset -2px -2px 6px rgba(255,255,255,0.9)",
            overflow: "hidden",
          }}
        >
          <div
            style={{
              width: `${pct}%`,
              height: "100%",
              borderRadius: 999,
              background: dark
                ? "linear-gradient(90deg, #7f9dc2, #9ab2d2)"
                : "linear-gradient(90deg, #698fbe, #8eacd0)",
              boxShadow: "none",
              transition: "width 180ms ease",
            }}
          />
        </div>
        <div style={{ marginTop: 7, textAlign: "right" }}>
          <ClayNumber
            value={`${pct}%`}
            tone={dark ? C.cyan : C.blue}
            size={10}
            minWidth={56}
          />
        </div>
      </div>
    </div>
  );
}

function ScannerTab({
  scanModel = "general",
  onAutoSwitchForDomain = () => {},
  pendingAutoScan = null,
  onAutoScanConsumed = () => {},
}) {
  const [domain, setDomain] = useState("");
  const [scanId, setScanId] = useState(null);
  const [scanData, setScanData] = useState(null);
  const [polling, setPolling] = useState(false);
  const [batch, setBatch] = useState("");
  const [formula, setFormula] = useState(null);
  const [flashMessage, setFlashMessage] = useState(null);
  const [fleetScans, setFleetScans] = useState([]);
  const [fleetBatchScans, setFleetBatchScans] = useState([]);
  const [fleetPolling, setFleetPolling] = useState(false);
  const [fleetAggregate, setFleetAggregate] = useState(null);
  const [showFleetStatusModal, setShowFleetStatusModal] = useState(false);
  const [fleetStatusQuery, setFleetStatusQuery] = useState("");
  const [fleetStatusFilter, setFleetStatusFilter] = useState("all");
  const logRef = useRef(null);

  useEffect(() => {
    if (flashMessage) {
      const timer = setTimeout(
        () => setFlashMessage(null),
        Number(flashMessage.durationMs || 11000),
      );
      return () => clearTimeout(timer);
    }
  }, [flashMessage]);

  const statusScore = (status) =>
    ({ CRITICAL: 100, WARNING: 50, ACCEPTABLE: 20, SAFE: 0 })[
      String(status || "").toUpperCase()
    ] ?? 50;

  const computeHndlBreakdown = (list) => {
    const cat = {
      key_exchange: { score: 0, count: 0 },
      authentication: { score: 0, count: 0 },
      tls_version: { score: 0, count: 0 },
      certificate: { score: 0, count: 0 },
      symmetric: { score: 0, count: 0 },
    };
    (list || []).forEach((f) => {
      if (!cat[f.category]) return;
      cat[f.category].score += statusScore(f.status);
      cat[f.category].count += 1;
    });
    const avg = (k) => (cat[k].count ? cat[k].score / cat[k].count : 0);
    const raw = {
      key_exchange: avg("key_exchange"),
      authentication: avg("authentication"),
      tls_version: avg("tls_version"),
      certificate: avg("certificate"),
      symmetric: avg("symmetric"),
    };
    const weighted = {
      key_exchange: raw.key_exchange * 0.45,
      authentication: raw.authentication * 0.25,
      tls_version: raw.tls_version * 0.15,
      certificate: raw.certificate * 0.1,
      symmetric: raw.symmetric * 0.05,
    };
    return {
      raw,
      weighted,
      total: Number(
        (
          weighted.key_exchange +
          weighted.authentication +
          weighted.tls_version +
          weighted.certificate +
          weighted.symmetric
        ).toFixed(2),
      ),
    };
  };

  const parseFleetDomains = () =>
    Array.from(
      new Set(
        batch
          .split(/[\n,]+/)
          .map((x) => x.trim().toLowerCase())
          .filter(Boolean),
      ),
    );

  const downloadArtifact = async (path, fallbackName) => {
    const r = await fetch(`${API}${path}`);
    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      const detail = err?.detail;
      if (detail && typeof detail === "object" && detail?.message === "Not QuantHunt Certified") {
        const reasons = Array.isArray(detail.reasons) ? detail.reasons : [];
        const reasonText = reasons.length
          ? reasons.map((x, i) => `${i + 1}. ${x}`).join("\n")
          : "Certification eligibility checks failed.";
        setFlashMessage({
          type: "error",
          centered: true,
          durationMs: 11000,
          text:
            `THIS WEBSITE IS NOT QUANTHUNT CERTIFIED\n\n` +
            `Avg HNDL Risk: ${detail.avg_hndl_risk ?? "n/a"}\n` +
            `${reasonText}`,
        });
        return;
      }
      const message =
        typeof detail === "string"
          ? detail
          : "File unavailable right now.";
      setFlashMessage({ type: "error", text: message, durationMs: 11000 });
      return;
    }
    const blob = await r.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const cd = r.headers.get("Content-Disposition") || "";
    const filename = /filename=([^;]+)/i.test(cd)
      ? cd.match(/filename=([^;]+)/i)[1].replace(/"/g, "")
      : fallbackName;
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const loadScanDetail = async (id) => {
    const detailResp = await fetch(`${API}/api/scan/${id}`);
    if (!detailResp.ok) return null;
    const detail = await detailResp.json();
    setScanData(detail);
    return detail;
  };

  const executeScan = async (target, requestedModel) => {
    let r;
    try {
      r = await fetch(`${API}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          domain: target,
          deep_scan: true,
          scan_model: requestedModel,
        }),
      });
    } catch {
      return setFlashMessage({
        text: "?? BACKEND OFFLINE OR BLOCKED (CORS/NETWORK). SET API WITH ?api=https://your-backend-url",
        type: "error",
      });
    }
    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      const detail =
        typeof err?.detail === "string"
          ? err.detail
          : !API && r.status === 404
            ? "Backend API not connected. Deploy FastAPI and open this app as ?api=https://your-backend-url"
            : "SCAN REJECTED BY MISSION CONTROL";
      return setFlashMessage({
        text: `?? TRANSMISSION FAILED: ${detail}`,
        type: "error",
      });
    }
    const d = await r.json();
    setScanId(d.scan_id);
    setFormula(null);

    if (d.reused && d.status === "completed") {
      const detail = await loadScanDetail(d.scan_id);
      if (!detail) {
        setPolling(false);
        setFlashMessage({
          text: "?? PREVIOUS SCAN DATA CORRUPPTED. RETRYING...",
          type: "error",
        });
        return;
      }
      setPolling(false);
      return;
    }

    if (d.reused && (d.status === "queued" || d.status === "running")) {
      await loadScanDetail(d.scan_id);
    } else {
      setScanData(null);
    }
    setPolling(true);
  };

  const startScan = async () => {
    const target = domain.trim();
    if (!target) return;

    if (
      !target.includes(".") ||
      target.length < 4 ||
      /[^a-zA-Z0-9.-]/.test(target)
    ) {
      setFlashMessage({
        text: "?? DOMAIN REJECTED! \n UNIDENTIFIED TRANSMISSION PATTERN. RECTIFY INPUT.",
        type: "error",
      });
      return;
    }

    const requestedModel = effectiveScanModelForDomain(target, scanModel);
    if (requestedModel !== normalizeScanModel(scanModel)) {
      onAutoSwitchForDomain(target, requestedModel);
      return;
    }
    await executeScan(target, requestedModel);
  };

  useEffect(() => {
    if (!pendingAutoScan?.domain || !pendingAutoScan?.scan_model) return;
    if (
      normalizeScanModel(pendingAutoScan.scan_model) !==
      normalizeScanModel(scanModel)
    )
      return;
    onAutoScanConsumed();
    setDomain(pendingAutoScan.domain);
    executeScan(pendingAutoScan.domain, pendingAutoScan.scan_model);
  }, [pendingAutoScan, scanModel]);

  useEffect(() => {
    if (!polling || !scanId) return;
    const id = setInterval(async () => {
      try {
        const r = await fetch(`${API}/api/scan/${scanId}`);
        if (!r.ok) {
          console.error("Scan polling failed:", r.status);
          return;
        }
        const d = await r.json();

        if (!d || !d.scan) {
          console.warn("Incomplete scan data received during polling");
          return;
        }

        setScanData(d);
        if (d.scan.status === "completed" || d.scan.status === "failed") {
          setPolling(false);
          if (d.scan.status === "failed") {
            setFlashMessage({
              text: "? SCAN ENGINE CRITICAL FAILURE.",
              type: "error",
            });
          }
        }
      } catch (e) {
        console.error("Polling error:", e);
      }
      if (logRef.current)
        logRef.current.scrollTop = logRef.current.scrollHeight;
    }, 1500);
    return () => clearInterval(id);
  }, [polling, scanId]);

  useEffect(() => {
    if (!scanData?.scan?.scan_id || scanData?.scan?.status !== "completed")
      return;
    let alive = true;
    fetch(`${API}/api/scan/${scanData.scan.scan_id}/findings`)
      .then((r) => (r.ok ? r.json() : { findings: [] }))
      .then((d) => {
        if (!alive) return;
        setFormula(computeHndlBreakdown(d.findings || []));
      })
      .catch(() => {
        if (alive) setFormula(null);
      });

    fetch(`${API}/api/scan/${scanData.scan.scan_id}/certification-status`)
      .then((r) => (r.ok ? r.json() : null))
      .then((status) => {
        if (!alive || !status || status.eligible) return;
        const reasons = Array.isArray(status.reasons) ? status.reasons : [];
        const reasonText = reasons.length
          ? reasons.map((x, i) => `${i + 1}. ${x}`).join("\n")
          : "Certification eligibility checks failed.";
        setFlashMessage({
          type: "error",
          centered: true,
          durationMs: 11000,
          text:
            `THIS WEBSITE IS NOT QUANTHUNT CERTIFIED\n\n` +
            `Avg HNDL Risk: ${status.avg_hndl_risk ?? "n/a"}\n` +
            `${reasonText}`,
        });
      })
      .catch(() => {});

    return () => {
      alive = false;
    };
  }, [scanData?.scan?.scan_id, scanData?.scan?.status]);

  useEffect(() => {
    if (!fleetPolling || !fleetBatchScans.length) return;

    const id = setInterval(async () => {
      try {
        const r = await fetch(`${API}/api/scan/batch/progress`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            scans: fleetBatchScans.map((item) => ({
              scan_id: item.scan_id,
              scan_model: normalizeScanModel(item.scan_model || scanModel),
              domain: item.domain,
            })),
          }),
        });
        if (!r.ok) return;
        const d = await r.json().catch(() => ({}));
        const scans = Array.isArray(d?.scans) ? d.scans : [];
        const byId = new Map(scans.map((x) => [x.scan_id, x]));
        const updatedAll = fleetBatchScans.map((item) => {
          const next = byId.get(item.scan_id);
          if (!next) return item;
          return {
            ...item,
            domain: next.domain || item.domain,
            status: next.status || item.status,
            progress: Number(next.progress ?? item.progress ?? 0),
          };
        });

        setFleetBatchScans(updatedAll);

        const backendInstant = String(d?.execution_mode || "interactive") === "backend_instant";
        const backendThreshold = Number(d?.backend_threshold ?? 5);
        setFleetScans(
          backendInstant
            ? updatedAll.slice(0, Math.max(1, backendThreshold))
            : updatedAll,
        );

        setFleetAggregate({
          total: Number(d?.total ?? updatedAll.length),
          completed: Number(d?.completed ?? 0),
          failed: Number(d?.failed ?? 0),
          running: Number(d?.running ?? 0),
          queued: Number(d?.queued ?? 0),
          progressPct: Number(d?.progress_pct ?? 0),
          backendInstant,
        });

        if (!Boolean(d?.in_progress)) {
          setFleetPolling(false);
        }
      } catch (_) {}
    }, 1800);

    return () => clearInterval(id);
  }, [fleetPolling, fleetBatchScans, scanModel]);

  const launchBatch = async () => {
    const domains = batch
      .split(/[\n,]+/)
      .map((x) => x.trim())
      .filter(Boolean);
    if (!domains.length) return;
    const r = await fetch(`${API}/api/scan/batch`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domains, scan_model: scanModel }),
    });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) {
      const detail =
        typeof d?.detail === "string"
          ? d.detail
          : d?.detail?.message || "Batch scan failed.";
      setFlashMessage({
        type: "error",
        text: `?? FLEET SCAN FAILED: ${detail}`,
      });
      return;
    }
    const scheduled = Number(d?.scheduled ?? 0);
    const reused = Number(d?.reused ?? 0);
    const items = Array.isArray(d?.scans) ? d.scans : [];
    const executionMode = String(d?.execution_mode || "interactive");
    const backendInstant = executionMode === "backend_instant";
    const backendThreshold = Number(d?.backend_threshold ?? 5);
    const selectedModel = normalizeScanModel(scanModel);
    const autoSwitched = items.filter(
      (x) => normalizeScanModel(x?.scan_model) !== selectedModel,
    );
    const mappedScans = items.map((x) => ({
      scan_id: x.scan_id,
      domain: x.domain,
      status: x.status,
      progress: x.status === "completed" ? 100 : 0,
      reused: Boolean(x.reused),
      scan_model: normalizeScanModel(x.scan_model || scanModel),
      data: null,
    }));

    setFleetBatchScans(mappedScans);
    setFleetAggregate({
      total: mappedScans.length,
      completed: mappedScans.filter((x) => x.status === "completed").length,
      failed: mappedScans.filter((x) => x.status === "failed").length,
      running: mappedScans.filter((x) => x.status === "running").length,
      queued: mappedScans.filter((x) => x.status === "queued").length,
      progressPct:
        Math.round(
          (mappedScans.reduce((acc, x) => acc + Number(x.progress || 0), 0) /
            Math.max(mappedScans.length, 1)) *
            100,
        ) / 100,
      backendInstant,
    });

    if (backendInstant) {
      setFleetScans(mappedScans.slice(0, backendThreshold));
      setFleetPolling(items.some((x) => x.status === "queued" || x.status === "running"));
    } else {
      setFleetScans(mappedScans);
      setFleetPolling(
        items.some((x) => x.status === "queued" || x.status === "running"),
      );
    }

    const modeLine = backendInstant
      ? `BACKEND INSTANT MODE ACTIVE: ${items.length} domain(s) are processing server-side and persisted. Showing first ${Math.min(items.length, backendThreshold)} for quick view.`
      : "";
    if (autoSwitched.length > 0) {
      const switchedDomains = autoSwitched.map((x) => x.domain).join(", ");
      setFlashMessage({
        type: "success",
        text:
          `FLEET INITIATED: ${scheduled} targets scheduled, ${reused} from intelligence cache.\n` +
          `${modeLine}${modeLine ? "\n" : ""}` +
          `AUTO MODE ROUTING ACTIVE: ${autoSwitched.length} domain(s) were routed to NON-BANK mode in backend (${switchedDomains}).\n` +
          `Artifacts (report/certificate/CBOM/analysis) are available under their respective mode tabs only.`,
      });
    } else {
      setFlashMessage({
        type: "success",
        text:
          `FLEET INITIATED: ${scheduled} targets scheduled, ${reused} from intelligence cache.` +
          (modeLine ? `\n${modeLine}` : ""),
      });
    }
    setBatch("");
  };

  const openFleetScan = async (item) => {
    if (!item?.scan_id) return;
    setScanId(item.scan_id);
    const detail = item.data || (await loadScanDetail(item.scan_id));
    if (!detail) return;
    setScanData(detail);
    setDomain(detail?.scan?.domain || item.domain || "");
    if (
      detail?.scan?.status === "queued" ||
      detail?.scan?.status === "running"
    ) {
      setPolling(true);
    }
  };

  const currentMode = normalizeScanModel(scanModel);
  const inModeFleetScans = fleetScans.filter(
    (item) => normalizeScanModel(item.scan_model || scanModel) === currentMode,
  );
  const autoRoutedFleetScans = fleetScans.filter(
    (item) => normalizeScanModel(item.scan_model || scanModel) !== currentMode,
  );
  const fleetStatusOptions = ["all", "queued", "running", "completed", "failed"];
  const filteredFleetStatuses = useMemo(() => {
    const q = String(fleetStatusQuery || "").trim().toLowerCase();
    return (fleetBatchScans || []).filter((item) => {
      const state = String(item?.status || "queued").toLowerCase();
      if (fleetStatusFilter !== "all" && state !== fleetStatusFilter) return false;
      if (!q) return true;
      const d = String(item?.domain || "").toLowerCase();
      const sid = String(item?.scan_id || "").toLowerCase();
      return d.includes(q) || sid.includes(q);
    });
  }, [fleetBatchScans, fleetStatusQuery, fleetStatusFilter]);

  return (
    <div style={{ display: "grid", gap: 18 }}>
      {polling && (
        <ScanOverlay
          domain={scanData?.scan?.domain || domain}
          progress={scanData?.scan?.progress || 0}
        />
      )}
      <Card style={{ padding: 24 }}>
        <TabModeAccent scanModel={scanModel} tabLabel="DOMAIN RADAR" />
        <TabGuide
          title="This tab runs live domain scans"
          subtitle="Use it to launch single or batch scans and monitor completion, posture score, and remediation outputs."
          bullets={[
            "Starts scan pipeline",
            "Shows telemetry and progress",
            "Downloads report and certificate",
          ]}
        />
        <h3 style={{ fontFamily: "Orbitron", color: C.cyan, marginTop: 0 }}>
          <PressureText glow={C.cyan}>DOMAIN RADAR</PressureText>
        </h3>
        {flashMessage && (
          <div
            style={{
              position: flashMessage.centered ? "fixed" : "relative",
              left: flashMessage.centered ? "50%" : undefined,
              top: flashMessage.centered ? "50%" : undefined,
              transform: flashMessage.centered ? "translate(-50%, -50%)" : undefined,
              zIndex: flashMessage.centered ? 3000 : undefined,
              minWidth: flashMessage.centered ? "min(86vw, 780px)" : undefined,
              maxWidth: flashMessage.centered ? "86vw" : undefined,
              background:
                flashMessage.type === "error"
                  ? "linear-gradient(145deg, rgba(145,0,20,0.42), rgba(100,0,10,0.30))"
                  : "rgba(40,167,69,0.15)",
              border: `1px solid ${flashMessage.type === "error" ? C.red : C.green}`,
              color: flashMessage.type === "error" ? C.red : C.green,
              padding: "12px 18px",
              borderRadius: 12,
              marginBottom: 16,
              fontFamily: "JetBrains Mono",
              fontSize: 13,
              display: "flex",
              alignItems: "center",
              gap: 12,
              backdropFilter: flashMessage.centered ? "blur(22px) saturate(1.15)" : undefined,
              WebkitBackdropFilter: flashMessage.centered ? "blur(22px) saturate(1.15)" : undefined,
              boxShadow: flashMessage.centered
                ? "0 22px 55px rgba(60,0,0,0.45), inset 0 1px 0 rgba(255,255,255,0.14)"
                : undefined,
              animation: "pulse 2s infinite",
            }}
          >
            <span style={{ fontSize: 20 }}>
              {flashMessage.type === "error" ? "??" : "?"}
            </span>
            <span style={{ whiteSpace: "pre-line" }}>{flashMessage.text}</span>
          </div>
        )}
        <div style={{ display: "flex", gap: 10 }}>
          <input
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="Enter any domain, e.g. pnb.bank.in"
            style={{
              flex: 1,
              borderRadius: 12,
              border: `1px solid ${C.border}`,
              background: "rgba(132,170,208,0.06)",
              color: C.text,
              padding: "12px 14px",
              fontFamily: "JetBrains Mono",
            }}
          />
          <Btn onClick={startScan} disabled={!domain.trim() || polling}>
            {polling ? "SCANNING..." : "SCAN"}
          </Btn>
        </div>
        <div
          style={{
            marginTop: 10,
            color: C.dim,
            fontFamily: "JetBrains Mono",
            fontSize: 12,
          }}
        >
          SCAN STATUS:{" "}
          <span style={{ color: C.cyan }}>
            {scanData?.scan?.status || "idle"}
          </span>{" "}
          |{" "}
          <ClayNumber
            value={`${scanData?.scan?.progress || 0}%`}
            tone={isDarkTheme() ? C.cyan : C.blue}
            size={10}
            minWidth={56}
          />
        </div>

        {scanData?.scan?.domain && (
          <div
            style={{
              marginTop: 15,
              padding: "16px",
              borderRadius: "18px",
              background: isDarkTheme()
                ? "linear-gradient(145deg, rgba(30,45,38,0.6), rgba(20,32,26,0.5))"
                : "linear-gradient(145deg, rgba(255,250,235,0.9), rgba(240,225,190,0.8))",
              border: isDarkTheme()
                ? "1px solid rgba(214,182,106,0.3)"
                : "1px solid rgba(186,161,101,0.4)",
              boxShadow: isDarkTheme()
                ? "12px 12px 24px rgba(5,8,6,0.4), -8px -8px 20px rgba(116,100,60,0.1), inset 0 1px 0 rgba(255,243,210,0.1)"
                : "10px 10px 20px rgba(178,156,106,0.2), -8px -8px 16px rgba(255,255,255,0.7), inset 0 1px 0 rgba(255,255,255,0.9)",
              fontFamily: "JetBrains Mono",
              display: "grid",
              gap: 12,
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <div
                style={{
                  width: 32,
                  height: 32,
                  borderRadius: "50%",
                  display: "grid",
                  placeItems: "center",
                  background: scanData.scan.domain.includes(".bank")
                    ? C.cyan
                    : C.orange,
                  boxShadow: `0 0 15px ${scanData.scan.domain.includes(".bank") ? C.cyan : C.orange}44`,
                }}
              >
                {scanData.scan.domain.includes(".bank") ? "???" : "??"}
              </div>
              <div style={{ flex: 1 }}>
                <div
                  style={{
                    fontSize: 13,
                    fontWeight: "bold",
                    color: isDarkTheme() ? C.cyan : C.blue,
                    letterSpacing: 1,
                  }}
                >
                  {scanData.scan.domain.includes(".bank")
                    ? "FINANCIAL CRYPTO LICENSE / PQC-S1"
                    : "NON-BANK ASSET LICENSE / PQC-M2"}
                </div>
                <div style={{ fontSize: 10, color: C.dim }}>
                  ACTIVE SECURITY BASELINE PROTOCOL
                </div>
              </div>
            </div>

            <div
              style={{
                padding: "10px",
                borderRadius: "12px",
                background: "rgba(0,0,0,0.04)",
                fontSize: 11,
                color: C.dim,
                lineHeight: 1.5,
                border: "1px solid rgba(186,161,101,0.1)",
              }}
            >
              {scanData.scan.domain.includes(".bank") ? (
                <>
                  <div
                    style={{
                      color: C.cyan,
                      fontWeight: "bold",
                      marginBottom: 4,
                    }}
                  >
                    [BANKING PROTOCOL ENABLED]
                  </div>
                  - NIST SP 800-186 Compliance Verification
                  <br />
                  - Strict Quantum-Resistance (Kyber/Dilithium) Enforcement
                  <br />- Full Certificate Revocation Path Analysis
                </>
              ) : (
                <>
                  <div
                    style={{
                      color: C.orange,
                      fontWeight: "bold",
                      marginBottom: 4,
                    }}
                  >
                    [MODERATE BASELINE ENABLED]
                  </div>
                  - Standard PQC Transition Framework (30% severity factor)
                  <br />
                  - Modern TLS 1.3 Adaptive Cipher Scoring
                  <br />- Standard Classical RSA/ECDSA Validation
                </>
              )}
            </div>
          </div>
        )}
        {scanData?.chain_blocks?.length > 0 && (
          <div
            style={{
              marginTop: 8,
              color: C.dim,
              fontFamily: "JetBrains Mono",
              fontSize: 11,
            }}
          >
            Audit checkpoint #
            {
              scanData.chain_blocks[scanData.chain_blocks.length - 1]
                .block_index
            }{" "}
            verified (hash:{" "}
            {String(
              scanData.chain_blocks[scanData.chain_blocks.length - 1]
                .block_hash || "",
            ).slice(0, 12)}
            ...)
          </div>
        )}
        {scanData?.scan?.scan_id && scanData?.scan?.status === "completed" && (
          <div
            style={{ display: "flex", flexWrap: "wrap", gap: 8, marginTop: 12 }}
          >
            <Btn
              onClick={() =>
                downloadArtifact(
                  `/api/scan/${scanData.scan.scan_id}/report.pdf`,
                  `quanthunt-report-${scanData.scan.scan_id}.pdf`,
                )
              }
            >
              DOWNLOAD REPORT
            </Btn>
            <Btn
              onClick={() =>
                downloadArtifact(
                  `/api/scan/${scanData.scan.scan_id}/certificate.pdf`,
                  `quanthunt-certificate-${scanData.scan.scan_id}.pdf`,
                )
              }
            >
              QUANTUM READINESS CERTIFICATE
            </Btn>
          </div>
        )}
      </Card>

      {formula && (
        <Card style={{ padding: 18 }}>
          <div
            style={{ fontFamily: "Orbitron", color: C.blue, marginBottom: 8 }}
          >
            <PressureText glow={C.blue}>
              HNDL Formula Breakdown (Live)
            </PressureText>
          </div>
          <div style={{ display: "grid", gap: 8 }}>
            {[
              { key: "key_exchange", label: "Key Exchange", weight: 45 },
              { key: "authentication", label: "Auth", weight: 25 },
              { key: "tls_version", label: "TLS Version", weight: 15 },
              { key: "certificate", label: "Certificate", weight: 10 },
              { key: "symmetric", label: "Symmetric", weight: 5 },
            ].map((row) => (
              <div
                key={row.key}
                style={{
                  display: "grid",
                  gridTemplateColumns: "160px 1fr 130px",
                  gap: 8,
                  alignItems: "center",
                }}
              >
                <div
                  style={{
                    color: C.dim,
                    fontFamily: "JetBrains Mono",
                    fontSize: 11,
                  }}
                >
                  {row.label} ({row.weight}%)
                </div>
                <div
                  style={{
                    color: C.text,
                    fontFamily: "JetBrains Mono",
                    fontSize: 11,
                  }}
                >
                  {formula.raw[row.key].toFixed(2)} x{" "}
                  {(row.weight / 100).toFixed(2)}
                </div>
                <div style={{ textAlign: "right" }}>
                  <ClayNumber
                    value={formula.weighted[row.key].toFixed(2)}
                    tone={C.blue}
                    size={10}
                    minWidth={70}
                  />
                </div>
              </div>
            ))}
          </div>
          <div
            style={{
              marginTop: 10,
              color: C.dim,
              fontFamily: "JetBrains Mono",
              fontSize: 11,
            }}
          >
            Final HNDL Score:
            <ClayNumber
              value={formula.total.toFixed(2)}
              tone={riskColor(formula.total)}
              size={11}
              minWidth={76}
              style={{ marginLeft: 8 }}
            />
          </div>
        </Card>
      )}

      <Card style={{ padding: 0, overflow: "hidden" }}>
        <div
          style={{
            padding: "12px 16px",
            borderBottom: `1px solid ${C.border}`,
            fontFamily: "JetBrains Mono",
            fontSize: 12,
            color: C.dim,
          }}
        >
          SCAN TELEMETRY LOG
        </div>
        <div
          ref={logRef}
          style={{
            maxHeight: 260,
            overflowY: "auto",
            padding: 16,
            fontFamily: "JetBrains Mono",
            fontSize: 12,
            lineHeight: 1.6,
          }}
        >
          {(scanData?.logs || []).map((l, i) => (
            <div
              key={i}
              style={{ color: l.message?.includes("ERROR") ? C.red : C.text }}
            >
              {l.timestamp ? new Date(l.timestamp).toLocaleTimeString() : "--"}{" "}
              {l.message}
            </div>
          ))}
        </div>
      </Card>

      <Card style={{ padding: 24 }}>
        <h3 style={{ fontFamily: "Orbitron", color: C.orange, marginTop: 0 }}>
          <PressureText glow={C.orange}>FLEET SCAN</PressureText>
        </h3>
        <div
          style={{
            color: C.dim,
            fontFamily: "JetBrains Mono",
            fontSize: 11,
            marginBottom: 8,
          }}
        >
          Paste multiple domains (new line or comma) to launch a single
          coordinated scan run.
        </div>
        <textarea
          value={batch}
          onChange={(e) => setBatch(e.target.value)}
          rows={6}
          placeholder={[
            "example.com",
            "api.example.com",
            "secure.example.org",
            "portal.example.net",
          ].join("\n")}
          style={{
            width: "100%",
            boxSizing: "border-box",
            borderRadius: 12,
            border: `1px solid rgba(185,152,112,0.35)`,
            background: "rgba(185,152,112,0.08)",
            color: C.text,
            padding: 12,
            fontFamily: "JetBrains Mono",
          }}
        />
        <div
          style={{ display: "flex", gap: 8, marginTop: 10, flexWrap: "wrap" }}
        >
          <Btn onClick={launchBatch} disabled={!batch.trim() || polling}>
            LAUNCH BATCH
          </Btn>
          <Btn onClick={() => setBatch(domain.trim() ? domain.trim() : "")}>
            USE ACTIVE DOMAIN
          </Btn>
          <Btn onClick={() => setBatch("")}>CLEAR</Btn>
        </div>
        <div
          style={{
            marginTop: 10,
            display: "grid",
            gap: 8,
            border: `1px solid ${C.border}`,
            borderRadius: 12,
            padding: 10,
            background: "rgba(132,170,208,0.07)",
          }}
        >
          {fleetAggregate && fleetAggregate.total > 0 && (
            <div
              style={{
                border: `1px solid rgba(216,181,108,0.52)`,
                background:
                  "linear-gradient(135deg, rgba(233,206,147,0.34) 0%, rgba(255,245,225,0.24) 44%, rgba(233,206,147,0.2) 100%)",
                borderRadius: 12,
                padding: 12,
                boxShadow: "0 10px 24px rgba(110,87,42,0.16)",
                backdropFilter: "blur(8px)",
              }}
            >
              <div
                style={{
                  fontFamily: "Orbitron",
                  color: "#9f7423",
                  fontSize: 12,
                  marginBottom: 8,
                }}
              >
                Fleet Batch Live Progress
              </div>
              <div
                style={{
                  height: 10,
                  borderRadius: 999,
                  overflow: "hidden",
                  background: "rgba(255,255,255,0.4)",
                  border: "1px solid rgba(216,181,108,0.35)",
                  marginBottom: 8,
                }}
              >
                <div
                  style={{
                    width: `${Math.max(0, Math.min(100, Number(fleetAggregate.progressPct || 0)))}%`,
                    height: "100%",
                    background:
                      "linear-gradient(90deg, rgba(232,192,105,0.95), rgba(196,142,46,0.92))",
                    transition: "width 220ms ease",
                  }}
                />
              </div>
              <div
                style={{
                  color: "#7a6535",
                  fontFamily: "JetBrains Mono",
                  fontSize: 10,
                  lineHeight: 1.55,
                }}
              >
                Total: {fleetAggregate.total} | Completed: {fleetAggregate.completed} | Running: {fleetAggregate.running} | Queued: {fleetAggregate.queued} | Failed: {fleetAggregate.failed} | Progress: {fleetAggregate.progressPct.toFixed(2)}%
              </div>
              <div style={{ marginTop: 8, display: "flex", justifyContent: "flex-end" }}>
                <Btn onClick={() => setShowFleetStatusModal(true)}>
                  VIEW ALL {Math.max(0, Number(fleetAggregate?.total || fleetBatchScans.length || 0))} STATUSES
                </Btn>
              </div>
            </div>
          )}
        </div>

        {fleetScans.length > 0 && (
          <div
            style={{
              marginTop: 16,
              borderTop: `1px solid ${C.border}`,
              paddingTop: 14,
            }}
          >
            <div
              style={{
                fontFamily: "Orbitron",
                color: C.cyan,
                fontSize: 14,
                marginBottom: 10,
              }}
            >
              <PressureText glow={C.cyan}>FLEET LIVE BOARD</PressureText>
            </div>
            {autoRoutedFleetScans.length > 0 && (
              <div
                style={{
                  marginBottom: 12,
                  borderRadius: 12,
                  border: `1px solid ${C.orange}66`,
                  background: "rgba(185,152,112,0.12)",
                  padding: 12,
                }}
              >
                <div
                  style={{
                    fontFamily: "Orbitron",
                    color: C.orange,
                    fontSize: 12,
                    marginBottom: 6,
                  }}
                >
                  <PressureText glow={C.orange}>
                    AUTO-ROUTED DOMAINS
                  </PressureText>
                </div>
                <div
                  style={{
                    color: C.dim,
                    fontFamily: "JetBrains Mono",
                    fontSize: 10,
                    marginBottom: 8,
                  }}
                >
                  These domains were routed to{" "}
                  {scanModelUiLabel(
                    currentMode === "banking" ? "general" : "banking",
                  )}{" "}
                  mode by backend policy and will surface under their respective
                  mode tabs.
                </div>
                <div style={{ display: "grid", gap: 6 }}>
                  {autoRoutedFleetScans.map((item) => (
                    <div
                      key={`auto-${item.scan_id}`}
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        gap: 8,
                        alignItems: "center",
                        fontFamily: "JetBrains Mono",
                        fontSize: 11,
                      }}
                    >
                      <span style={{ color: C.text }}>{item.domain}</span>
                      <span style={{ color: C.orange }}>
                        mode: {scanModelUiLabel(item.scan_model || scanModel)}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            <div style={{ display: "grid", gap: 10 }}>
              {inModeFleetScans.map((item) => (
                <div
                  key={item.scan_id}
                  style={{
                    borderRadius: 12,
                    border: `1px solid ${C.border}`,
                    background: "rgba(132,170,208,0.06)",
                    padding: 12,
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      gap: 10,
                      flexWrap: "wrap",
                    }}
                  >
                    <div>
                      <div
                        style={{
                          fontFamily: "JetBrains Mono",
                          fontSize: 12,
                          color: C.text,
                        }}
                      >
                        {item.domain}
                      </div>
                      <div
                        style={{
                          fontFamily: "JetBrains Mono",
                          fontSize: 10,
                          color: C.dim,
                        }}
                      >
                        {item.scan_id} {item.reused ? "- reused" : ""} | mode:{" "}
                        {scanModelUiLabel(item.scan_model || scanModel)}
                      </div>
                    </div>
                    <div
                      style={{ display: "flex", alignItems: "center", gap: 8 }}
                    >
                      <span
                        style={{
                          fontFamily: "JetBrains Mono",
                          fontSize: 11,
                          color:
                            item.status === "failed"
                              ? C.red
                              : item.status === "completed"
                                ? C.green
                                : C.cyan,
                        }}
                      >
                        {String(item.status || "queued").toUpperCase()}
                      </span>
                      <ClayNumber
                        value={`${Number(item.progress || 0)}%`}
                        tone={
                          item.status === "failed"
                            ? C.red
                            : item.status === "completed"
                              ? C.green
                              : C.cyan
                        }
                        size={10}
                        minWidth={62}
                      />
                      <Btn onClick={() => openFleetScan(item)}>OPEN</Btn>
                    </div>
                  </div>
                  <div
                    style={{
                      marginTop: 8,
                      height: 8,
                      borderRadius: 999,
                      background: "rgba(0,0,0,0.12)",
                      overflow: "hidden",
                    }}
                  >
                    <div
                      style={{
                        width: `${Math.max(0, Math.min(100, Number(item.progress || 0)))}%`,
                        height: "100%",
                        borderRadius: 999,
                        background:
                          item.status === "failed"
                            ? C.red
                            : item.status === "completed"
                              ? C.green
                              : C.cyan,
                        transition: "width 180ms ease",
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {showFleetStatusModal && (
          <div
            role="dialog"
            aria-modal="true"
            style={{
              position: "fixed",
              inset: 0,
              background: "rgba(26,20,9,0.48)",
              display: "grid",
              placeItems: "center",
              zIndex: 1200,
              padding: 14,
            }}
            onClick={() => setShowFleetStatusModal(false)}
          >
            <div
              onClick={(e) => e.stopPropagation()}
              style={{
                width: "min(940px, 100%)",
                maxHeight: "86vh",
                borderRadius: 16,
                border: "1px solid rgba(216,181,108,0.52)",
                background:
                  "linear-gradient(145deg, rgba(238,214,162,0.35) 0%, rgba(255,248,236,0.28) 44%, rgba(238,214,162,0.2) 100%)",
                boxShadow: "0 26px 60px rgba(90,70,26,0.28)",
                backdropFilter: "blur(12px)",
                overflow: "hidden",
                display: "grid",
                gridTemplateRows: "auto auto 1fr",
              }}
            >
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  gap: 10,
                  padding: "12px 14px",
                  borderBottom: "1px solid rgba(216,181,108,0.35)",
                }}
              >
                <div style={{ fontFamily: "Orbitron", color: "#8a641f", fontSize: 13 }}>
                  Fleet Status Board (All Domains)
                </div>
                <Btn onClick={() => setShowFleetStatusModal(false)}>CLOSE</Btn>
              </div>

              <div
                style={{
                  padding: "10px 14px",
                  borderBottom: "1px solid rgba(216,181,108,0.25)",
                  display: "grid",
                  gridTemplateColumns: "1fr auto",
                  gap: 8,
                }}
              >
                <input
                  value={fleetStatusQuery}
                  onChange={(e) => setFleetStatusQuery(e.target.value)}
                  placeholder="Search domain or scan id"
                  style={{
                    borderRadius: 10,
                    border: "1px solid rgba(179,143,75,0.45)",
                    background: "rgba(255,255,255,0.46)",
                    color: "#4e3f1f",
                    padding: "9px 10px",
                    fontFamily: "JetBrains Mono",
                    fontSize: 11,
                  }}
                />
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap", justifyContent: "flex-end" }}>
                  {fleetStatusOptions.map((opt) => (
                    <button
                      key={opt}
                      onClick={() => setFleetStatusFilter(opt)}
                      style={{
                        borderRadius: 999,
                        border:
                          fleetStatusFilter === opt
                            ? "1px solid rgba(172,122,36,0.95)"
                            : "1px solid rgba(172,122,36,0.35)",
                        background:
                          fleetStatusFilter === opt
                            ? "rgba(219,179,101,0.42)"
                            : "rgba(255,255,255,0.34)",
                        color: "#6a511f",
                        padding: "6px 10px",
                        fontFamily: "JetBrains Mono",
                        fontSize: 10,
                        cursor: "pointer",
                      }}
                    >
                      {opt.toUpperCase()}
                    </button>
                  ))}
                </div>
              </div>

              <div style={{ overflowY: "auto", padding: 12, display: "grid", gap: 8 }}>
                <div style={{ color: "#7a6535", fontFamily: "JetBrains Mono", fontSize: 10 }}>
                  Showing {filteredFleetStatuses.length} of {fleetBatchScans.length}
                </div>
                {filteredFleetStatuses.map((item) => {
                  const state = String(item.status || "queued").toLowerCase();
                  const stateColor =
                    state === "completed"
                      ? C.green
                      : state === "failed"
                        ? C.red
                        : state === "running"
                          ? C.cyan
                          : C.yellow;
                  return (
                    <div
                      key={`modal-${item.scan_id}`}
                      style={{
                        borderRadius: 10,
                        border: "1px solid rgba(176,139,75,0.32)",
                        background: "rgba(255,255,255,0.32)",
                        padding: "10px 11px",
                        display: "grid",
                        gap: 6,
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", gap: 8, flexWrap: "wrap" }}>
                        <div style={{ color: "#453617", fontFamily: "JetBrains Mono", fontSize: 11 }}>
                          {item.domain}
                        </div>
                        <div style={{ color: stateColor, fontFamily: "JetBrains Mono", fontSize: 10 }}>
                          {state.toUpperCase()} | {Number(item.progress || 0)}%
                        </div>
                      </div>
                      <div style={{ color: "#6f5a2a", fontFamily: "JetBrains Mono", fontSize: 10 }}>
                        {item.scan_id} | mode: {scanModelUiLabel(item.scan_model || scanModel)}
                      </div>
                      <div style={{ height: 6, borderRadius: 999, overflow: "hidden", background: "rgba(108,85,38,0.14)" }}>
                        <div
                          style={{
                            width: `${Math.max(0, Math.min(100, Number(item.progress || 0)))}%`,
                            height: "100%",
                            borderRadius: 999,
                            background: stateColor,
                            transition: "width 180ms ease",
                          }}
                        />
                      </div>
                    </div>
                  );
                })}
                {!filteredFleetStatuses.length && (
                  <div style={{ color: "#7a6535", fontFamily: "JetBrains Mono", fontSize: 11 }}>
                    No statuses matched your search/filter.
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}

function AssetMapTab({ scanModel = "general" }) {
  const [scans, setScans] = useState([]);
  const [assets, setAssets] = useState([]);
  const [selected, setSelected] = useState(null);
  useEffect(() => {
    fetch(`${API}/api/scans?${scanModelParam(scanModel)}`)
      .then((r) => r.json())
      .then((d) =>
        setScans(uniqueCompletedScansByDomain(filterRowsByMode(d, scanModel))),
      );
  }, [scanModel]);
  const load = async (s) => {
    setSelected(s.scan_id);
    const r = await fetch(`${API}/api/scan/${s.scan_id}`);
    const d = await r.json();
    setAssets(d.assets || []);
  };
  const vpnSignalTags = (signals) => {
    const tags = [];
    if (signals?.udp_500) tags.push("UDP/500");
    if (signals?.udp_4500) tags.push("UDP/4500");
    if (signals?.sstp) tags.push("SSTP");
    return tags;
  };
  const domainOptions = useMemo(
    () =>
      (scans || []).map((s) => ({
        value: s.scan_id,
        label: s.domain,
      })),
    [scans],
  );
  return (
    <div style={{ display: "grid", gap: 16 }}>
      <Card style={{ padding: 18 }}>
        <TabModeAccent scanModel={scanModel} tabLabel="DISCOVERED ASSET MAP" />
        <TabGuide
          title="This tab explains discovered infrastructure"
          subtitle="Use it to inspect asset inventory, risk labels, and where exposure is concentrated in the selected mode."
          bullets={[
            "Host and service mapping",
            "Risk score per asset",
            "VPN signal hints",
          ]}
        />
        <LiquidSearchSelect
          value={selected || ""}
          onChange={(scanId) => {
            const picked = scans.find((s) => String(s.scan_id) === String(scanId));
            if (picked) load(picked);
          }}
          options={domainOptions}
          buttonLabel="Select bank/domain"
          searchPlaceholder="Search domain..."
          emptyLabel="No scanned domains match your search"
          minWidth={420}
        />
        <div
          style={{
            marginTop: 8,
            color: C.dim,
            fontFamily: "JetBrains Mono",
            fontSize: 10,
          }}
        >
          Pick a domain from the searchable liquid selector.
        </div>
      </Card>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fill,minmax(260px,1fr))",
          gap: 14,
        }}
      >
        {assets.map((a) => {
          const vpnTags = vpnSignalTags(a.vpn_signals);
          return (
            <Card key={a.id} style={{ padding: 16 }}>
              <div style={{ display: "flex", justifyContent: "space-between" }}>
                <div>
                  <div
                    style={{
                      color: C.text,
                      fontFamily: "JetBrains Mono",
                      fontSize: 12,
                    }}
                  >
                    {a.hostname}
                  </div>
                  <div style={{ color: C.dim, fontSize: 10 }}>
                    {a.asset_type}
                  </div>
                </div>
                <ClayNumber
                  value={Number(a.risk_score || 0).toFixed(0)}
                  tone={riskColor(a.risk_score)}
                  size={16}
                  minWidth={62}
                />
              </div>
              <div
                style={{
                  marginTop: 6,
                  color: C.dim,
                  fontFamily: "JetBrains Mono",
                  fontSize: 10,
                }}
              >
                Risk meaning: {Number(a.risk_score || 0).toFixed(0)}/100 (
                {Number(a.risk_score || 0) >= 61
                  ? "high"
                  : Number(a.risk_score || 0) >= 36
                    ? "watch"
                    : "safer"}
                ).
              </div>
              {vpnTags.length > 0 && (
                <div
                  style={{
                    marginTop: 8,
                    color: C.orange,
                    fontFamily: "JetBrains Mono",
                    fontSize: 10,
                  }}
                >
                  VPN signals: {vpnTags.join(" | ")}
                </div>
              )}
              <div style={{ marginTop: 10 }}>
                <Badge status={a.label} />
              </div>
            </Card>
          );
        })}
      </div>
    </div>
  );
}

function CryptoTab({ scanModel = "general" }) {
  const [scans, setScans] = useState([]);
  const [findings, setFindings] = useState([]);
  const [radar, setRadar] = useState([]);
  const [selectedScanId, setSelectedScanId] = useState("");
  useEffect(() => {
    fetch(`${API}/api/scans?${scanModelParam(scanModel)}`)
      .then((r) => r.json())
      .then((d) =>
        setScans(uniqueCompletedScansByDomain(filterRowsByMode(d, scanModel))),
      );
  }, [scanModel]);
  const load = async (scanId) => {
    setSelectedScanId(scanId);
    const r = await fetch(`${API}/api/scan/${scanId}/findings`);
    const d = await r.json();
    const list = d.findings || [];
    setFindings(list);
    const cat = {
      key_exchange: 0,
      authentication: 0,
      symmetric: 0,
      certificate: 0,
    };
    const cnt = {
      key_exchange: 0,
      authentication: 0,
      symmetric: 0,
      certificate: 0,
    };
    list.forEach((f) => {
      if (cat[f.category] !== undefined) {
        cat[f.category] +=
          { CRITICAL: 0, WARNING: 50, ACCEPTABLE: 80, SAFE: 100 }[f.status] ||
          0;
        cnt[f.category] += 1;
      }
    });
    setRadar([
      {
        axis: "Key Exchange",
        value: cnt.key_exchange ? cat.key_exchange / cnt.key_exchange : 0,
      },
      {
        axis: "Auth",
        value: cnt.authentication ? cat.authentication / cnt.authentication : 0,
      },
      {
        axis: "Symmetric",
        value: cnt.symmetric ? cat.symmetric / cnt.symmetric : 0,
      },
      {
        axis: "Certificate",
        value: cnt.certificate ? cat.certificate / cnt.certificate : 0,
      },
      { axis: "Protocol", value: 40 },
      { axis: "Hash", value: 35 },
    ]);
  };
  const domainOptions = useMemo(
    () =>
      (scans || []).map((s) => ({
        value: s.scan_id,
        label: s.domain,
      })),
    [scans],
  );
  return (
    <div style={{ display: "grid", gap: 16 }}>
      <Card style={{ padding: 18 }}>
        <TabModeAccent
          scanModel={scanModel}
          tabLabel="CRYPTO POSTURE ANALYZER"
        />
        <TabGuide
          title="This tab analyzes cryptographic strength"
          subtitle="Use it to inspect algorithm choices, findings by category, and readiness radar for the selected domain."
          bullets={[
            "Finding-by-finding crypto review",
            "Radar posture view",
            "Status badges for weak/strong controls",
          ]}
        />
        <LiquidSearchSelect
          value={selectedScanId}
          onChange={(scanId) => load(scanId)}
          options={domainOptions}
          buttonLabel="Select bank/domain"
          searchPlaceholder="Search domain..."
          emptyLabel="No scanned domains match your search"
          minWidth={420}
        />
        <div
          style={{
            marginTop: 8,
            color: C.dim,
            fontFamily: "JetBrains Mono",
            fontSize: 10,
          }}
        >
          Pick a domain from the searchable liquid selector.
        </div>
      </Card>
      {radar.length > 0 && (
        <Card style={{ padding: 20 }}>
          {HAS_RECHARTS ? (
            <ResponsiveContainer width="100%" height={280}>
              <RadarChart data={radar}>
                <PolarGrid stroke={C.border} />
                <PolarAngleAxis
                  dataKey="axis"
                  tick={{ fill: C.dim, fontSize: 10 }}
                />
                <Radar
                  dataKey="value"
                  stroke={C.cyan}
                  fill={C.cyan}
                  fillOpacity={0.15}
                />
              </RadarChart>
            </ResponsiveContainer>
          ) : (
            <RadarFallback data={radar} color={C.cyan} />
          )}
        </Card>
      )}
      <Card style={{ padding: 0, overflowX: "auto" }}>
        <table
          style={{
            width: "100%",
            minWidth: 980,
            borderCollapse: "collapse",
            fontFamily: "JetBrains Mono",
            fontSize: 12,
          }}
        >
          <thead>
            <tr style={{ borderBottom: `1px solid ${C.border}` }}>
              <th style={{ textAlign: "left", padding: 10, color: C.dim }}>
                Category
              </th>
              <th style={{ textAlign: "left", padding: 10, color: C.dim }}>
                Algorithm
              </th>
              <th style={{ textAlign: "left", padding: 10, color: C.dim }}>
                Primitive
              </th>
              <th style={{ textAlign: "left", padding: 10, color: C.dim }}>
                OID
              </th>
              <th style={{ textAlign: "left", padding: 10, color: C.dim }}>
                Classical Level
              </th>
              <th style={{ textAlign: "left", padding: 10, color: C.dim }}>
                Key State
              </th>
              <th style={{ textAlign: "left", padding: 10, color: C.dim }}>
                CERT-IN Map
              </th>
              <th style={{ textAlign: "left", padding: 10, color: C.dim }}>
                Status
              </th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <tr key={f.id} style={{ borderBottom: `1px solid ${C.border}` }}>
                <td style={{ padding: 10, color: C.dim }}>{f.category}</td>
                <td style={{ padding: 10, color: C.text }}>
                  {f.algorithm_name || f.algorithm}
                </td>
                <td style={{ padding: 10, color: C.text }}>
                  {f.primitive || "-"}
                </td>
                <td style={{ padding: 10, color: C.dim }}>{f.oid || "-"}</td>
                <td style={{ padding: 10, color: C.text }}>
                  {f.classical_security_level || "-"}
                </td>
                <td style={{ padding: 10, color: C.text }}>
                  {f.key_state || "-"}
                </td>
                <td style={{ padding: 10, color: C.dim }}>
                  {f.cert_in_profile || "-"}
                </td>
                <td style={{ padding: 10 }}>
                  <Badge status={f.status} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
}

function CBOMTab({ scanModel = "general" }) {
  const [scans, setScans] = useState([]);
  const [cbom, setCbom] = useState(null);
  const [selectedScanId, setSelectedScanId] = useState("");
  const [selectedDomain, setSelectedDomain] = useState("");
  const [downloadingAll, setDownloadingAll] = useState(false);
  const [fleetLossPct, setFleetLossPct] = useState(1.2);
  const [exportingFleetCsv, setExportingFleetCsv] = useState(false);
  const [exportingAllScenarios, setExportingAllScenarios] = useState(false);
  const [scenarioExportLog, setScenarioExportLog] = useState([]);
  const [scanPickerQuery, setScanPickerQuery] = useState("");
  const [scanPickerIndex, setScanPickerIndex] = useState(-1);
  const [exportFeedback, setExportFeedback] = useState("");

  useEffect(() => {
    fetch(`${API}/api/scans?${scanModelParam(scanModel)}`)
      .then((r) => r.json())
      .then((d) =>
        setScans(uniqueCompletedScansByDomain(filterRowsByMode(d, scanModel))),
      );
  }, [scanModel]);

  const safeName = (value) =>
    String(value || "cbom")
      .replace(/[^a-z0-9._-]+/gi, "_")
      .toLowerCase();

  const downloadJsonFile = (filename, payload) => {
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: "application/json;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const downloadTextFile = (filename, text, mime = "text/plain;charset=utf-8") => {
    const blob = new Blob([text], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const cbomToCsvRows = (cbomData, scanId, domain) => {
    const components = Array.isArray(cbomData?.components)
      ? cbomData.components
      : [];
    return components.map((comp) => {
      const props = Object.fromEntries(
        (comp?.properties || []).map((p) => [String(p?.name || ""), String(p?.value || "")]),
      );
      return {
        scan_id: scanId,
        domain,
        asset_name: comp?.name || "",
        asset_type: comp?.cryptoProperties?.assetType || "",
        protocol: comp?.cryptoProperties?.protocolProperties?.type || "",
        tls_version: comp?.cryptoProperties?.protocolProperties?.version || "",
        key_exchange_algorithm:
          props["key-exchange-algorithm"] ||
          comp?.cryptoProperties?.protocolProperties?.keyExchangeAlgorithm ||
          "",
        primary_cipher_suite:
          props["primary-cipher-suite"] ||
          comp?.cryptoProperties?.protocolProperties?.primaryCipherSuite ||
          "",
        hndl_risk_score: props["hndl-risk-score"] || "",
        label: props.label || "",
        hndl_label: props["hndl-label"] || "",
        quantum_safe: props["quantum-safe"] || "",
        nist_fips_203: props["nist-fips-203-signal-detected"] || "",
        nist_fips_204: props["nist-fips-204-signal-detected"] || "",
        nist_fips_205: props["nist-fips-205-signal-detected"] || "",
        tls_scan_error: props["tls-scan-error"] || "",
      };
    });
  };

  const rowsToCsv = (rows) => {
    if (!rows.length) return "";
    const headers = Object.keys(rows[0]);
    const esc = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const body = rows.map((row) => headers.map((h) => esc(row[h])).join(","));
    return [headers.join(","), ...body].join("\n");
  };

  const completedDomains = useMemo(
    () =>
      Array.from(
        new Set(
          (scans || [])
            .map((s) => String(s?.domain || "").trim().toLowerCase())
            .filter(Boolean),
        ),
      ),
    [scans],
  );

  const filteredScans = useMemo(() => {
    const q = String(scanPickerQuery || "").trim().toLowerCase();
    if (!q) return scans;
    return scans.filter((s) =>
      String(s?.domain || "").toLowerCase().includes(q),
    );
  }, [scans, scanPickerQuery]);

  useEffect(() => {
    if (!filteredScans.length) {
      setScanPickerIndex(-1);
      return;
    }
    setScanPickerIndex((prev) => {
      if (prev < 0) return 0;
      if (prev >= filteredScans.length) return filteredScans.length - 1;
      return prev;
    });
  }, [filteredScans]);

  const onScanPickerKeyDown = (e) => {
    if (!filteredScans.length) return;

    if (e.key === "ArrowDown") {
      e.preventDefault();
      setScanPickerIndex((prev) => {
        if (prev < 0) return 0;
        return Math.min(prev + 1, filteredScans.length - 1);
      });
      return;
    }

    if (e.key === "ArrowUp") {
      e.preventDefault();
      setScanPickerIndex((prev) => {
        if (prev < 0) return filteredScans.length - 1;
        return Math.max(prev - 1, 0);
      });
      return;
    }

    if (e.key === "Enter") {
      e.preventDefault();
      const idx = scanPickerIndex >= 0 ? scanPickerIndex : 0;
      const picked = filteredScans[idx];
      if (picked) {
        load(picked.scan_id, picked.domain);
      }
      return;
    }

    if (e.key === "Escape") {
      e.preventDefault();
      setScanPickerQuery("");
      setScanPickerIndex(filteredScans.length ? 0 : -1);
    }
  };

  const downloadBlobFile = (filename, blob) => {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1200);
  };

  const exportFleetSimulationCsv = async () => {
    const domains = completedDomains;
    if (!domains.length) return;

    setExportingFleetCsv(true);
    setExportFeedback("");
    try {
      const resp = await fetch(`${API}/api/pqc/fleet-export.csv`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          domains,
          loss_rate: Number(fleetLossPct) / 100,
        }),
      });
      if (!resp.ok) {
        const errText = await resp.text();
        throw new Error(errText || `HTTP ${resp.status}`);
      }
      const blob = await resp.blob();
      const stamp = new Date().toISOString().replace(/[:.]/g, "-");
      downloadBlobFile(
        `fleet-simulation-${fleetLossPct.toFixed(1)}pct-${stamp}.csv`,
        blob,
      );
      setExportFeedback("Simulation CSV downloaded successfully.");
    } catch (err) {
      setExportFeedback(`Simulation CSV export failed: ${String(err)}`);
    } finally {
      setExportingFleetCsv(false);
    }
  };

  const exportAllScenarioCsvs = async () => {
    const domains = completedDomains;
    if (!domains.length) return;

    const scenarios = [
      { name: "scenario-a-fiber", lossPct: 0.1 },
      { name: "scenario-b-4g", lossPct: 1.2 },
      { name: "scenario-c-rural", lossPct: 3.5 },
    ];

    setExportingAllScenarios(true);
    setExportFeedback("");
    setScenarioExportLog([]);
    try {
      const exported = [];
      const combinedRows = [];
      let header = "";
      for (const scenario of scenarios) {
        const resp = await fetch(`${API}/api/pqc/fleet-export.csv`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            domains,
            loss_rate: scenario.lossPct / 100,
          }),
        });
        if (!resp.ok) {
          const errText = await resp.text();
          throw new Error(errText || `HTTP ${resp.status}`);
        }
        const csvText = await resp.text();
        const lines = String(csvText || "")
          .split(/\r?\n/)
          .filter(Boolean);
        if (!lines.length) continue;
        if (!header) {
          header = `scenario,loss_pct,${lines[0]}`;
        }
        for (const line of lines.slice(1)) {
          combinedRows.push(`${scenario.name},${scenario.lossPct.toFixed(1)},${line}`);
        }
        const now = new Date();
        const fileName = `fleet-simulation-${scenario.name}-${scenario.lossPct.toFixed(1)}pct.csv`;

        exported.push({
          scenario: scenario.name,
          lossPct: scenario.lossPct,
          fileName,
          exportedAt: now.toISOString(),
        });
      }
      if (!header || !combinedRows.length) {
        throw new Error("No scenario rows returned by export endpoint.");
      }
      const stamp = new Date().toISOString().replace(/[:.]/g, "-");
      const combinedCsv = `${header}\n${combinedRows.join("\n")}`;
      downloadTextFile(
        `fleet-simulation-all-scenarios-${stamp}.csv`,
        combinedCsv,
        "text/csv;charset=utf-8",
      );
      setScenarioExportLog(exported);
      setExportFeedback("All scenario CSV data exported as one combined file.");
    } catch (err) {
      setScenarioExportLog([]);
      setExportFeedback(`Scenario export failed: ${String(err)}`);
    } finally {
      setExportingAllScenarios(false);
    }
  };

  const load = async (id, domain) => {
    setSelectedScanId(id);
    setSelectedDomain(domain || "");
    const r = await fetch(`${API}/api/scan/${id}/cbom`);
    if (!r.ok) return setCbom(null);
    setCbom(await r.json());
  };

  const downloadSelectedCbom = () => {
    if (!cbom || !selectedScanId) return;
    const base = safeName(selectedDomain || selectedScanId);
    downloadJsonFile(`cbom-${base}.json`, cbom);
  };

  const downloadSelectedCbomCsv = () => {
    if (!cbom || !selectedScanId) return;
    const base = safeName(selectedDomain || selectedScanId);
    const rows = cbomToCsvRows(cbom, selectedScanId, selectedDomain || selectedScanId);
    const csvText = rowsToCsv(rows);
    if (!csvText) return;
    downloadTextFile(`cbom-${base}.csv`, csvText, "text/csv;charset=utf-8");
  };

  const downloadCombinedCbom = async () => {
    if (!scans.length || downloadingAll) return;
    setDownloadingAll(true);
    try {
      const items = [];
      const failed = [];

      for (const s of scans) {
        try {
          const r = await fetch(`${API}/api/scan/${s.scan_id}/cbom`);
          if (!r.ok) {
            failed.push({
              scan_id: s.scan_id,
              domain: s.domain,
              reason: `HTTP ${r.status}`,
            });
            continue;
          }
          const data = await r.json();
          items.push({
            scan_id: s.scan_id,
            domain: s.domain,
            scan_model: s.scan_model || scanModel,
            cbom: data,
          });
        } catch (err) {
          failed.push({
            scan_id: s.scan_id,
            domain: s.domain,
            reason: String(err),
          });
        }
      }

      const payload = {
        exported_at_utc: new Date().toISOString(),
        scan_model: scanModel,
        total_scans_considered: scans.length,
        total_cbom_exported: items.length,
        failed_exports: failed,
        banks: items,
      };

      downloadJsonFile("cbom-all-scanned-banks.json", payload);
    } finally {
      setDownloadingAll(false);
    }
  };

  const downloadCombinedCbomCsv = async () => {
    if (!scans.length || downloadingAll) return;
    setDownloadingAll(true);
    try {
      const rows = [];
      for (const s of scans) {
        try {
          const r = await fetch(`${API}/api/scan/${s.scan_id}/cbom`);
          if (!r.ok) continue;
          const data = await r.json();
          rows.push(...cbomToCsvRows(data, s.scan_id, s.domain));
        } catch (_err) {}
      }
      const csvText = rowsToCsv(rows);
      if (!csvText) return;
      downloadTextFile("cbom-all-scanned-banks.csv", csvText, "text/csv;charset=utf-8");
    } finally {
      setDownloadingAll(false);
    }
  };

  const cbomText = (cbom ? JSON.stringify(cbom) : "").toUpperCase();
  const fipsRows = [
    {
      standard: "FIPS 203",
      algorithm: "ML-KEM (Kyber)",
      matched: /ML-KEM|MLKEM|KYBER|FIPS 203/.test(cbomText),
      requirement: "PQC Key Encapsulation",
    },
    {
      standard: "FIPS 204",
      algorithm: "ML-DSA (Dilithium)",
      matched: /ML-DSA|MLDSA|DILITHIUM|FIPS 204/.test(cbomText),
      requirement: "PQC Digital Signatures",
    },
    {
      standard: "FIPS 205",
      algorithm: "SLH-DSA (SPHINCS+)",
      matched: /SLH-DSA|SLHDSA|SPHINCS|FIPS 205/.test(cbomText),
      requirement: "Stateless Hash Signatures",
    },
  ];
  return (
    <div style={{ display: "grid", gap: 14 }}>
      <Card style={{ padding: 16 }}>
        <TabModeAccent scanModel={scanModel} tabLabel="CBOM XPORT HUB" />
        <TabGuide
          title="This tab provides software/crypto bill of materials"
          subtitle="Use it to validate NIST PQC mapping and export CBOM content for audit and compliance review."
          bullets={[
            "FIPS 203/204/205 presence checks",
            "Structured CBOM JSON output",
            "Compliance-friendly evidence",
          ]}
        />
        <details className="cbom-picker-shell" open>
          <summary className="cbom-picker-summary">
            Select scanned bank/domain ({scans.length})
          </summary>
          <div className="cbom-picker-body">
            <input
              type="text"
              value={scanPickerQuery}
              onChange={(e) => setScanPickerQuery(e.target.value)}
              onKeyDown={onScanPickerKeyDown}
              placeholder="Search bank domain..."
              className="cbom-picker-search"
            />
            <div className="cbom-picker-results qh-soft-scroll">
              {filteredScans.length ? (
                filteredScans.map((s, idx) => (
                  <button
                    key={s.scan_id}
                    onClick={() => load(s.scan_id, s.domain)}
                    onMouseEnter={() => setScanPickerIndex(idx)}
                    className="cbom-picker-item"
                    aria-selected={idx === scanPickerIndex}
                    style={{
                      borderColor:
                        selectedScanId === s.scan_id
                          ? "rgba(30,128,93,0.65)"
                          : "rgba(157,141,90,0.35)",
                      background:
                        selectedScanId === s.scan_id
                          ? "linear-gradient(125deg, rgba(237,214,151,0.42), rgba(95,181,142,0.22))"
                          : idx === scanPickerIndex
                            ? "linear-gradient(125deg, rgba(255,238,178,0.52), rgba(128,214,176,0.26))"
                            : "rgba(255,250,232,0.48)",
                    }}
                  >
                    {s.domain}
                  </button>
                ))
              ) : (
                <div className="cbom-picker-empty">No scanned domains match your search.</div>
              )}
            </div>
            <div className="cbom-picker-selected">
              Selected: {selectedDomain || "None"}
            </div>
          </div>
        </details>
        <div
          style={{ marginTop: 10, display: "flex", flexWrap: "wrap", gap: 8 }}
        >
          <Btn
            onClick={downloadSelectedCbom}
            disabled={!cbom || !selectedScanId}
          >
            DOWNLOAD SELECTED BANK CBOM JSON
          </Btn>
          <Btn
            onClick={downloadSelectedCbomCsv}
            disabled={!cbom || !selectedScanId}
          >
            DOWNLOAD SELECTED BANK CBOM CSV
          </Btn>
          <Btn
            onClick={downloadCombinedCbom}
            disabled={!scans.length || downloadingAll}
          >
            {downloadingAll
              ? "PREPARING COMBINED CBOM..."
              : "DOWNLOAD COMBINED ALL SCANNED BANKS CBOM JSON"}
          </Btn>
          <Btn
            onClick={downloadCombinedCbomCsv}
            disabled={!scans.length || downloadingAll}
          >
            {downloadingAll
              ? "PREPARING COMBINED CBOM CSV..."
              : "DOWNLOAD COMBINED ALL SCANNED BANKS CBOM CSV"}
          </Btn>
          <Btn
            onClick={exportFleetSimulationCsv}
            disabled={!completedDomains.length || exportingFleetCsv}
          >
            {exportingFleetCsv
              ? "EXPORTING SIMULATION CSV..."
              : "EXPORT SIMULATION DATA CSV"}
          </Btn>
          <Btn
            onClick={exportAllScenarioCsvs}
            disabled={!completedDomains.length || exportingAllScenarios}
          >
            {exportingAllScenarios
              ? "EXPORTING SCENARIOS CSV..."
              : "EXPORT ALL SCENARIOS CSV"}
          </Btn>
        </div>
        <div
          className="cbom-liquid-glass"
          style={{
            marginTop: 10,
            display: "grid",
            gap: 8,
            border: "1px solid rgba(149,135,78,0.38)",
            borderRadius: 12,
            padding: 10,
            background:
              "linear-gradient(135deg, rgba(255,248,222,0.56), rgba(180,231,205,0.33))",
          }}
        >
          <div
            style={{
              color: C.dim,
              fontFamily: "JetBrains Mono",
              fontSize: 11,
            }}
          >
            Simulation Packet Loss: {fleetLossPct.toFixed(1)}% (domains source: completed scans in this mode)
          </div>
          <input
            type="range"
            min={0}
            max={8}
            step={0.1}
            value={fleetLossPct}
            onChange={(e) => setFleetLossPct(Number(e.target.value))}
            style={{ width: "100%" }}
          />
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <Btn onClick={() => setFleetLossPct(0.1)}>Scenario A: 0.1%</Btn>
            <Btn onClick={() => setFleetLossPct(1.2)}>Scenario B: 1.2%</Btn>
            <Btn onClick={() => setFleetLossPct(3.5)}>Scenario C: 3.5%</Btn>
          </div>
          {scenarioExportLog.length > 0 && (
            <div
              style={{
                border: `1px solid ${C.green}66`,
                background: "rgba(90,170,120,0.10)",
                borderRadius: 10,
                padding: 10,
                marginTop: 2,
              }}
            >
              <div
                style={{
                  fontFamily: "Orbitron",
                  color: C.green,
                  fontSize: 11,
                  marginBottom: 6,
                }}
              >
                Scenario Export Complete
              </div>
              {scenarioExportLog.map((entry) => (
                <div
                  key={entry.fileName}
                  style={{
                    color: C.dim,
                    fontFamily: "JetBrains Mono",
                    fontSize: 10,
                    lineHeight: 1.45,
                  }}
                >
                  {entry.lossPct.toFixed(1)}% - {entry.fileName} - {new Date(entry.exportedAt).toLocaleString()}
                </div>
              ))}
            </div>
          )}
          {exportFeedback ? (
            <div
              style={{
                border: "1px solid rgba(30,128,93,0.35)",
                background: "rgba(242,255,245,0.62)",
                borderRadius: 10,
                color: "#1f6a4d",
                fontFamily: "JetBrains Mono",
                fontSize: 11,
                padding: "8px 10px",
              }}
            >
              {exportFeedback}
            </div>
          ) : null}
        </div>
        <div
          style={{
            marginTop: 8,
            color: C.dim,
            fontFamily: "JetBrains Mono",
            fontSize: 10,
          }}
        >
          Use the searchable selector above to choose a bank/domain.
        </div>
      </Card>
      <Card style={{ padding: 16 }}>
        <div style={{ fontFamily: "Orbitron", color: C.blue, marginBottom: 8 }}>
          <PressureText glow={C.blue}>NIST PQC Compliance Mapping</PressureText>
        </div>
        <table
          style={{
            width: "100%",
            borderCollapse: "collapse",
            fontFamily: "JetBrains Mono",
            fontSize: 12,
          }}
        >
          <thead>
            <tr style={{ borderBottom: `1px solid ${C.border}` }}>
              <th
                style={{ textAlign: "left", padding: "8px 6px", color: C.dim }}
              >
                Standard
              </th>
              <th
                style={{ textAlign: "left", padding: "8px 6px", color: C.dim }}
              >
                Algorithm Family
              </th>
              <th
                style={{ textAlign: "left", padding: "8px 6px", color: C.dim }}
              >
                Requirement
              </th>
              <th
                style={{ textAlign: "left", padding: "8px 6px", color: C.dim }}
              >
                Observed in CBOM
              </th>
            </tr>
          </thead>
          <tbody>
            {fipsRows.map((r) => (
              <tr
                key={r.standard}
                style={{ borderBottom: `1px solid ${C.border}` }}
              >
                <td style={{ padding: "8px 6px", color: C.text }}>
                  {r.standard}
                </td>
                <td style={{ padding: "8px 6px", color: C.text }}>
                  {r.algorithm}
                </td>
                <td style={{ padding: "8px 6px", color: C.dim }}>
                  {r.requirement}
                </td>
                <td style={{ padding: "8px 6px" }}>
                  <Badge status={r.matched ? "SAFE" : "WARNING"} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
      <Card style={{ padding: 16 }}>
        <pre
          style={{
            margin: 0,
            whiteSpace: "pre-wrap",
            color: C.text,
            fontFamily: "JetBrains Mono",
            fontSize: 12,
          }}
        >
          {cbom
            ? JSON.stringify(cbom, null, 2)
            : "Select a completed scan to view CBOM."}
        </pre>
      </Card>
    </div>
  );
}

function RoadmapTab({ scanModel = "general" }) {
  const [scans, setScans] = useState([]);
  const [selectedScanId, setSelectedScanId] = useState("");
  const [recs, setRecs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState("");

  const loadScans = () => {
    fetch(`${API}/api/scans?${scanModelParam(scanModel)}`)
      .then((r) => r.json())
      .then((d) => {
        const completed = uniqueCompletedScansByDomain(
          filterRowsByMode(d, scanModel),
        );
        setScans(completed);
        setSelectedScanId((prev) => {
          if (prev && completed.some((x) => x.scan_id === prev)) return prev;
          return completed[0]?.scan_id || "";
        });
      })
      .catch(() => {
        setScans([]);
        setSelectedScanId("");
      });
  };

  useEffect(() => {
    loadScans();
    const id = setInterval(loadScans, 8000);
    return () => clearInterval(id);
  }, [scanModel]);

  useEffect(() => {
    if (!selectedScanId) {
      setRecs([]);
      return;
    }
    let alive = true;
    const load = async () => {
      setLoading(true);
      setLoadError("");
      try {
        const r = await fetch(`${API}/api/scan/${selectedScanId}/findings`);
        if (!r.ok) throw new Error("Failed to load findings");
        const d = await r.json();
        if (!alive) return;
        setRecs(
          (d.recommendations || []).filter((x) => String(x?.text || "").trim()),
        );
      } catch {
        if (!alive) return;
        setRecs([]);
        setLoadError(
          "Could not load roadmap recommendations for this scan yet.",
        );
      } finally {
        if (alive) setLoading(false);
      }
    };
    load();
    return () => {
      alive = false;
    };
  }, [selectedScanId]);

  const phases = ["Phase 1", "Phase 2", "Phase 3", "Phase 4"];
  const phaseTitles = {
    "Phase 1": "Stabilize Now",
    "Phase 2": "Harden The Core",
    "Phase 3": "Modernize Crypto",
    "Phase 4": "Future-Proof Governance",
  };
  const phaseGuidance = {
    "Phase 1":
      "Do immediately: fix exploitable items, rotate weak certs, and close exposed services.",
    "Phase 2":
      "Do next: enforce protocol baselines (TLS 1.3+, cipher policy, hardening controls).",
    "Phase 3":
      "Do in modernization sprint: roll out hybrid/PQC-ready key exchange and signature paths.",
    "Phase 4":
      "Do for continuity: automate policy checks, ownership, and periodic drift review.",
  };
  const grouped = Object.fromEntries(phases.map((p) => [p, []]));
  const seenByPhase = Object.fromEntries(phases.map((p) => [p, new Set()]));
  for (const r of recs) {
    const phase = phases.includes(r.phase) ? r.phase : "Phase 1";
    const key = String(r?.text || "")
      .trim()
      .toLowerCase();
    if (!key || seenByPhase[phase].has(key)) continue;
    seenByPhase[phase].add(key);
    grouped[phase].push(r);
  }

  return (
    <div style={{ display: "grid", gap: 14 }}>
      <Card style={{ padding: 16 }}>
        <TabModeAccent scanModel={scanModel} tabLabel="REMEDIATION ROADMAP" />
        <TabGuide
          title="This tab turns findings into phased actions"
          subtitle="Use it to plan immediate, medium, and long-term remediation based on selected scan evidence."
          bullets={[
            "Phase-based action list",
            "De-duplicated recommendation view",
            "Refresh as scans update",
          ]}
        />
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            gap: 10,
            alignItems: "center",
          }}
        >
          <div style={{ fontFamily: "Orbitron", color: C.blue, fontSize: 12 }}>
            <PressureText glow={C.blue}>
              REMEDIATION ROADMAP SOURCE
            </PressureText>
          </div>
          <div
            style={{
              marginLeft: "auto",
              display: "flex",
              gap: 8,
              alignItems: "center",
            }}
          >
            <LiquidSearchSelect
              value={selectedScanId}
              onChange={setSelectedScanId}
              options={(scans || []).map((s) => ({
                value: s.scan_id,
                label: s.domain,
              }))}
              buttonLabel="Select completed scan"
              searchPlaceholder="Search scan domain..."
              emptyLabel="No completed scans match"
              minWidth={280}
            />
            <Btn onClick={loadScans}>REFRESH</Btn>
          </div>
        </div>
        <div
          style={{
            color: C.dim,
            fontFamily: "JetBrains Mono",
            fontSize: 10,
            marginTop: 8,
          }}
        >
          Roadmap items are generated from the selected scan. Duplicates are
          auto-merged for readability.
        </div>
        {loading && (
          <div
            style={{
              color: C.dim,
              fontFamily: "JetBrains Mono",
              fontSize: 11,
              marginTop: 8,
            }}
          >
            Loading roadmap...
          </div>
        )}
        {!!loadError && (
          <div
            style={{
              color: C.red,
              fontFamily: "JetBrains Mono",
              fontSize: 11,
              marginTop: 8,
            }}
          >
            {loadError}
          </div>
        )}
      </Card>
      {phases.map((phase) => {
        const list = grouped[phase] || [];
        return (
          <Card key={phase} style={{ padding: 18 }}>
            <h4 style={{ marginTop: 0, fontFamily: "Orbitron", color: C.cyan }}>
              {phase} - {phaseTitles[phase]}
            </h4>
            <div
              style={{
                color: C.dim,
                fontFamily: "JetBrains Mono",
                fontSize: 11,
                marginBottom: 10,
              }}
            >
              {phaseGuidance[phase]}
            </div>
            {list.length ? (
              list.map((r, i) => (
                <div
                  key={r.id ?? `${phase}-${i}`}
                  style={{ color: C.text, marginBottom: 8, fontSize: 13 }}
                >
                  {i + 1}. {r.text}
                </div>
              ))
            ) : (
              <div
                style={{
                  color: C.dim,
                  fontFamily: "JetBrains Mono",
                  fontSize: 11,
                }}
              >
                No actions generated for this phase yet.
              </div>
            )}
          </Card>
        );
      })}
    </div>
  );
}

function LeaderboardTab({ scanModel = "general" }) {
  const [rows, setRows] = useState([]);
  const [assetRows, setAssetRows] = useState([]);
  const [assetLoading, setAssetLoading] = useState(true);
  const [insightDomain, setInsightDomain] = useState("");
  const [safestFirst, setSafestFirst] = useState(true);

  useEffect(() => {
    fetch(`${API}/api/leaderboard?${scanModelParam(scanModel)}`)
      .then((r) => r.json())
      .then((d) =>
        setRows(
          uniqueLatestByDomain(
            filterRowsByMode(d || [], scanModel),
            "domain",
            "created_at",
          ),
        ),
      )
      .catch(() => setRows([]));
  }, [scanModel]);

  useEffect(() => {
    let alive = true;
    const loadAssetRows = async () => {
      setAssetLoading(true);
      try {
        const scansResp = await fetch(
          `${API}/api/scans?${scanModelParam(scanModel)}`,
        );
        const scansRaw = scansResp.ok ? await scansResp.json() : [];
        const latestPerDomain = uniqueLatestByDomain(
          filterRowsByMode(
            (scansRaw || []).filter((x) => x.status === "completed"),
            scanModel,
          ),
          "domain",
          "updated_at",
        ).slice(0, 20);
        const detailRows = await Promise.all(
          latestPerDomain.map(async (scan) => {
            try {
              const r = await fetch(`${API}/api/scan/${scan.scan_id}`);
              if (!r.ok) return null;
              const data = await r.json();
              const assets = data.assets || [];
              const scores = assets
                .map((a) => Number(a.risk_score ?? 0))
                .filter((n) => Number.isFinite(n));
              if (!scores.length) return null;
              return {
                scan_id: scan.scan_id,
                domain: data.scan?.domain || scan.domain,
                asset_count: scores.length,
                avg_risk: Number(
                  (scores.reduce((a, b) => a + b, 0) / scores.length).toFixed(
                    2,
                  ),
                ),
                safe_score: Number(Math.min(...scores).toFixed(2)),
                risk_score: Number(Math.max(...scores).toFixed(2)),
              };
            } catch {
              return null;
            }
          }),
        );
        if (!alive) return;
        setAssetRows(
          uniqueLatestByDomain(
            detailRows.filter(Boolean),
            "domain",
            "created_at",
          ),
        );
      } catch {
        if (alive) setAssetRows([]);
      } finally {
        if (alive) setAssetLoading(false);
      }
    };
    loadAssetRows();
    return () => {
      alive = false;
    };
  }, [scanModel]);

  const modeIsBanking = normalizeScanModel(scanModel) === "banking";
  const normalized = uniqueLatestLeaderboardByDomain(rows)
    .map((r) => ({
      ...r,
      avg_score: Number(r.avg_score ?? r.average_hndl_risk ?? 0),
    }))
    .sort((a, b) => b.avg_score - a.avg_score);
  const isBankingDomain = (domain) => isBankingDomainName(domain);
  const filteredNormalized = normalized.filter((r) =>
    modeIsBanking ? isBankingDomain(r.domain) : !isBankingDomain(r.domain),
  );
  const licenseForDomain = (domain) =>
    isBankingDomain(domain)
      ? "FINANCIAL CRYPTO LICENSE / PQC-S1"
      : "NON-BANK ASSET LICENSE / PQC-M2";
  const rankMedal = (index) => {
    if (index === 0) return "GOLD";
    if (index === 1) return "SILVER";
    if (index === 2) return "BRONZE";
    return "";
  };
  const highestRisk = filteredNormalized[0] || null;
  const mostSecure =
    [...filteredNormalized].sort((a, b) => a.avg_score - b.avg_score)[0] ||
    null;
  const fallbackAssetRows = filteredNormalized.map((r) => ({
    scan_id: r.scan_id,
    domain: r.domain,
    asset_count: Number(r.asset_count || 0),
    avg_risk: Number(r.avg_score || 0),
    safe_score: Math.max(0, Number(r.avg_score || 0) - 12),
    risk_score: Math.min(100, Number(r.avg_score || 0) + 12),
  }));
  const effectiveAssetRows = uniqueLatestByDomain(
    assetRows.length ? assetRows : fallbackAssetRows,
    "domain",
    "created_at",
  ).filter((r) => Number.isFinite(r.avg_risk));
  const sortByRisk = (a, b) =>
    safestFirst ? a.avg_risk - b.avg_risk : b.avg_risk - a.avg_risk;
  const modeRows = [...effectiveAssetRows]
    .filter((r) =>
      modeIsBanking ? isBankingDomain(r.domain) : !isBankingDomain(r.domain),
    )
    .sort(sortByRisk)
    .slice(0, 10);
  const riskiestFirst = [...modeRows]
    .sort((a, b) => b.avg_risk - a.avg_risk)
    .slice(0, 10);
  const safestToRiskiest = [...effectiveAssetRows]
    .sort((a, b) => a.avg_risk - b.avg_risk)
    .slice(0, 10)
    .map((r, i) => ({ ...r, rank: `#${i + 1}` }));
  const perBankInsights = [...effectiveAssetRows]
    .sort((a, b) => b.avg_risk - a.avg_risk)
    .map((row) => {
      const projected = Math.min(100, row.avg_risk + 6);
      const problems = [];
      if (row.risk_score >= 70)
        problems.push("Critical-risk assets detected in this domain scope.");
      if (row.avg_risk >= 60)
        problems.push(
          "Overall risk posture is high and needs immediate hardening.",
        );
      if (row.asset_count >= 25)
        problems.push(
          "Large asset footprint increases attack surface and governance overhead.",
        );
      if (!problems.length)
        problems.push(
          "No severe blockers, but continuous hardening is still recommended.",
        );
      return {
        domain: row.domain,
        analysis: `${row.domain} has avg risk ${row.avg_risk.toFixed(1)} across ${row.asset_count} assets in the current dataset.`,
        prediction: `If current control coverage stays unchanged, risk may move to ${projected.toFixed(1)} in 90 days due to exposed endpoints and crypto drift.`,
        problems,
        solutions: [
          `Prioritize top high-risk assets under ${row.domain} and patch TLS/cipher weaknesses first.`,
          "Enforce certificate/key rotation policy and monitor weak-signature detections weekly.",
          "Run monthly batch rescans and compare deltas against your baseline.",
        ],
      };
    });

  useEffect(() => {
    if (!perBankInsights.length) {
      setInsightDomain("");
      return;
    }
    if (
      !insightDomain ||
      !perBankInsights.some((x) => x.domain === insightDomain)
    ) {
      setInsightDomain(perBankInsights[0].domain);
    }
  }, [insightDomain, perBankInsights]);

  const selectedInsight =
    perBankInsights.find((x) => x.domain === insightDomain) ||
    perBankInsights[0] ||
    null;
  const activeModeTitle = modeIsBanking
    ? "BANKING ASSETS (PQC-S1)"
    : "NON-BANK ASSETS (PQC-M2)";

  return (
    <div style={{ display: "grid", gap: 14 }}>
      <Card style={{ padding: 14 }}>
        <TabModeAccent scanModel={scanModel} tabLabel="RISK LEADERBOARD" />
        <TabGuide
          title="This tab compares domain posture rankings"
          subtitle="Use it to see safest-to-riskiest ordering, trend spread, and domain-specific action cues for the selected mode."
          bullets={[
            "Mode-exclusive rankings",
            "Risk ladder and spread graphs",
            "Per-domain guidance",
          ]}
        />
      </Card>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit,minmax(260px,1fr))",
          gap: 12,
        }}
      >
        <Card style={{ padding: 16 }}>
          <div
            style={{
              color: C.dim,
              fontFamily: "JetBrains Mono",
              fontSize: 10,
              marginBottom: 6,
            }}
          >
            HIGHEST RISK WEBSITE
          </div>
          <div style={{ fontFamily: "Orbitron", color: C.red, fontSize: 16 }}>
            <PressureText glow={C.red}>
              {highestRisk?.domain || "N/A"}
            </PressureText>
          </div>
          <div style={{ marginTop: 6 }}>
            Score:{" "}
            <ClayNumber
              value={highestRisk?.avg_score ?? "-"}
              tone={C.red}
              size={10}
              minWidth={56}
              style={{ marginLeft: 6 }}
            />
          </div>
          <div
            style={{
              marginTop: 5,
              color: C.dim,
              fontFamily: "JetBrains Mono",
              fontSize: 10,
            }}
          >
            Significance: A score = 61 indicates critical vulnerabilities. Such
            scores mean the domain's encryption policies (like TLS ciphers) are
            at high risk of quantum or classical breaches and require immediate
            remediation.
          </div>
          <div
            style={{
              marginTop: 6,
              color: C.orange,
              fontFamily: "JetBrains Mono",
              fontSize: 10,
            }}
          >
            Scan basis:{" "}
            {highestRisk?.domain ? licenseForDomain(highestRisk.domain) : "N/A"}
          </div>
        </Card>
        <Card style={{ padding: 16 }}>
          <div
            style={{
              color: C.dim,
              fontFamily: "JetBrains Mono",
              fontSize: 10,
              marginBottom: 6,
            }}
          >
            MOST SECURE WEBSITE
          </div>
          <div style={{ fontFamily: "Orbitron", color: C.green, fontSize: 16 }}>
            <PressureText glow={C.green}>
              {mostSecure?.domain || "N/A"}
            </PressureText>
          </div>
          <div style={{ marginTop: 6 }}>
            Score:{" "}
            <ClayNumber
              value={mostSecure?.avg_score ?? "-"}
              tone={C.green}
              size={10}
              minWidth={56}
              style={{ marginLeft: 6 }}
            />
          </div>
          <div
            style={{
              marginTop: 5,
              color: C.dim,
              fontFamily: "JetBrains Mono",
              fontSize: 10,
            }}
          >
            Significance: A score = 35 implies strong cryptographic hygiene,
            meaning the domain relies on robust, modern, and potentially
            PQC-ready encryption protocols.
          </div>
          <div
            style={{
              marginTop: 6,
              color: C.orange,
              fontFamily: "JetBrains Mono",
              fontSize: 10,
            }}
          >
            Scan basis:{" "}
            {mostSecure?.domain ? licenseForDomain(mostSecure.domain) : "N/A"}
          </div>
        </Card>
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit,minmax(340px,1fr))",
          gap: 12,
        }}
      >
        <div
          style={{
            gridColumn: "1 / -1",
            display: "flex",
            justifyContent: "flex-end",
            alignItems: "center",
            gap: 8,
          }}
        >
          <div
            style={{ color: C.dim, fontFamily: "JetBrains Mono", fontSize: 10 }}
          >
            Leaderboard order
          </div>
          <LiquidSearchSelect
            value={safestFirst ? "safest" : "risky"}
            onChange={(v) => setSafestFirst(v === "safest")}
            options={[
              { value: "safest", label: "SAFEST FIRST" },
              { value: "risky", label: "HIGHEST RISK FIRST" },
            ]}
            buttonLabel="Leaderboard order"
            searchPlaceholder="Search order..."
            emptyLabel="No order option"
            minWidth={220}
          />
        </div>
        <Card style={{ padding: 0, overflow: "hidden" }}>
          <div
            style={{
              padding: "10px 12px",
              background: "rgba(186,161,101,0.08)",
              borderBottom: `1px solid ${C.border}`,
              color: modeIsBanking ? C.cyan : C.orange,
              fontFamily: "Orbitron",
              fontSize: 12,
              letterSpacing: 1.1,
            }}
          >
            {activeModeTitle}
          </div>
          <table
            style={{
              width: "100%",
              borderCollapse: "collapse",
              fontFamily: "JetBrains Mono",
              fontSize: 11,
            }}
          >
            <thead>
              <tr
                style={{
                  borderBottom: `1px solid ${C.border}`,
                  background: "rgba(0,0,0,0.02)",
                }}
              >
                <th
                  style={{
                    textAlign: "left",
                    padding: "8px 10px",
                    color: C.dim,
                  }}
                >
                  #
                </th>
                <th
                  style={{
                    textAlign: "left",
                    padding: "8px 10px",
                    color: C.dim,
                  }}
                >
                  Domain
                </th>
                <th
                  style={{
                    textAlign: "left",
                    padding: "8px 10px",
                    color: C.dim,
                  }}
                >
                  Avg Risk
                </th>
              </tr>
            </thead>
            <tbody>
              {modeRows.length ? (
                modeRows.map((r, i) => (
                  <tr
                    key={`mode-rank-${r.scan_id}`}
                    style={{ borderBottom: `1px dashed ${C.border}44` }}
                  >
                    <td style={{ padding: "10px", color: C.dim }}>
                      <div>{i + 1}</div>
                      {rankMedal(i) && (
                        <div
                          style={{
                            marginTop: 3,
                            fontSize: 9,
                            color: C.orange,
                            letterSpacing: 0.5,
                          }}
                        >
                          {rankMedal(i)}
                        </div>
                      )}
                    </td>
                    <td style={{ padding: "10px", color: C.text }}>
                      <div style={{ fontWeight: "bold" }}>{r.domain}</div>
                      <div style={{ fontSize: 9, color: C.dim, marginTop: 4 }}>
                        {r.asset_count} tracked assets
                      </div>
                    </td>
                    <td style={{ padding: "10px" }}>
                      <ClayNumber
                        value={r.avg_risk.toFixed(1)}
                        tone={riskColor(r.avg_risk)}
                        size={10}
                        minWidth={44}
                      />
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td
                    colSpan="3"
                    style={{ padding: 12, textAlign: "center", color: C.dim }}
                  >
                    No domains in current mode leaderboard.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </Card>
      </div>

      <Card style={{ padding: 18 }}>
        <div
          style={{
            marginBottom: 8,
            color: C.blue,
            fontFamily: "Orbitron",
            fontSize: 12,
            letterSpacing: 1.2,
          }}
        >
          <PressureText glow={C.blue}>
            ASSET RISK LADDER (SAFEST TO RISKIEST)
          </PressureText>
        </div>
        {!HAS_RECHARTS && (
          <div
            style={{
              marginBottom: 8,
              color: C.dim,
              fontFamily: "JetBrains Mono",
              fontSize: 11,
            }}
          >
            Recharts unavailable; using built-in fallback visualization.
          </div>
        )}
        {safestToRiskiest.length > 0 && HAS_RECHARTS ? (
          <ResponsiveContainer width="100%" height={290}>
            <BarChart
              data={safestToRiskiest}
              layout="vertical"
              margin={{ top: 4, right: 12, left: 30, bottom: 2 }}
            >
              <CartesianGrid
                stroke="rgba(98,118,154,0.12)"
                strokeDasharray="3 3"
              />
              <XAxis
                type="number"
                domain={[0, 100]}
                tick={{ fill: C.dim, fontSize: 10 }}
              />
              <YAxis
                type="category"
                dataKey="domain"
                width={140}
                tick={{ fill: C.dim, fontSize: 10 }}
              />
              <Tooltip
                contentStyle={{
                  background: "#e2e8ef",
                  border: "1px solid rgba(98,118,154,0.2)",
                  borderRadius: 10,
                  color: C.text,
                }}
              />
              <Bar dataKey="avg_risk" radius={[8, 8, 8, 8]}>
                {safestToRiskiest.map((r, i) => (
                  <Cell key={i} fill={riskColor(r.avg_risk)} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        ) : safestToRiskiest.length > 0 ? (
          <div style={{ display: "grid", gap: 8 }}>
            {safestToRiskiest.map((r) => (
              <div
                key={r.scan_id}
                style={{
                  display: "grid",
                  gridTemplateColumns: "150px 1fr 48px",
                  gap: 8,
                  alignItems: "center",
                }}
              >
                <div
                  style={{
                    color: C.dim,
                    fontFamily: "JetBrains Mono",
                    fontSize: 11,
                  }}
                >
                  {r.domain}
                </div>
                <div
                  style={{
                    height: 10,
                    borderRadius: 999,
                    background: isDarkTheme() ? "#10233f" : "#dce7f5",
                    overflow: "hidden",
                  }}
                >
                  <div
                    style={{
                      width: `${Math.max(1, r.avg_risk)}%`,
                      height: "100%",
                      borderRadius: 999,
                      background: riskColor(r.avg_risk),
                      boxShadow: isDarkTheme()
                        ? `0 0 10px ${riskColor(r.avg_risk)}99`
                        : "none",
                    }}
                  />
                </div>
                <div style={{ textAlign: "right" }}>
                  <ClayNumber
                    value={r.avg_risk.toFixed(1)}
                    tone={riskColor(r.avg_risk)}
                    size={10}
                    minWidth={52}
                  />
                  <div
                    style={{
                      fontSize: 9,
                      color: riskColor(r.avg_risk),
                      marginTop: 4,
                      textTransform: "uppercase",
                      letterSpacing: 0.5,
                    }}
                  >
                    {r.avg_risk < 36
                      ? "Safe Posture"
                      : r.avg_risk < 61
                        ? "Warning State"
                        : "Critical Risk"}
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div
            style={{ color: C.dim, fontFamily: "JetBrains Mono", fontSize: 12 }}
          >
            No completed scan asset data yet.
          </div>
        )}
      </Card>

      <Card style={{ padding: 18 }}>
        <div
          style={{
            marginBottom: 8,
            color: C.blue,
            fontFamily: "Orbitron",
            fontSize: 12,
            letterSpacing: 1.2,
          }}
        >
          <PressureText glow={C.blue}>SAFE VS RISK SPREAD BY SITE</PressureText>
        </div>
        {safestToRiskiest.length > 0 && HAS_RECHARTS ? (
          <ResponsiveContainer width="100%" height={250}>
            <AreaChart
              data={safestToRiskiest}
              margin={{ top: 8, right: 12, left: 2, bottom: 0 }}
            >
              <defs>
                <linearGradient id="safeAreaGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={C.green} stopOpacity={0.42} />
                  <stop offset="100%" stopColor={C.green} stopOpacity={0.03} />
                </linearGradient>
                <linearGradient
                  id="riskMidAreaGrad"
                  x1="0"
                  y1="0"
                  x2="0"
                  y2="1"
                >
                  <stop offset="0%" stopColor={C.yellow} stopOpacity={0.34} />
                  <stop offset="100%" stopColor={C.yellow} stopOpacity={0.02} />
                </linearGradient>
                <linearGradient
                  id="riskHighAreaGrad"
                  x1="0"
                  y1="0"
                  x2="0"
                  y2="1"
                >
                  <stop offset="0%" stopColor={C.red} stopOpacity={0.28} />
                  <stop offset="100%" stopColor={C.red} stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid
                stroke="rgba(98,118,154,0.12)"
                strokeDasharray="3 3"
              />
              <XAxis dataKey="domain" tick={{ fill: C.dim, fontSize: 10 }} />
              <YAxis domain={[0, 100]} tick={{ fill: C.dim, fontSize: 10 }} />
              <Tooltip
                contentStyle={{
                  background: "#e2e8ef",
                  border: "1px solid rgba(98,118,154,0.2)",
                  borderRadius: 10,
                  color: C.text,
                }}
              />
              <Area
                type="monotone"
                dataKey="safe_score"
                stroke={C.green}
                fill="url(#safeAreaGrad)"
                strokeWidth={2.4}
              />
              <Area
                type="monotone"
                dataKey="avg_risk"
                stroke={C.yellow}
                fill="url(#riskMidAreaGrad)"
                strokeWidth={2.2}
              />
              <Area
                type="monotone"
                dataKey="risk_score"
                stroke={C.red}
                fill="url(#riskHighAreaGrad)"
                strokeWidth={2.2}
              />
            </AreaChart>
          </ResponsiveContainer>
        ) : safestToRiskiest.length > 0 ? (
          <div style={{ display: "grid", gap: 8 }}>
            {safestToRiskiest.map((r) => (
              <div
                key={r.scan_id}
                style={{
                  color: C.text,
                  fontFamily: "JetBrains Mono",
                  fontSize: 11,
                }}
              >
                {r.domain}: safe {r.safe_score.toFixed(1)} | avg{" "}
                {r.avg_risk.toFixed(1)} | risk {r.risk_score.toFixed(1)}
              </div>
            ))}
          </div>
        ) : (
          <div
            style={{ color: C.dim, fontFamily: "JetBrains Mono", fontSize: 12 }}
          >
            Waiting for risk spread data.
          </div>
        )}
      </Card>

      <Card style={{ padding: 0, overflow: "hidden" }}>
        <div
          style={{
            padding: "10px 12px",
            fontFamily: "JetBrains Mono",
            color: C.dim,
            borderBottom: `1px solid ${C.border}`,
            fontSize: 11,
          }}
        >
          SITE ASSET RISK ALIGNMENT{" "}
          {assetLoading ? "(loading backend data)" : ""}
        </div>
        <div
          style={{
            padding: "8px 12px",
            color: C.dim,
            fontFamily: "JetBrains Mono",
            fontSize: 10,
          }}
        >
          All scores are risk scores out of 100. Lower values indicate stronger
          security posture.
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr", gap: 0 }}>
          <div>
            <div
              style={{
                padding: "10px 12px",
                background: "rgba(186,161,101,0.06)",
                borderBottom: `1px solid ${C.border}`,
                color: modeIsBanking ? C.cyan : C.orange,
                fontFamily: "Orbitron",
                fontSize: 12,
                letterSpacing: 1.1,
              }}
            >
              {modeIsBanking ? "??? " : "?? "}
              {activeModeTitle}
            </div>
            <table
              style={{
                width: "100%",
                borderCollapse: "collapse",
                fontFamily: "JetBrains Mono",
                fontSize: 11,
              }}
            >
              <thead>
                <tr
                  style={{
                    borderBottom: `1px solid ${C.border}`,
                    background: "rgba(0,0,0,0.02)",
                  }}
                >
                  <th
                    style={{
                      textAlign: "left",
                      padding: "8px 10px",
                      color: C.dim,
                    }}
                  >
                    Domain
                  </th>
                  <th
                    style={{
                      textAlign: "left",
                      padding: "8px 10px",
                      color: C.dim,
                    }}
                  >
                    Avg Risk Score
                  </th>
                </tr>
              </thead>
              <tbody>
                {riskiestFirst.length ? (
                  riskiestFirst.map((r) => (
                    <tr
                      key={r.scan_id}
                      style={{ borderBottom: `1px dashed ${C.border}44` }}
                    >
                      <td style={{ padding: "10px", color: C.text }}>
                        <div style={{ fontWeight: "bold" }}>{r.domain}</div>
                        <div
                          style={{ fontSize: 9, color: C.dim, marginTop: 4 }}
                        >
                          {r.asset_count} tracked assets
                        </div>
                      </td>
                      <td style={{ padding: "10px" }}>
                        <ClayNumber
                          value={r.avg_risk.toFixed(1)}
                          tone={riskColor(r.avg_risk)}
                          size={10}
                          minWidth={44}
                        />
                        <div
                          style={{
                            fontSize: 9,
                            color: riskColor(r.avg_risk),
                            marginTop: 4,
                            textTransform: "uppercase",
                            letterSpacing: 0.5,
                          }}
                        >
                          {r.avg_risk < 36
                            ? "Safe Posture"
                            : r.avg_risk < 61
                              ? "Warning State"
                              : "Critical Risk"}
                        </div>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td
                      colSpan="2"
                      style={{ padding: 12, textAlign: "center", color: C.dim }}
                    >
                      {modeIsBanking
                        ? "No banking assets monitored."
                        : "No non-bank assets monitored."}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </Card>

      <Card style={{ padding: 18 }}>
        {HAS_RECHARTS ? (
          <ResponsiveContainer width="100%" height={230}>
            <AreaChart
              data={filteredNormalized}
              margin={{ top: 8, right: 12, left: 2, bottom: 0 }}
            >
              <defs>
                <linearGradient
                  id="avgRiskAreaGrad"
                  x1="0"
                  y1="0"
                  x2="0"
                  y2="1"
                >
                  <stop offset="0%" stopColor={C.blue} stopOpacity={0.42} />
                  <stop offset="100%" stopColor={C.blue} stopOpacity={0.03} />
                </linearGradient>
              </defs>
              <CartesianGrid
                stroke="rgba(98,118,154,0.12)"
                strokeDasharray="3 3"
              />
              <XAxis dataKey="domain" tick={{ fill: C.dim, fontSize: 10 }} />
              <YAxis domain={[0, 100]} tick={{ fill: C.dim, fontSize: 10 }} />
              <Tooltip
                contentStyle={{
                  background: "#e2e8ef",
                  border: "1px solid rgba(98,118,154,0.2)",
                  borderRadius: 10,
                  color: C.text,
                }}
              />
              <Area
                type="monotone"
                dataKey="avg_score"
                stroke={C.blue}
                strokeWidth={2.5}
                fill="url(#avgRiskAreaGrad)"
              />
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <RiskTrendFallback data={normalized} />
        )}
      </Card>

      <Card style={{ padding: 16 }}>
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            gap: 10,
            alignItems: "center",
            marginBottom: 12,
          }}
        >
          <div style={{ fontFamily: "Orbitron", color: C.blue }}>
            Per-Bank Intelligence Selector
          </div>
          <div
            style={{
              marginLeft: "auto",
              display: "flex",
              alignItems: "center",
              gap: 8,
            }}
          >
            <div
              style={{
                color: C.dim,
                fontFamily: "JetBrains Mono",
                fontSize: 10,
              }}
            >
              Select bank/domain
            </div>
            <LiquidSearchSelect
              value={insightDomain}
              onChange={setInsightDomain}
              options={(perBankInsights || []).map((item) => ({
                value: item.domain,
                label: item.domain,
              }))}
              buttonLabel="Select bank/domain"
              searchPlaceholder="Search bank/domain..."
              emptyLabel="No domains available"
              minWidth={280}
            />
          </div>
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit,minmax(260px,1fr))",
            gap: 10,
          }}
        >
          <Card style={{ padding: 14 }}>
            <div
              style={{ fontFamily: "Orbitron", color: C.blue, marginBottom: 8 }}
            >
              Analysis
            </div>
            <div
              style={{
                color: C.text,
                fontFamily: "JetBrains Mono",
                fontSize: 12,
                lineHeight: 1.6,
              }}
            >
              {selectedInsight
                ? selectedInsight.analysis
                : "Run completed scans to generate analysis."}
            </div>
          </Card>
          <Card style={{ padding: 14 }}>
            <div
              style={{
                fontFamily: "Orbitron",
                color: C.orange,
                marginBottom: 8,
              }}
            >
              Problems
            </div>
            <div
              style={{
                color: C.text,
                fontFamily: "JetBrains Mono",
                fontSize: 12,
                lineHeight: 1.6,
              }}
            >
              {selectedInsight
                ? selectedInsight.problems.map((p, i) => (
                    <div key={i}>- {p}</div>
                  ))
                : "No problems available."}
            </div>
          </Card>
          <Card style={{ padding: 14 }}>
            <div
              style={{
                fontFamily: "Orbitron",
                color: C.green,
                marginBottom: 8,
              }}
            >
              Recommendations
            </div>
            <div
              style={{
                color: C.text,
                fontFamily: "JetBrains Mono",
                fontSize: 12,
                lineHeight: 1.6,
              }}
            >
              {selectedInsight
                ? selectedInsight.solutions.map((s, i) => (
                    <div key={i}>- {s}</div>
                  ))
                : "No recommendations available."}
            </div>
          </Card>
        </div>
        <div
          style={{
            marginTop: 10,
            color: C.dim,
            fontFamily: "JetBrains Mono",
            fontSize: 10,
          }}
        >
          {selectedInsight
            ? selectedInsight.prediction
            : "Prediction will appear after selecting a bank/domain."}
        </div>
      </Card>
    </div>
  );
}

function BankSignalLabTab({ scanModel = "general" }) {
  const [rows, setRows] = useState([]);
  const [selected, setSelected] = useState("");

  useEffect(() => {
    const load = () => {
      fetch(`${API}/api/leaderboard?${scanModelParam(scanModel)}`)
        .then((r) => r.json())
        .then((d) => {
          const normalized = filterRowsByMode(d || [], scanModel)
            .map((x) => ({
              domain: String(x.domain || "").toLowerCase(),
              avg_risk: Number(x.avg_score ?? x.average_hndl_risk ?? 0),
              asset_count: Number(x.asset_count || 0),
              created_at: x.created_at || null,
            }))
            .filter((x) => x.domain && Number.isFinite(x.avg_risk));
          const deduped = uniqueLatestLeaderboardByDomain(
            normalized.map((x) => ({
              ...x,
              avg_score: x.avg_risk,
            })),
          ).map((x) => ({
            domain: x.domain,
            avg_risk: Number(x.avg_score ?? 0),
            asset_count: Number(x.asset_count || 0),
            created_at: x.created_at || null,
          }));
          setRows(deduped);
        })
        .catch(() => setRows([]));
    };
    load();
    const id = setInterval(load, 7000);
    return () => clearInterval(id);
  }, [scanModel]);

  const available = rows;
  useEffect(() => {
    if (!selected && available.length) setSelected(available[0].domain);
  }, [selected, available]);

  useEffect(() => {
    if (selected && !available.some((r) => r.domain === selected)) {
      setSelected(available[0]?.domain || "");
    }
  }, [available, selected]);

  const selectedRow = available.find((r) => r.domain === selected) || null;
  const lineUp = [...available]
    .sort((a, b) => securityScore(b.avg_risk) - securityScore(a.avg_risk))
    .map((r, i) => ({
      bank: r.domain,
      domain: r.domain,
      security: Number(securityScore(r.avg_risk).toFixed(2)),
      risk: Number(
        r.avg_risk.toFixed
          ? r.avg_risk.toFixed(2)
          : Number(r.avg_risk || 0).toFixed(2),
      ),
      asset_count: Number(r.asset_count || 0),
      rank: i + 1,
    }));
  const podium = {
    first: lineUp[0] || null,
    second: lineUp[1] || null,
    third: lineUp[2] || null,
  };
  const recs = selectedRow
    ? BANK_REQUIREMENTS[selectedRow.domain] || [
        "Patch highest-risk exposed assets first.",
        "Rotate weak cert/signature chains and enforce TLS baseline.",
        "Track weekly risk movement and verify mitigation closure.",
      ]
    : [];
  const scoreBand = (score) => {
    const s = Number(score || 0);
    if (s >= 80) return "very safe";
    if (s >= 65) return "safe";
    if (s >= 45) return "watch";
    return "high risk";
  };
  const compact = typeof window !== "undefined" && window.innerWidth < 860;
  const podiumOrder = compact
    ? [podium.first, podium.second, podium.third]
    : [podium.second, podium.first, podium.third];
  const podiumPalette = {
    first: {
      tone: "#c99d2b",
      border: "rgba(186,142,33,0.52)",
      glassA:
        "linear-gradient(160deg, rgba(255,247,215,0.9), rgba(240,211,124,0.48))",
      glassB:
        "linear-gradient(180deg, rgba(255,244,199,0.88), rgba(207,157,46,0.74) 55%, rgba(143,106,21,0.92) 100%)",
    },
    second: {
      tone: "#8c96a8",
      border: "rgba(119,129,146,0.52)",
      glassA:
        "linear-gradient(160deg, rgba(244,247,252,0.9), rgba(186,198,216,0.52))",
      glassB:
        "linear-gradient(180deg, rgba(241,245,251,0.86), rgba(158,170,189,0.72) 55%, rgba(96,108,126,0.9) 100%)",
    },
    third: {
      tone: "#a56a39",
      border: "rgba(147,90,44,0.52)",
      glassA:
        "linear-gradient(160deg, rgba(251,239,230,0.9), rgba(222,167,126,0.52))",
      glassB:
        "linear-gradient(180deg, rgba(251,236,223,0.86), rgba(195,132,88,0.72) 55%, rgba(125,74,37,0.9) 100%)",
    },
  };

  return (
    <div style={{ display: "grid", gap: 14 }}>
      <Card style={{ padding: 14 }}>
        <TabModeAccent scanModel={scanModel} tabLabel="THREAT INSIGHT LAB" />
        <TabGuide
          title="This tab compares domain risk insights"
          subtitle="Use it to inspect ranked posture, trend behavior, and domain-specific recommendations for the active mode."
          bullets={[
            "Interactive podium",
            "Domain-by-domain insights",
            "Prediction and action cues",
          ]}
        />
      </Card>
      <Card style={{ padding: 16 }}>
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            gap: 10,
            alignItems: "center",
          }}
        >
          <div
            style={{
              color: C.blue,
              fontFamily: "Orbitron",
              fontSize: 13,
              letterSpacing: 1.1,
            }}
          >
            <PressureText glow={C.blue}>DOMAIN INSIGHT STUDIO</PressureText>
          </div>
          <div
            style={{
              marginLeft: "auto",
              display: "flex",
              alignItems: "center",
              gap: 8,
            }}
          >
            <span
              style={{
                color: C.dim,
                fontFamily: "JetBrains Mono",
                fontSize: 11,
              }}
            >
              Select domain
            </span>
            <LiquidSearchSelect
              value={selected}
              onChange={setSelected}
              options={(available || []).map((r) => ({
                value: r.domain,
                label: r.domain,
              }))}
              buttonLabel="Select domain"
              searchPlaceholder="Search domain..."
              emptyLabel="No domains available"
              minWidth={280}
            />
          </div>
        </div>
        {!available.length && (
          <div
            style={{
              color: C.dim,
              fontFamily: "JetBrains Mono",
              fontSize: 11,
              marginTop: 8,
            }}
          >
            No completed scan domains available yet.
          </div>
        )}
      </Card>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit,minmax(250px,1fr))",
          gap: 12,
        }}
      >
        <Card style={{ padding: 16 }}>
          <div
            style={{
              color: C.dim,
              fontFamily: "JetBrains Mono",
              fontSize: 10,
              marginBottom: 6,
            }}
          >
            Selected Domain
          </div>
          <div style={{ color: C.text, fontFamily: "Orbitron", fontSize: 16 }}>
            {selectedRow ? selectedRow.domain : "N/A"}
          </div>
          <div
            style={{ marginTop: 8, fontFamily: "JetBrains Mono", fontSize: 12 }}
          >
            Risk Score:{" "}
            <ClayNumber
              value={
                selectedRow ? Number(selectedRow.avg_risk).toFixed(1) : "-"
              }
              tone={riskColor(selectedRow?.avg_risk ?? 0)}
              size={10}
              minWidth={56}
              style={{ marginLeft: 6 }}
            />
          </div>
          <div
            style={{ marginTop: 4, fontFamily: "JetBrains Mono", fontSize: 12 }}
          >
            Security Score:{" "}
            <ClayNumber
              value={
                selectedRow
                  ? securityScore(selectedRow.avg_risk).toFixed(1)
                  : "-"
              }
              tone={C.green}
              size={10}
              minWidth={56}
              style={{ marginLeft: 6 }}
            />
          </div>
          <div
            style={{
              marginTop: 4,
              color: C.dim,
              fontFamily: "JetBrains Mono",
              fontSize: 11,
            }}
          >
            Assets considered:{" "}
            <ClayNumber
              value={selectedRow?.asset_count ?? "-"}
              tone={C.blue}
              size={10}
              minWidth={52}
              style={{ marginLeft: 6 }}
            />
          </div>
          <div
            style={{
              marginTop: 8,
              color: C.dim,
              fontFamily: "JetBrains Mono",
              fontSize: 10,
            }}
          >
            Score meaning: risk is 0-100 (lower is better). Security score is
            100-risk (higher is better).
          </div>
        </Card>
        <Card style={{ padding: 16 }}>
          <div
            style={{
              color: C.blue,
              fontFamily: "Orbitron",
              fontSize: 12,
              marginBottom: 8,
            }}
          >
            Required Actions ({selectedRow ? selectedRow.domain : "Domain"})
          </div>
          <div
            style={{
              color: C.text,
              fontFamily: "JetBrains Mono",
              fontSize: 12,
              lineHeight: 1.6,
            }}
          >
            {recs.map((r, i) => (
              <div key={i}>- {r}</div>
            ))}
          </div>
        </Card>
      </div>

      <ClayBankAnalysisGraph selectedRow={selectedRow} lineUp={lineUp} />

      <Card style={{ padding: 16, overflow: "hidden" }}>
        <div
          style={{
            color: C.blue,
            fontFamily: "Orbitron",
            fontSize: 12,
            marginBottom: 6,
          }}
        >
          Security Line-up Across Scanned Domains
        </div>
        <div
          style={{
            color: C.dim,
            fontFamily: "JetBrains Mono",
            fontSize: 11,
            marginBottom: 12,
          }}
        >
          Interactive podium: gold/silver/bronze represent #1/#2/#3 by security
          score (higher is safer).
        </div>

        {!!podium.first && (
          <div
            style={{
              position: "relative",
              borderRadius: 18,
              padding: "20px 10px 14px",
              background: isDarkTheme()
                ? "linear-gradient(165deg, rgba(24,44,38,0.72), rgba(18,33,29,0.58))"
                : "linear-gradient(165deg, rgba(236,246,242,0.82), rgba(226,239,234,0.7))",
              border: `1px solid ${C.border}`,
              boxShadow: isDarkTheme()
                ? "inset 0 1px 0 rgba(182,221,205,0.14), 0 10px 22px rgba(4,12,10,0.34)"
                : "inset 0 1px 0 rgba(255,255,255,0.82), 0 10px 22px rgba(155,183,171,0.28)",
            }}
          >
            <div
              className="podium-aurora"
              style={{
                position: "absolute",
                width: 220,
                height: 220,
                borderRadius: "52% 48% 58% 42%",
                top: -82,
                left: -64,
                background:
                  "radial-gradient(circle at 32% 32%, rgba(99,228,181,0.28), rgba(87,188,154,0.08) 62%, transparent 74%)",
                filter: "blur(4px)",
                pointerEvents: "none",
              }}
            />
            <div
              className="podium-aurora-b"
              style={{
                position: "absolute",
                width: 250,
                height: 250,
                borderRadius: "46% 54% 41% 59%",
                right: -75,
                top: -95,
                background:
                  "radial-gradient(circle at 36% 30%, rgba(126,230,196,0.23), rgba(88,176,146,0.06) 64%, transparent 78%)",
                filter: "blur(5px)",
                pointerEvents: "none",
              }}
            />

            <div
              className="podium-grid"
              style={{
                display: "grid",
                gridTemplateColumns: compact
                  ? "1fr"
                  : "repeat(3, minmax(0,1fr))",
                gap: compact ? 12 : 10,
                alignItems: "end",
                minHeight: compact ? 0 : 255,
                position: "relative",
                zIndex: 1,
              }}
            >
              {podiumOrder.map((item, idx) => {
                if (!item) return <div key={`podium-empty-${idx}`} />;
                const slot =
                  item.rank === 1
                    ? "first"
                    : item.rank === 2
                      ? "second"
                      : "third";
                const height =
                  slot === "first" ? 170 : slot === "second" ? 142 : 118;
                const palette = podiumPalette[slot];
                return (
                  <div
                    key={item.domain}
                    className={`podium-slot podium-slot-${slot}`}
                    style={{ display: "grid", gap: 8, justifyItems: "center" }}
                  >
                    <div
                      style={{
                        borderRadius: 16,
                        padding: "8px 10px",
                        width: "100%",
                        maxWidth: 210,
                        background: palette.glassA,
                        border: `1px solid ${palette.border}`,
                        backdropFilter: "blur(12px) saturate(125%)",
                        boxShadow:
                          "inset 0 1px 0 rgba(255,255,255,0.74), 0 8px 16px rgba(69,56,28,0.24)",
                      }}
                    >
                      <div
                        style={{
                          color: palette.tone,
                          fontFamily: "Orbitron",
                          fontSize: 10,
                          letterSpacing: 1.1,
                          textAlign: "center",
                        }}
                      >
                        {slot.toUpperCase()} PLACE
                      </div>
                      <div
                        style={{
                          color: C.text,
                          fontFamily: "JetBrains Mono",
                          fontSize: 11,
                          textAlign: "center",
                          marginTop: 4,
                        }}
                      >
                        {item.domain}
                      </div>
                      <div
                        style={{
                          display: "flex",
                          justifyContent: "center",
                          marginTop: 6,
                        }}
                      >
                        <ClayNumber
                          value={item.security.toFixed(1)}
                          tone={palette.tone}
                          size={10}
                          minWidth={56}
                        />
                      </div>
                      <div
                        style={{
                          marginTop: 5,
                          color: C.dim,
                          fontFamily: "JetBrains Mono",
                          fontSize: 10,
                          textAlign: "center",
                        }}
                      >
                        Status: {scoreBand(item.security)}
                      </div>
                    </div>
                    <div
                      style={{
                        position: "relative",
                        width: "100%",
                        maxWidth: compact ? 320 : 215,
                        height,
                        borderRadius: "14px 14px 22px 22px",
                        border: `1px solid ${palette.border}`,
                        background: palette.glassB,
                        boxShadow:
                          "0 14px 24px rgba(49,38,14,0.34), inset 0 1px 0 rgba(255,255,255,0.72), inset 0 -10px 18px rgba(55,36,10,0.28)",
                        overflow: "hidden",
                        transformStyle: "preserve-3d",
                      }}
                    >
                      <div
                        className="podium-liquid"
                        style={{
                          position: "absolute",
                          inset: "-30% -18% auto -18%",
                          height: "74%",
                          borderRadius: "48% 52% 41% 59%",
                          background:
                            "radial-gradient(circle at 35% 30%, rgba(224,255,243,0.44), rgba(159,233,205,0.18) 56%, transparent 74%)",
                          pointerEvents: "none",
                        }}
                      />
                      <div
                        style={{
                          position: "absolute",
                          left: 10,
                          right: 10,
                          top: 10,
                          height: 10,
                          borderRadius: 999,
                          background:
                            "linear-gradient(180deg, rgba(255,255,255,0.65), rgba(255,255,255,0.06))",
                          pointerEvents: "none",
                        }}
                      />
                      <div
                        style={{
                          position: "absolute",
                          inset: "0 0 auto 0",
                          height: 38,
                          background: isDarkTheme()
                            ? "linear-gradient(180deg, rgba(239,255,248,0.18), rgba(239,255,248,0.02))"
                            : "linear-gradient(180deg, rgba(255,255,255,0.65), rgba(255,255,255,0.08))",
                          pointerEvents: "none",
                        }}
                      />
                      <div
                        style={{
                          position: "absolute",
                          left: 0,
                          right: 0,
                          bottom: 10,
                          textAlign: "center",
                          fontFamily: "Orbitron",
                          color: "#fff8e2",
                          textShadow: "0 1px 3px rgba(70,48,10,0.45)",
                          letterSpacing: 1.6,
                          fontSize: 13,
                        }}
                      >
                        #{item.rank}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>

            <div
              className="podium-lineup"
              style={{ marginTop: 14, display: "grid", gap: 8 }}
            >
              {lineUp.slice(0, 12).map((r) => (
                <div
                  key={`lineup-${r.domain}-${r.rank}`}
                  style={{
                    display: "grid",
                    gridTemplateColumns: compact
                      ? "34px 1fr 74px 56px"
                      : "42px 170px 1fr 94px 62px",
                    gap: 8,
                    alignItems: "center",
                  }}
                >
                  <div
                    style={{
                      color: C.dim,
                      fontFamily: "JetBrains Mono",
                      fontSize: 10,
                    }}
                  >{`#${r.rank}`}</div>
                  <div
                    style={{
                      color: C.text,
                      fontFamily: "JetBrains Mono",
                      fontSize: 11,
                    }}
                  >
                    {r.domain}
                  </div>
                  {!compact && (
                    <div
                      style={{
                        height: 9,
                        borderRadius: 999,
                        background: isDarkTheme()
                          ? "rgba(22,45,38,0.92)"
                          : "rgba(211,232,223,0.9)",
                        overflow: "hidden",
                      }}
                    >
                      <div
                        style={{
                          width: `${Math.max(1, Math.min(100, r.security))}%`,
                          height: "100%",
                          borderRadius: 999,
                          background:
                            "linear-gradient(90deg, #2c8f66, #53c298)",
                          boxShadow: "0 0 12px rgba(88,206,160,0.45)",
                        }}
                      />
                    </div>
                  )}
                  <div
                    style={{
                      color: C.dim,
                      fontFamily: "JetBrains Mono",
                      fontSize: 10,
                      textTransform: "uppercase",
                    }}
                  >
                    {scoreBand(r.security)}
                  </div>
                  <div style={{ textAlign: "right" }}>
                    <ClayNumber
                      value={r.security.toFixed(1)}
                      tone={C.green}
                      size={10}
                      minWidth={58}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        <style>{`
          @keyframes podiumFloatA {
            0% { transform: translate3d(0, 0, 0) scale(1); }
            50% { transform: translate3d(-8px, 6px, 0) scale(1.04); }
            100% { transform: translate3d(0, 0, 0) scale(1); }
          }
          @keyframes podiumFloatB {
            0% { transform: translate3d(0, 0, 0) scale(1); }
            50% { transform: translate3d(9px, -5px, 0) scale(1.05); }
            100% { transform: translate3d(0, 0, 0) scale(1); }
          }
          @keyframes podiumLiquid {
            0% { transform: translateX(0) scale(1); }
            50% { transform: translateX(8px) scale(1.03); }
            100% { transform: translateX(0) scale(1); }
          }
          .podium-aurora { animation: podiumFloatA 9.8s ease-in-out infinite; }
          .podium-aurora-b { animation: podiumFloatB 11.4s ease-in-out infinite; }
          .podium-liquid { animation: podiumLiquid 6.8s ease-in-out infinite; }
          .podium-slot { transition: transform 200ms ease, filter 200ms ease; }
          .podium-slot:hover { transform: translateY(-6px) rotateX(2deg); filter: saturate(1.08); }
          .podium-slot:active { transform: translateY(-2px) scale(0.99); filter: saturate(1.1); }
          .podium-slot-first .podium-liquid { background: radial-gradient(circle at 35% 30%, rgba(255,247,206,0.55), rgba(250,206,86,0.2) 56%, transparent 74%); }
          .podium-slot-second .podium-liquid { background: radial-gradient(circle at 35% 30%, rgba(244,248,255,0.52), rgba(186,203,227,0.2) 56%, transparent 74%); }
          .podium-slot-third .podium-liquid { background: radial-gradient(circle at 35% 30%, rgba(252,236,224,0.52), rgba(215,156,111,0.22) 56%, transparent 74%); }
          @media (max-width: 860px) {
            .podium-grid { grid-template-columns: 1fr !important; }
          }
        `}</style>
      </Card>
    </div>
  );
}

function QuantHuntFloating({ theme = "light", scanModel = "general" }) {
  const dark = theme === "dark";
  const [open, setOpen] = useState(false);
  const [fabPressed, setFabPressed] = useState(false);
  const [messages, setMessages] = useState([
    {
      role: "assistant",
      text: "QuantHunt AI is ready. Ask: safety ranking, riskiest bank, analysis, prediction, solutions, PQC limits, or demo script. Offline fallback is always available.",
    },
  ]);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const [context, setContext] = useState("");
  const [contextSource, setContextSource] = useState("backend");
  const [sourceMode, setSourceMode] = useState("auto");
  const [focusMode, setFocusMode] = useState("general");
  const [showPrompts, setShowPrompts] = useState(false);
  const chatRef = useRef(null);

  useEffect(() => {
    fetch(`${API}/api/leaderboard?${scanModelParam(scanModel)}`)
      .then((r) => r.json())
      .then((d) => {
        const rows = uniqueLatestLeaderboardByDomain(
          filterRowsByMode(d || [], scanModel),
        ).slice(0, 10);
        if (rows.length) {
          const ctx = rows
            .map(
              (x, i) =>
                `${i + 1}. ${x.domain} score=${x.avg_score} assets=${x.asset_count}`,
            )
            .join("\n");
          setContext(
            `Source=backend\nModel=${normalizeScanModel(scanModel)}\n${ctx}`,
          );
          setContextSource("backend");
          return;
        }
        const fallback = BANK_DEMO_ROWS.map(
          (x, i) =>
            `${i + 1}. ${x.domain} score=${x.avg_risk} assets=${x.asset_count}`,
        ).join("\n");
        setContext(
          `Source=demo-bank-baseline\nModel=${normalizeScanModel(scanModel)}\n${fallback}`,
        );
        setContextSource("demo");
      })
      .catch(() => {
        const fallback = BANK_DEMO_ROWS.map(
          (x, i) =>
            `${i + 1}. ${x.domain} score=${x.avg_risk} assets=${x.asset_count}`,
        ).join("\n");
        setContext(
          `Source=demo-bank-baseline\nModel=${normalizeScanModel(scanModel)}\n${fallback}`,
        );
        setContextSource("demo");
      });
  }, [scanModel]);

  useEffect(() => {
    const el = chatRef.current;
    if (!el) return;
    el.scrollTo({ top: el.scrollHeight, behavior: "smooth" });
  }, [messages, sending, open]);

  const toggleOpen = () => {
    setFabPressed(true);
    setTimeout(() => setFabPressed(false), 180);
    setOpen((v) => !v);
  };

  const sendMessage = async (preset) => {
    const msg = (preset ?? input).trim();
    if (!msg || sending) return;
    setMessages((m) => [...m, { role: "user", text: msg }]);
    setInput("");
    setSending(true);
    try {
      let outbound = msg;
      if (
        focusMode !== "general" &&
        !outbound.toLowerCase().includes(focusMode)
      ) {
        outbound = `${outbound}\nfocus:${focusMode}`;
      }
      const r = await fetch(`${API}/api/quanthunt/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: outbound,
          context,
          mode: sourceMode,
          focus: focusMode,
          scan_model: scanModel,
        }),
      });
      const d = await r.json();
      if (!r.ok) {
        const err = d?.detail
          ? typeof d.detail === "string"
            ? d.detail
            : JSON.stringify(d.detail)
          : "Request failed.";
        setMessages((m) => [
          ...m,
          {
            role: "assistant",
            text: `Assistant API error (${r.status}): ${err}`,
          },
        ]);
      } else {
        const source = d?.source ? `\n\n[source: ${d.source}]` : "";
        const offline = d?.offline_mode ? "\n[offline mode active]" : "";
        const reason = d?.offline_reason
          ? `\n[offline reason: ${d.offline_reason}]`
          : "";
        const text = d?.reply || d?.message || JSON.stringify(d);
        setMessages((m) => [
          ...m,
          {
            role: "assistant",
            text: `${text || "No response."}${source}${offline}${reason}`,
          },
        ]);
      }
    } catch {
      setMessages((m) => [
        ...m,
        { role: "assistant", text: "Assistant request failed." },
      ]);
    } finally {
      setSending(false);
    }
  };

  const quick = [
    "best bank in terms of safety",
    "which bank is riskiest and why",
    "give analysis",
    "give prediction for next 90 days",
    "give solution plan",
    "top 3 risky banks",
    "top 3 safest banks",
    "what is pqc",
    "what is hndl",
    "explain tls 1 3",
    "wait time meaning",
    "remediation roadmap",
    "pqc detection limits",
    "explain chain block meaning",
    "certificate criteria",
    "testing coverage",
    "frontend polish checklist",
    "demo script for judges",
    "cors stance for production",
    "known limitations",
  ];
  const featuredQuick = quick.slice(0, 4);

  return (
    <>
      <button
        onClick={toggleOpen}
        title="Open Assistant"
        style={{
          position: "fixed",
          right: 24,
          bottom: 24,
          zIndex: 30,
          width: 66,
          height: 66,
          borderRadius: "50%",
          border: dark
            ? "1px solid rgba(141,162,189,0.52)"
            : "1px solid rgba(99,127,161,0.32)",
          background: dark
            ? "linear-gradient(160deg, #223754, #1a2c46)"
            : "linear-gradient(160deg, #eef3fb, #d8e4f4)",
          boxShadow: dark
            ? "0 18px 30px rgba(6,10,16,0.54), inset 0 1px 0 rgba(177,197,221,0.18)"
            : "8px 8px 18px rgba(168,184,206,0.42), -8px -8px 18px rgba(255,255,255,0.92)",
          cursor: "pointer",
          display: "grid",
          placeItems: "center",
          transform: fabPressed
            ? "scale(0.92)"
            : open
              ? "scale(1.04) translateY(-2px)"
              : "scale(1)",
          transition: "transform 180ms ease, box-shadow 240ms ease",
        }}
      >
        <div style={{ transform: "scale(0.92)" }}>
          <Logo size={34} animated={false} />
        </div>
      </button>

      <div
        className="quanthunt-panel"
        style={{
          position: "fixed",
          right: 24,
          bottom: 102,
          width: "min(468px, calc(100vw - 28px))",
          maxHeight: "76vh",
          zIndex: 30,
          borderRadius: 20,
          overflow: "hidden",
          border: dark
            ? "1px solid rgba(158,182,212,0.44)"
            : "1px solid rgba(118,142,173,0.34)",
          background: dark
            ? "linear-gradient(158deg, rgba(28,45,69,0.8), rgba(18,31,50,0.82))"
            : "linear-gradient(158deg, rgba(235,242,251,0.84), rgba(222,233,246,0.82))",
          backdropFilter: "blur(14px) saturate(130%)",
          boxShadow: open
            ? dark
              ? "0 26px 42px rgba(5,10,18,0.66), 0 8px 22px rgba(10,28,49,0.38), inset 0 1px 0 rgba(195,214,235,0.28), inset 0 -1px 0 rgba(8,18,30,0.45)"
              : "16px 20px 34px rgba(162,178,201,0.42), -12px -12px 24px rgba(255,255,255,0.88), inset 0 1px 0 rgba(255,255,255,0.7), inset 0 -1px 0 rgba(150,173,202,0.26)"
            : "0 0 0 rgba(0,0,0,0)",
          display: "grid",
          gridTemplateRows: "auto auto auto 1fr auto",
          opacity: open ? 1 : 0,
          transform: open
            ? "translateY(0) scale(1)"
            : "translateY(26px) scale(0.95)",
          transformOrigin: "bottom right",
          transition:
            "opacity 240ms ease, transform 320ms cubic-bezier(0.22, 1, 0.36, 1), box-shadow 280ms ease",
          pointerEvents: open ? "auto" : "none",
        }}
      >
        <div
          className="quanthunt-liquid quanthunt-liquid-a"
          style={{
            position: "absolute",
            inset: "-12% -28% auto auto",
            width: 220,
            height: 220,
            borderRadius: "52% 48% 58% 42%",
            background: dark
              ? "radial-gradient(circle at 30% 30%, rgba(177,212,245,0.2), rgba(76,114,157,0.06) 64%, transparent 72%)"
              : "radial-gradient(circle at 30% 30%, rgba(198,221,245,0.44), rgba(120,158,199,0.14) 64%, transparent 72%)",
            filter: "blur(2px)",
            pointerEvents: "none",
            zIndex: 0,
          }}
        />
        <div
          className="quanthunt-liquid quanthunt-liquid-b"
          style={{
            position: "absolute",
            inset: "auto auto -18% -22%",
            width: 210,
            height: 210,
            borderRadius: "46% 54% 42% 58%",
            background: dark
              ? "radial-gradient(circle at 30% 30%, rgba(146,188,230,0.14), rgba(78,116,155,0.04) 66%, transparent 74%)"
              : "radial-gradient(circle at 30% 30%, rgba(188,213,241,0.34), rgba(113,150,190,0.1) 66%, transparent 74%)",
            filter: "blur(3px)",
            pointerEvents: "none",
            zIndex: 0,
          }}
        />
        <div
          style={{
            position: "relative",
            zIndex: 1,
            display: "flex",
            alignItems: "center",
            gap: 10,
            padding: "12px 14px",
            borderBottom: dark
              ? "1px solid rgba(162,181,204,0.22)"
              : "1px solid rgba(110,132,162,0.2)",
            background: dark
              ? "linear-gradient(180deg, rgba(31,49,73,0.74), rgba(23,39,61,0.54))"
              : "linear-gradient(180deg, rgba(244,249,255,0.75), rgba(231,239,249,0.55))",
            boxShadow: dark
              ? "inset 0 1px 0 rgba(201,219,238,0.18)"
              : "inset 0 1px 0 rgba(255,255,255,0.7)",
          }}
        >
          <Logo size={22} animated={false} />
          <div
            style={{
              fontFamily: "Orbitron",
              color: dark ? "#d9e4f2" : "#2f4f7b",
              fontSize: 12,
              letterSpacing: 1.4,
            }}
          >
            <PressureText glow={dark ? C.cyan : C.blue}>
              QUANTHUNT ASSISTANT
            </PressureText>
          </div>
          <div
            style={{
              marginLeft: "auto",
              color: C.dim,
              fontFamily: "JetBrains Mono",
              fontSize: 10,
              padding: "4px 9px",
              borderRadius: 999,
              border: dark
                ? "1px solid rgba(149,173,202,0.34)"
                : "1px solid rgba(112,138,170,0.3)",
              background: dark
                ? "rgba(32,50,74,0.52)"
                : "rgba(240,246,253,0.64)",
            }}
          >
            context: {contextSource}
          </div>
        </div>

        <div
          className="quanthunt-controls"
          style={{
            position: "relative",
            zIndex: 1,
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: 10,
            padding: "10px 12px",
            borderBottom: dark
              ? "1px solid rgba(148,168,191,0.16)"
              : "1px solid rgba(92,126,168,0.16)",
          }}
        >
          <div
            style={{
              borderRadius: 14,
              padding: "8px 10px",
              border: dark
                ? "1px solid rgba(142,166,196,0.28)"
                : "1px solid rgba(102,131,166,0.24)",
              background: dark
                ? "linear-gradient(165deg, rgba(34,52,76,0.7), rgba(26,43,67,0.56))"
                : "linear-gradient(165deg, rgba(242,248,255,0.75), rgba(230,239,249,0.6))",
              boxShadow: dark
                ? "inset 0 1px 0 rgba(194,214,237,0.12), 5px 7px 14px rgba(7,14,24,0.25)"
                : "inset 0 1px 0 rgba(255,255,255,0.68), 5px 6px 12px rgba(169,185,207,0.28)",
            }}
          >
            <div
              style={{
                color: C.dim,
                fontFamily: "JetBrains Mono",
                fontSize: 10,
                marginBottom: 6,
                letterSpacing: 0.8,
              }}
            >
              Source
            </div>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
              {["auto", "online", "offline"].map((m) => (
                <button
                  key={m}
                  onClick={() => setSourceMode(m)}
                  className="quanthunt-pill"
                  style={{
                    borderRadius: 999,
                    border:
                      m === sourceMode
                        ? dark
                          ? "1px solid rgba(164,196,232,0.7)"
                          : "1px solid rgba(95,129,171,0.62)"
                        : dark
                          ? "1px solid rgba(136,159,188,0.38)"
                          : "1px solid rgba(110,137,170,0.34)",
                    background:
                      m === sourceMode
                        ? dark
                          ? "linear-gradient(160deg, rgba(79,112,151,0.5), rgba(48,79,116,0.34))"
                          : "linear-gradient(160deg, rgba(195,218,243,0.86), rgba(169,196,227,0.56))"
                        : dark
                          ? "linear-gradient(160deg, rgba(38,57,84,0.68), rgba(28,46,70,0.56))"
                          : "linear-gradient(160deg, rgba(238,246,255,0.74), rgba(223,235,248,0.56))",
                    color:
                      m === sourceMode ? (dark ? "#d9ebff" : "#244f82") : C.dim,
                    padding: "4px 8px",
                    fontFamily: "JetBrains Mono",
                    fontSize: 10,
                    cursor: "pointer",
                    boxShadow: dark
                      ? "inset 0 1px 0 rgba(198,217,241,0.14), 2px 3px 8px rgba(7,12,20,0.22)"
                      : "inset 0 1px 0 rgba(255,255,255,0.8), 2px 3px 8px rgba(175,190,210,0.34)",
                  }}
                >
                  {m}
                </button>
              ))}
            </div>
          </div>

          <div
            style={{
              borderRadius: 14,
              padding: "8px 10px",
              border: dark
                ? "1px solid rgba(142,166,196,0.28)"
                : "1px solid rgba(102,131,166,0.24)",
              background: dark
                ? "linear-gradient(165deg, rgba(34,52,76,0.7), rgba(26,43,67,0.56))"
                : "linear-gradient(165deg, rgba(242,248,255,0.75), rgba(230,239,249,0.6))",
              boxShadow: dark
                ? "inset 0 1px 0 rgba(194,214,237,0.12), 5px 7px 14px rgba(7,14,24,0.25)"
                : "inset 0 1px 0 rgba(255,255,255,0.68), 5px 6px 12px rgba(169,185,207,0.28)",
            }}
          >
            <div
              style={{
                color: C.dim,
                fontFamily: "JetBrains Mono",
                fontSize: 10,
                marginBottom: 6,
                letterSpacing: 0.8,
              }}
            >
              Focus
            </div>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
              {["general", "analysis", "prediction", "solutions"].map((m) => (
                <button
                  key={m}
                  onClick={() => setFocusMode(m)}
                  className="quanthunt-pill"
                  style={{
                    borderRadius: 999,
                    border:
                      m === focusMode
                        ? dark
                          ? "1px solid rgba(164,196,232,0.7)"
                          : "1px solid rgba(95,129,171,0.62)"
                        : dark
                          ? "1px solid rgba(136,159,188,0.38)"
                          : "1px solid rgba(110,137,170,0.34)",
                    background:
                      m === focusMode
                        ? dark
                          ? "linear-gradient(160deg, rgba(79,112,151,0.5), rgba(48,79,116,0.34))"
                          : "linear-gradient(160deg, rgba(195,218,243,0.86), rgba(169,196,227,0.56))"
                        : dark
                          ? "linear-gradient(160deg, rgba(38,57,84,0.68), rgba(28,46,70,0.56))"
                          : "linear-gradient(160deg, rgba(238,246,255,0.74), rgba(223,235,248,0.56))",
                    color:
                      m === focusMode ? (dark ? "#d9ebff" : "#244f82") : C.dim,
                    padding: "4px 10px",
                    fontFamily: "JetBrains Mono",
                    fontSize: 10,
                    cursor: "pointer",
                    boxShadow: dark
                      ? "inset 0 1px 0 rgba(198,217,241,0.14), 2px 3px 8px rgba(7,12,20,0.22)"
                      : "inset 0 1px 0 rgba(255,255,255,0.8), 2px 3px 8px rgba(175,190,210,0.34)",
                  }}
                >
                  {m}
                </button>
              ))}
            </div>
          </div>
        </div>

        <div
          style={{
            position: "relative",
            zIndex: 1,
            display: "grid",
            gap: 8,
            padding: "10px 12px",
            borderBottom: dark
              ? "1px solid rgba(146,165,188,0.18)"
              : "1px solid rgba(87,122,169,0.16)",
            background: dark
              ? "linear-gradient(180deg, rgba(24,40,63,0.52), rgba(23,38,61,0.28))"
              : "linear-gradient(180deg, rgba(241,247,255,0.58), rgba(230,239,249,0.24))",
          }}
        >
          <div style={{ display: "flex", flexWrap: "wrap", gap: 7 }}>
            {featuredQuick.map((q) => (
              <button
                key={q}
                onClick={() => sendMessage(q)}
                className="quanthunt-chip"
                style={{
                  borderRadius: 11,
                  border: dark
                    ? "1px solid rgba(144,166,193,0.36)"
                    : "1px solid rgba(98,128,164,0.32)",
                  background: dark
                    ? "linear-gradient(160deg, rgba(41,60,86,0.8), rgba(31,49,73,0.58))"
                    : "linear-gradient(160deg, rgba(237,246,255,0.86), rgba(221,234,249,0.62))",
                  color: dark ? "#d5e4f6" : "#2d5487",
                  padding: "6px 10px",
                  fontSize: 10,
                  fontFamily: "JetBrains Mono",
                  cursor: "pointer",
                  boxShadow: dark
                    ? "inset 0 1px 0 rgba(191,213,239,0.14), 4px 6px 12px rgba(8,14,25,0.24)"
                    : "inset 0 1px 0 rgba(255,255,255,0.86), 4px 6px 11px rgba(173,189,210,0.28)",
                }}
              >
                {q}
              </button>
            ))}
          </div>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: 8,
            }}
          >
            <div
              style={{
                color: C.dim,
                fontFamily: "JetBrains Mono",
                fontSize: 10,
                letterSpacing: 0.7,
              }}
            >
              Prompt Library ({quick.length})
            </div>
            <button
              onClick={() => setShowPrompts((v) => !v)}
              className="quanthunt-toggle"
              style={{
                borderRadius: 999,
                border: dark
                  ? "1px solid rgba(144,166,193,0.38)"
                  : "1px solid rgba(96,127,166,0.34)",
                background: dark
                  ? "linear-gradient(160deg, rgba(37,56,83,0.86), rgba(29,47,71,0.62))"
                  : "linear-gradient(160deg, rgba(238,246,255,0.86), rgba(223,235,248,0.64))",
                color: dark ? "#cfe0f4" : "#2c5487",
                padding: "4px 12px",
                fontFamily: "JetBrains Mono",
                fontSize: 10,
                cursor: "pointer",
                boxShadow: dark
                  ? "inset 0 1px 0 rgba(194,217,242,0.14), 3px 5px 10px rgba(9,15,24,0.24)"
                  : "inset 0 1px 0 rgba(255,255,255,0.82), 3px 5px 10px rgba(169,186,207,0.28)",
              }}
            >
              {showPrompts ? "Hide Prompts" : "Show Prompts"}
            </button>
          </div>
          {showPrompts && (
            <div className="quanthunt-prompt-grid">
              {quick.map((q) => (
                <button
                  key={q}
                  onClick={() => sendMessage(q)}
                  className="quanthunt-chip quanthunt-chip-full"
                  style={{
                    borderRadius: 12,
                    border: dark
                      ? "1px solid rgba(144,166,193,0.34)"
                      : "1px solid rgba(98,128,164,0.3)",
                    background: dark
                      ? "linear-gradient(160deg, rgba(40,59,84,0.76), rgba(30,48,72,0.55))"
                      : "linear-gradient(160deg, rgba(237,246,255,0.82), rgba(221,234,249,0.58))",
                    color: dark ? "#d5e4f6" : "#305686",
                    padding: "7px 10px",
                    fontSize: 10,
                    textAlign: "left",
                    fontFamily: "JetBrains Mono",
                    cursor: "pointer",
                    boxShadow: dark
                      ? "inset 0 1px 0 rgba(191,213,239,0.12), 4px 6px 12px rgba(8,14,25,0.2)"
                      : "inset 0 1px 0 rgba(255,255,255,0.82), 4px 6px 12px rgba(173,189,210,0.24)",
                  }}
                >
                  {q}
                </button>
              ))}
            </div>
          )}
        </div>

        <div
          ref={chatRef}
          style={{
            position: "relative",
            zIndex: 1,
            overflowY: "auto",
            padding: 12,
            display: "grid",
            gap: 10,
            background: dark
              ? "linear-gradient(180deg, rgba(24,40,63,0.34), rgba(18,30,49,0.2))"
              : "linear-gradient(180deg, rgba(245,250,255,0.42), rgba(229,238,248,0.24))",
          }}
        >
          {messages.map((m, i) => (
            <div
              key={i}
              style={{
                justifySelf: m.role === "user" ? "end" : "start",
                maxWidth: "88%",
                animation: "quanthuntMsgIn 200ms ease",
              }}
            >
              <div
                style={{
                  padding: "9px 11px",
                  borderRadius: 12,
                  border: `1px solid ${m.role === "user" ? (dark ? "rgba(158,187,220,0.48)" : "rgba(98,128,166,0.34)") : dark ? "rgba(136,166,200,0.32)" : "rgba(100,124,158,0.24)"}`,
                  background:
                    m.role === "user"
                      ? dark
                        ? "linear-gradient(160deg, rgba(52,75,105,0.86), rgba(38,61,90,0.58))"
                        : "linear-gradient(160deg, rgba(205,223,243,0.58), rgba(171,194,222,0.28))"
                      : dark
                        ? "linear-gradient(160deg, rgba(35,55,80,0.78), rgba(24,40,63,0.56))"
                        : "linear-gradient(160deg, rgba(248,252,255,0.74), rgba(230,239,249,0.52))",
                  color: C.text,
                  fontFamily: "JetBrains Mono",
                  fontSize: 12,
                  lineHeight: 1.55,
                  whiteSpace: "pre-wrap",
                  boxShadow: dark
                    ? "inset 0 1px 0 rgba(198,220,244,0.12), 5px 8px 15px rgba(8,13,22,0.25)"
                    : "inset 0 1px 0 rgba(255,255,255,0.82), 5px 8px 15px rgba(170,188,210,0.26)",
                }}
              >
                {m.text}
              </div>
            </div>
          ))}
          {sending && (
            <div
              style={{
                color: dark ? "#c7d8ec" : "#3d628f",
                fontFamily: "JetBrains Mono",
                fontSize: 12,
                animation: "quanthuntThinking 900ms ease-in-out infinite",
              }}
            >
              Thinking...
            </div>
          )}
        </div>

        <div
          style={{
            position: "relative",
            zIndex: 1,
            display: "flex",
            gap: 8,
            borderTop: dark
              ? "1px solid rgba(146,166,190,0.24)"
              : "1px solid rgba(104,131,163,0.22)",
            padding: 12,
            background: dark
              ? "linear-gradient(180deg, rgba(24,39,60,0.62), rgba(20,34,54,0.72))"
              : "linear-gradient(180deg, rgba(239,246,255,0.64), rgba(228,237,248,0.78))",
            boxShadow: dark
              ? "inset 0 1px 0 rgba(188,210,236,0.14)"
              : "inset 0 1px 0 rgba(255,255,255,0.76)",
          }}
        >
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
              }
            }}
            placeholder="Ask safety, PQC limits, testing, or demo script..."
            style={{
              flex: 1,
              borderRadius: 14,
              border: dark
                ? "1px solid rgba(149,174,205,0.4)"
                : "1px solid rgba(103,134,171,0.34)",
              background: dark
                ? "linear-gradient(160deg, rgba(22,38,59,0.86), rgba(17,32,52,0.74))"
                : "linear-gradient(160deg, rgba(249,253,255,0.78), rgba(231,240,250,0.66))",
              color: C.text,
              padding: "10px 12px",
              fontFamily: "JetBrains Mono",
              boxShadow: dark
                ? "inset 0 1px 0 rgba(181,206,236,0.12), inset 0 -1px 0 rgba(8,17,28,0.42)"
                : "inset 0 1px 0 rgba(255,255,255,0.9), inset 0 -1px 0 rgba(167,186,208,0.26)",
            }}
          />
          <Btn
            onClick={() => sendMessage()}
            disabled={sending || !input.trim()}
          >
            SEND
          </Btn>
        </div>
      </div>

      <style>{`
        @keyframes quanthuntMsgIn {
          from { opacity: .1; transform: translateY(8px) scale(.98); }
          to { opacity: 1; transform: translateY(0) scale(1); }
        }
        @keyframes quanthuntThinking {
          0%,100% { opacity: .45; }
          50% { opacity: 1; }
        }
        @keyframes quanthuntLiquidDriftA {
          0% { transform: translate3d(0, 0, 0) scale(1); border-radius: 52% 48% 58% 42%; }
          50% { transform: translate3d(-6px, 6px, 0) scale(1.04); border-radius: 45% 55% 51% 49%; }
          100% { transform: translate3d(0, 0, 0) scale(1); border-radius: 52% 48% 58% 42%; }
        }
        @keyframes quanthuntLiquidDriftB {
          0% { transform: translate3d(0, 0, 0) scale(1); border-radius: 46% 54% 42% 58%; }
          50% { transform: translate3d(8px, -6px, 0) scale(1.05); border-radius: 52% 48% 56% 44%; }
          100% { transform: translate3d(0, 0, 0) scale(1); border-radius: 46% 54% 42% 58%; }
        }
        .quanthunt-liquid-a { animation: quanthuntLiquidDriftA 8.5s ease-in-out infinite; }
        .quanthunt-liquid-b { animation: quanthuntLiquidDriftB 10.5s ease-in-out infinite; }
        .quanthunt-chip, .quanthunt-pill, .quanthunt-toggle { transition: transform 180ms ease, filter 180ms ease, box-shadow 220ms ease; }
        .quanthunt-chip:hover, .quanthunt-pill:hover, .quanthunt-toggle:hover { transform: translateY(-1px); filter: saturate(1.06); }
        .quanthunt-prompt-grid {
          display: grid;
          grid-template-columns: repeat(2, minmax(0, 1fr));
          gap: 8px;
          max-height: 178px;
          overflow-y: auto;
          padding-right: 2px;
        }
        @media (max-width: 560px) {
          .quanthunt-controls { grid-template-columns: 1fr !important; }
          .quanthunt-prompt-grid { grid-template-columns: 1fr; }
        }
      `}</style>
    </>
  );
}

function DocsTab({ scanModel = "general" }) {
  return (
    <Card style={{ padding: 22 }}>
      <TabModeAccent scanModel={scanModel} tabLabel="SYSTEM ARCHITECTURE" />
      <TabGuide
        title="This tab summarizes how QuantHunt works"
        subtitle="Use it to understand scoring logic, scan pipeline, standards coverage, and audit integrity assumptions."
        bullets={[
          "HNDL weighting model",
          "Pipeline overview",
          "Standards and governance references",
        ]}
      />
      <h3 style={{ marginTop: 0, color: C.cyan, fontFamily: "Orbitron" }}>
        <PressureText glow={C.cyan}>Architecture Docs</PressureText>
      </h3>
      <pre
        style={{
          margin: 0,
          color: C.text,
          whiteSpace: "pre-wrap",
          fontFamily: "JetBrains Mono",
          fontSize: 12,
          lineHeight: 1.7,
        }}
      >
        HNDL Score = key_exchange(45%) + auth(25%) + tls(15%) + cert(10%) +
        symmetric(5%)
        {"\n"}Standards: NIST FIPS 203/204/205, CycloneDX 1.6
        {"\n"}Pipeline: Discovery -&gt; TLS/API scan -&gt; heuristic PQC signal
        classify -&gt; CBOM -&gt; Roadmap
        {"\n"}Audit Integrity: Tamper-evident hash-chain blocks (non-consensus,
        non-crypto-currency).
        {"\n"}Bank Focus: India major-bank presets for risk benchmarking.
        {"\n"}Reference Basis: RBI-style cyber controls + TLS/PQC hardening
        guidance.
      </pre>
    </Card>
  );
}

const TABS = [
  ["scanner", "DOMAIN SCAN COMMAND"],
  ["latency", "PQC TLS LATENCY MODEL"],
  ["banklab", "THREAT INSIGHT LAB"],
  ["assets", "DISCOVERED ASSET MAP"],
  ["crypto", "CRYPTO POSTURE ANALYZER"],
  ["xport", "CBOM XPORT"],
  ["roadmap", "REMEDIATION ROADMAP"],
  ["leaderboard", "RISK LEADERBOARD"],
  ["docs", "SYSTEM ARCHITECTURE"],
];

const TAB_VISUALS = {
  scanner: {
    chip: "SCAN",
    darkGlass:
      "linear-gradient(150deg, rgba(18,60,102,0.6), rgba(10,38,73,0.54))",
    lightGlass:
      "linear-gradient(150deg, rgba(238,242,247,0.78), rgba(204,216,232,0.62))",
    accentDark: "rgba(80,206,255,0.84)",
    accentLight: "rgba(74,124,221,0.76)",
  },
  banklab: {
    chip: "LAB",
    darkGlass:
      "linear-gradient(150deg, rgba(21,72,97,0.62), rgba(13,42,58,0.56))",
    lightGlass:
      "linear-gradient(150deg, rgba(238,242,247,0.78), rgba(196,223,224,0.64))",
    accentDark: "rgba(70,242,216,0.84)",
    accentLight: "rgba(66,174,182,0.72)",
  },
  assets: {
    chip: "MAP",
    darkGlass:
      "linear-gradient(150deg, rgba(24,60,92,0.62), rgba(16,36,58,0.56))",
    lightGlass:
      "linear-gradient(150deg, rgba(238,242,247,0.78), rgba(201,214,234,0.64))",
    accentDark: "rgba(99,182,255,0.82)",
    accentLight: "rgba(86,143,228,0.72)",
  },
  crypto: {
    chip: "CRY",
    darkGlass:
      "linear-gradient(150deg, rgba(56,54,95,0.62), rgba(26,24,58,0.56))",
    lightGlass:
      "linear-gradient(150deg, rgba(238,242,247,0.78), rgba(214,208,235,0.64))",
    accentDark: "rgba(170,153,255,0.82)",
    accentLight: "rgba(122,108,228,0.72)",
  },
  cbom: {
    chip: "BOM",
    darkGlass:
      "linear-gradient(150deg, rgba(41,70,94,0.62), rgba(15,36,53,0.56))",
    lightGlass:
      "linear-gradient(150deg, rgba(238,242,247,0.78), rgba(198,218,232,0.64))",
    accentDark: "rgba(112,205,255,0.84)",
    accentLight: "rgba(88,149,228,0.72)",
  },
  xport: {
    chip: "BOM",
    darkGlass:
      "linear-gradient(150deg, rgba(41,70,94,0.62), rgba(15,36,53,0.56))",
    lightGlass:
      "linear-gradient(150deg, rgba(238,242,247,0.78), rgba(198,218,232,0.64))",
    accentDark: "rgba(112,205,255,0.84)",
    accentLight: "rgba(88,149,228,0.72)",
  },
  roadmap: {
    chip: "PLAN",
    darkGlass:
      "linear-gradient(150deg, rgba(61,73,96,0.62), rgba(30,37,53,0.58))",
    lightGlass:
      "linear-gradient(150deg, rgba(238,242,247,0.78), rgba(212,218,228,0.66))",
    accentDark: "rgba(170,199,255,0.82)",
    accentLight: "rgba(101,132,183,0.72)",
  },
  leaderboard: {
    chip: "INTEL",
    darkGlass:
      "linear-gradient(150deg, rgba(29,78,84,0.62), rgba(13,45,54,0.58))",
    lightGlass:
      "linear-gradient(150deg, rgba(238,242,247,0.78), rgba(196,221,218,0.64))",
    accentDark: "rgba(82,234,210,0.84)",
    accentLight: "rgba(72,183,171,0.72)",
  },
  docs: {
    chip: "DOC",
    darkGlass:
      "linear-gradient(150deg, rgba(65,72,84,0.62), rgba(28,33,41,0.58))",
    lightGlass:
      "linear-gradient(150deg, rgba(238,242,247,0.78), rgba(210,216,224,0.66))",
    accentDark: "rgba(189,207,233,0.82)",
    accentLight: "rgba(128,148,177,0.72)",
  },
};

const getTabLabel = (id) => TABS.find(([tid]) => tid === id)?.[1] || id;

class TabContentErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, message: "" };
  }

  static getDerivedStateFromError(error) {
    return {
      hasError: true,
      message: String(error?.message || "Unknown tab error"),
    };
  }

  componentDidCatch(error, info) {
    console.error("Tab render error:", error, info);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div
          style={{
            borderRadius: 16,
            border: `1px solid ${C.red}`,
            background: "rgba(220,53,69,0.12)",
            color: C.red,
            padding: 16,
            fontFamily: "JetBrains Mono",
            fontSize: 12,
          }}
        >
          TAB FAILED TO RENDER. SWITCH TAB OR REFRESH. DETAILS:{" "}
          {this.state.message}
        </div>
      );
    }
    return this.props.children;
  }
}

function PQCLatencyTab({ scanModel = "general" }) {
  const [profile, setProfile] = useState("classical");
  const [rttMs, setRttMs] = useState(72);
  const [lossPct, setLossPct] = useState(1.2);
  const [animateTick, setAnimateTick] = useState(0);
  const [showAnnotations, setShowAnnotations] = useState(true);
  const [bankDomain, setBankDomain] = useState("");
  const [endpointCategory, setEndpointCategory] = useState("Core Web");
  const [currentCipherSuite, setCurrentCipherSuite] = useState(
    "TLS_AES_128_GCM_SHA256",
  );
  const [baselineTtfbMs, setBaselineTtfbMs] = useState("");
  const [remoteMetrics, setRemoteMetrics] = useState(null);
  const [remoteError, setRemoteError] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [networkStatus, setNetworkStatus] = useState(null);

  const MSS = 1460;
  const IW = 10;
  const MIN_RTO = 200;
  const BASE_TLS = 500;
  const CLASSICAL_TLS_BYTES = BASE_TLS;
  const HYBRID_KEM_CT = 1100;
  const HYBRID_SERVER_CERT = 5000;
  const HYBRID_INTERMEDIATE_CERT = 5000;
  const HYBRID_EXTRA_OVERHEAD = 5200;
  const T_CRYPTO_MS = profile === "hybrid" ? 18 : 9;
  const p = Math.max(0, Math.min(0.35, lossPct / 100));

  const cleanedDomain = String(bankDomain || "")
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/\/$/, "");
  const subBranches = useMemo(
    () => [
      `api.${cleanedDomain}`,
      `payments.${cleanedDomain}`,
      `auth.${cleanedDomain}`,
    ],
    [cleanedDomain],
  );

  const hybridChainPayload =
    BASE_TLS +
    HYBRID_KEM_CT +
    HYBRID_SERVER_CERT +
    HYBRID_INTERMEDIATE_CERT +
    HYBRID_EXTRA_OVERHEAD;
  const localPayloadBytes =
    profile === "hybrid" ? hybridChainPayload : CLASSICAL_TLS_BYTES;
  const localNSeg = Math.max(1, Math.ceil(localPayloadBytes / MSS));
  const localFlights =
    localNSeg <= IW ? 0 : Math.ceil(Math.log2(localNSeg / IW + 1));
  const localTProp = rttMs * (2 + localFlights);
  const localPSuccess = Math.pow(1 - p, localNSeg);
  const localRTO = Math.max(MIN_RTO, 3 * rttMs);
  const localTLoss =
    localPSuccess > 0 ? ((1 - localPSuccess) / localPSuccess) * localRTO : 0;
  const localTtfb = T_CRYPTO_MS + localTProp + localTLoss;

  useEffect(() => {
    const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    const payload = {
      connection_type: conn?.type || null,
      effective_type: conn?.effectiveType || null,
      downlink_mbps: Number.isFinite(conn?.downlink) ? Number(conn.downlink) : null,
      rtt_ms: Number.isFinite(conn?.rtt) ? Number(conn.rtt) : null,
      vpn_hint: false,
    };

    fetch(`${API}/api/network-status`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => setNetworkStatus(d))
      .catch(() => setNetworkStatus(null));
  }, []);

  const runLiveScan = async (nextProfile = profile) => {
    if (!cleanedDomain) {
      setRemoteError("Enter a target domain, then run scan.");
      return;
    }
    setIsScanning(true);
    setRemoteError("");
    try {
      const resp = await fetch(`${API}/api/pqc/simulate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          domain: cleanedDomain,
          endpoint_category: endpointCategory,
          current_cipher_suite: currentCipherSuite,
          baseline_ttfb_ms:
            baselineTtfbMs === "" ? undefined : Number(baselineTtfbMs),
          loss_rate: Number(lossPct) / 100,
          profile: nextProfile,
        }),
      });
      if (!resp.ok) {
        const msg = await resp.text();
        throw new Error(msg || `HTTP ${resp.status}`);
      }
      const data = await resp.json();
      setRemoteMetrics(data);
      const measured = Number(data?.live_app_inputs?.measured_rtt_ms || 0);
      if (Number.isFinite(measured) && measured > 0) setRttMs(measured);
      setAnimateTick((v) => v + 1);
    } catch (_err) {
      setRemoteError("Scan failed. Check domain and retry.");
    } finally {
      setIsScanning(false);
    }
  };

  const remoteActive = remoteMetrics
    ? profile === "hybrid"
      ? remoteMetrics.hybrid
      : remoteMetrics.classical
    : null;
  const hasRemote = Boolean(remoteMetrics?.calculated_simulation_output);
  const awaitState = !hasRemote && !isScanning;
  const payloadBytes = hasRemote ? (profile === "hybrid" ? 16800 : 2500) : 0;
  const nSeg = hasRemote ? (remoteActive?.segments ?? 0) : 0;
  const flights = hasRemote ? (remoteActive?.extra_flights ?? 0) : 0;
  const pSuccess = hasRemote ? (remoteActive?.p_success ?? 0) : 0;
  const tLoss = hasRemote ? (remoteActive?.t_loss_ms ?? 0) : 0;
  const ttfb = hasRemote ? (remoteActive?.total_latency_ms ?? 0) : 0;

  const outputBlock = hasRemote
    ? remoteMetrics.calculated_simulation_output
    : {
        connection_status: awaitState ? "Awaiting Scan" : "Scanning",
        classical_metrics: {
          tcp_segments_required: 0,
          extra_tcp_flights: 0,
          expected_packet_loss_penalty_ms: 0.0,
          total_handshake_ttfb_ms: 0.0,
        },
        pqc_hybrid_metrics: {
          tcp_segments_required: 0,
          extra_tcp_flights: 0,
          expected_packet_loss_penalty_ms: 0.0,
          total_handshake_ttfb_ms: 0.0,
          latency_degradation_percentage: 0.0,
        },
      };

  const headline = remoteMetrics?.headline_metrics || {
    absolute_latency_delta_ms: 0,
    latency_degradation_percentage: 0,
    risk_categorization: {
      label: "Safe",
      thresholds_ms: {
        safe_lt: 100,
        warning_range: "100-300",
        critical_gt: 300,
      },
      basis_total_ttfb_ms: 0,
    },
  };

  const baselineRttDisplay = Number(
    remoteMetrics?.live_app_inputs?.measured_rtt_ms ?? rttMs,
  );
  const baselineTtfbDisplay = Number(
    remoteMetrics?.live_app_inputs?.baseline_ttfb_ms ??
      outputBlock.classical_metrics.total_handshake_ttfb_ms ??
      localTtfb,
  );
  const hybridPayloadForMath = 16800;
  const hybridSegmentsDisplay = Number(
    outputBlock.pqc_hybrid_metrics.tcp_segments_required ??
      Math.ceil(hybridPayloadForMath / MSS),
  );
  const extraFlightsDisplay = Number(
    outputBlock.pqc_hybrid_metrics.extra_tcp_flights ??
      (hybridSegmentsDisplay <= IW
        ? 0
        : Math.ceil(Math.log2(hybridSegmentsDisplay / IW + 1))),
  );
  const hybridTtfbDisplay = Number(
    outputBlock.pqc_hybrid_metrics.total_handshake_ttfb_ms ?? ttfb ?? localTtfb,
  );
  const latencyDegradationDisplay = Number(
    outputBlock.pqc_hybrid_metrics.latency_degradation_percentage ??
      headline.latency_degradation_percentage ??
      (baselineTtfbDisplay > 0
        ? ((hybridTtfbDisplay - baselineTtfbDisplay) / baselineTtfbDisplay) * 100
        : 0),
  );

  const fragments = useMemo(
    () =>
      Array.from({ length: nSeg }, (_, i) => {
        const targetSlot = i % 4; // 0 main bank, 1..3 sub-branches
        const lane = [16, 36, 58, 80][targetSlot];
        return {
          i,
          overflow: i >= IW,
          lane,
          targetSlot,
        };
      }),
    [nSeg],
  );

  const streamNodes = useMemo(() => {
    if (!hasRemote || nSeg <= 0) return [];
    const streamCount = Math.max(24, Math.min(72, nSeg * 3));
    return Array.from({ length: streamCount }, (_, i) => {
      const targetSlot = i % 4;
      const lane = [16, 36, 58, 80][targetSlot];
      const overflow = nSeg > IW && i % 7 === 0;
      return {
        id: `stream-${i}`,
        lane,
        overflow,
        targetSlot,
        delay: -(i * 0.14),
        dur: 2.6 + (i % 5) * 0.14,
      };
    });
  }, [hasRemote, nSeg, IW]);

  const launchSimulation = (nextProfile) => {
    setProfile(nextProfile);
    setAnimateTick((v) => v + 1);
  };

  return (
    <div style={{ display: "grid", gap: 16 }}>
      <Card style={{ padding: 18, position: "relative", overflow: "hidden" }}>
        <div
          style={{
            position: "absolute",
            inset: "-35% auto auto -10%",
            width: 320,
            height: 240,
            background:
              "radial-gradient(circle at 35% 35%, rgba(185,152,112,0.24), rgba(185,152,112,0))",
            pointerEvents: "none",
          }}
        />
        <TabModeAccent scanModel={scanModel} tabLabel="PQC TLS LATENCY MODEL" />
        <TabGuide
          title="* QUANTHUNT BANK-MESH LATENCY STUDIO"
          subtitle="Scanner fragments route to bank core and sub-branches while formulas update in real time with RTT and packet loss."
          bullets={[
            "Domain + sub-branch interaction",
            "Fragment routing and congestion windows",
            "Gold/Emerald formula highlights",
          ]}
        />
      </Card>

      <Card style={{ padding: 18, display: "grid", gap: 14 }}>
        <div
          style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr", gap: 10 }}
        >
          <div
            style={{
              border: `1px solid ${C.border}`,
              borderRadius: 12,
              padding: 12,
              background: "rgba(185,152,112,0.06)",
            }}
          >
            <div
              style={{
                color: C.dim,
                fontFamily: "JetBrains Mono",
                fontSize: 10,
                marginBottom: 6,
              }}
            >
              BANK DOMAIN TARGET
            </div>
            <input
              value={bankDomain}
              onChange={(e) => setBankDomain(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  runLiveScan(profile);
                }
              }}
              placeholder="bank.example"
              style={{
                width: "100%",
                boxSizing: "border-box",
                borderRadius: 10,
                border: `1px solid ${C.border}`,
                background: "rgba(255,255,255,0.18)",
                color: C.text,
                padding: "8px 10px",
                fontFamily: "JetBrains Mono",
                fontSize: 12,
              }}
            />
          </div>
          <div
            style={{
              border: `1px solid ${C.border}`,
              borderRadius: 12,
              padding: 12,
              background: "rgba(111,194,148,0.08)",
            }}
          >
            <div
              style={{
                color: C.dim,
                fontFamily: "JetBrains Mono",
                fontSize: 10,
                marginBottom: 6,
              }}
            >
              SUB-BRANCH ROUTES
            </div>
            <div
              style={{
                display: "grid",
                gap: 4,
                color: C.text,
                fontFamily: "JetBrains Mono",
                fontSize: 11,
              }}
            >
              {(cleanedDomain
                ? subBranches
                : [
                    "api.target-domain",
                    "payments.target-domain",
                    "auth.target-domain",
                  ]
              ).map((b) => (
                <div key={b}>- {b}</div>
              ))}
            </div>
            {remoteError && (
              <div
                style={{
                  marginTop: 6,
                  color: C.orange,
                  fontFamily: "JetBrains Mono",
                  fontSize: 10,
                }}
              >
                {remoteError}
              </div>
            )}
          </div>
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
            gap: 10,
          }}
        >
          <div
            style={{
              border: `1px solid ${C.border}`,
              borderRadius: 12,
              padding: 12,
              background: "rgba(132,170,208,0.08)",
            }}
          >
            <div
              style={{
                color: C.dim,
                fontFamily: "JetBrains Mono",
                fontSize: 10,
                marginBottom: 6,
              }}
            >
              ENDPOINT CATEGORY
            </div>
            <select
              value={endpointCategory}
              onChange={(e) => setEndpointCategory(e.target.value)}
              style={{
                width: "100%",
                borderRadius: 10,
                border: `1px solid ${C.border}`,
                background: "rgba(255,255,255,0.2)",
                color: C.text,
                padding: "8px 10px",
                fontFamily: "JetBrains Mono",
                fontSize: 12,
              }}
            >
              <option>Core Web</option>
              <option>Payment Gateway</option>
              <option>Mobile API</option>
              <option>Auth Server</option>
            </select>
          </div>
          <div
            style={{
              border: `1px solid ${C.border}`,
              borderRadius: 12,
              padding: 12,
              background: "rgba(185,152,112,0.06)",
            }}
          >
            <div
              style={{
                color: C.dim,
                fontFamily: "JetBrains Mono",
                fontSize: 10,
                marginBottom: 6,
              }}
            >
              CURRENT CIPHER SUITE
            </div>
            <input
              value={currentCipherSuite}
              onChange={(e) => setCurrentCipherSuite(e.target.value)}
              placeholder="TLS_AES_128_GCM_SHA256"
              style={{
                width: "100%",
                boxSizing: "border-box",
                borderRadius: 10,
                border: `1px solid ${C.border}`,
                background: "rgba(255,255,255,0.18)",
                color: C.text,
                padding: "8px 10px",
                fontFamily: "JetBrains Mono",
                fontSize: 12,
              }}
            />
          </div>
          <div
            style={{
              border: `1px solid ${C.border}`,
              borderRadius: 12,
              padding: 12,
              background: "rgba(111,194,148,0.08)",
            }}
          >
            <div
              style={{
                color: C.dim,
                fontFamily: "JetBrains Mono",
                fontSize: 10,
                marginBottom: 6,
              }}
            >
              BASELINE TTFB (ms)
            </div>
            <input
              type="number"
              min="1"
              step="0.1"
              value={baselineTtfbMs}
              onChange={(e) => setBaselineTtfbMs(e.target.value)}
              placeholder="Auto from classical profile"
              style={{
                width: "100%",
                boxSizing: "border-box",
                borderRadius: 10,
                border: `1px solid ${C.border}`,
                background: "rgba(255,255,255,0.18)",
                color: C.text,
                padding: "8px 10px",
                fontFamily: "JetBrains Mono",
                fontSize: 12,
              }}
            />
          </div>
        </div>

        <div
          style={{
            display: "flex",
            gap: 8,
            flexWrap: "wrap",
            alignItems: "center",
          }}
        >
          <button
            className="qh-latency-btn liquid-tap"
            onClick={() => launchSimulation("classical")}
            style={{
              borderColor: profile === "classical" ? C.green : C.border,
              color: profile === "classical" ? C.green : C.dim,
              background:
                profile === "classical"
                  ? "rgba(111,194,148,0.14)"
                  : "rgba(185,152,112,0.06)",
              boxShadow:
                profile === "classical"
                  ? "inset 0 1px 0 rgba(255,255,255,0.62), 0 10px 20px rgba(52,79,64,0.2)"
                  : "inset 0 1px 0 rgba(255,255,255,0.4), 0 6px 14px rgba(41,58,54,0.14)",
            }}
          >
            * CLASSICAL PROFILE
          </button>
          <button
            className="qh-latency-btn liquid-tap"
            onClick={() => launchSimulation("hybrid")}
            style={{
              borderColor: profile === "hybrid" ? C.orange : C.border,
              color: profile === "hybrid" ? C.orange : C.dim,
              background:
                profile === "hybrid"
                  ? "rgba(185,152,112,0.16)"
                  : "rgba(185,152,112,0.06)",
              boxShadow:
                profile === "hybrid"
                  ? "inset 0 1px 0 rgba(255,255,255,0.58), 0 10px 20px rgba(106,83,38,0.2)"
                  : "inset 0 1px 0 rgba(255,255,255,0.4), 0 6px 14px rgba(56,49,34,0.14)",
            }}
          >
            * HYBRID PQC PROFILE
          </button>
          <button
            className="qh-latency-btn liquid-tap"
            onClick={() => runLiveScan(profile)}
            disabled={isScanning}
            style={{
              borderColor: C.cyan,
              color: C.text,
              background:
                "linear-gradient(145deg, rgba(185,152,112,0.2), rgba(111,194,148,0.2))",
              boxShadow:
                "inset 0 1px 0 rgba(255,255,255,0.58), 0 10px 22px rgba(48,62,52,0.18)",
              opacity: isScanning ? 0.75 : 1,
            }}
          >
            {isScanning ? "* SCANNING..." : "* RUN LIVE SCAN"}
          </button>
          <label
            style={{
              marginLeft: "auto",
              display: "flex",
              alignItems: "center",
              gap: 8,
              color: C.dim,
              fontFamily: "JetBrains Mono",
              fontSize: 11,
            }}
          >
            <input
              type="checkbox"
              checked={showAnnotations}
              onChange={(e) => setShowAnnotations(e.target.checked)}
            />
            SHOW ANNOTATIONS
          </label>
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
            gap: 10,
          }}
        >
          <div
            style={{
              border: `1px solid ${C.border}`,
              borderRadius: 12,
              padding: 12,
              background: "rgba(185,152,112,0.06)",
            }}
          >
            <div
              style={{
                color: C.dim,
                fontFamily: "JetBrains Mono",
                fontSize: 10,
              }}
            >
              ROUND TRIP TIME (ms)
            </div>
            <input
              type="range"
              min={20}
              max={250}
              value={rttMs}
              onChange={(e) => setRttMs(Number(e.target.value))}
              style={{ width: "100%", marginTop: 6 }}
            />
            <div
              style={{
                color: C.text,
                fontFamily: "JetBrains Mono",
                fontSize: 12,
              }}
            >
              {rttMs} ms
            </div>
          </div>
          <div
            style={{
              border: `1px solid ${C.border}`,
              borderRadius: 12,
              padding: 12,
              background: "rgba(132,170,208,0.08)",
            }}
          >
            <div
              style={{
                color: C.dim,
                fontFamily: "JetBrains Mono",
                fontSize: 10,
              }}
            >
              PACKET LOSS p (%)
            </div>
            <input
              type="range"
              min={0}
              max={8}
              step={0.1}
              value={lossPct}
              onChange={(e) => setLossPct(Number(e.target.value))}
              style={{ width: "100%", marginTop: 6 }}
            />
            <div
              style={{
                color: C.text,
                fontFamily: "JetBrains Mono",
                fontSize: 12,
              }}
            >
              {lossPct.toFixed(1)}%
            </div>
          </div>
          <div
            style={{
              border: `1px solid ${C.border}`,
              borderRadius: 12,
              padding: 12,
              background: "rgba(111,194,148,0.08)",
            }}
          >
            <div
              style={{
                color: C.dim,
                fontFamily: "JetBrains Mono",
                fontSize: 10,
              }}
            >
              PROFILE
            </div>
            <div
              style={{
                color: C.text,
                fontFamily: "JetBrains Mono",
                fontSize: 12,
              }}
            >
              {profile.toUpperCase()}
            </div>
          </div>
        </div>

        <div
          style={{
            border: `1px solid ${C.border}`,
            borderRadius: 14,
            padding: 12,
            background:
              "linear-gradient(145deg, rgba(244,232,209,0.58), rgba(214,230,215,0.52))",
            boxShadow:
              "inset 0 1px 0 rgba(255,255,255,0.8), 0 12px 24px rgba(106,95,70,0.12)",
          }}
        >
          <div
            style={{
              color: C.dim,
              fontFamily: "JetBrains Mono",
              fontSize: 10,
              marginBottom: 6,
            }}
          >
            SIMULATION CONNECTION STATUS
          </div>
          <div
            style={{
              color:
                outputBlock.connection_status === "Connected"
                  ? C.green
                  : C.orange,
              fontFamily: "Orbitron",
              fontSize: 14,
            }}
          >
            {outputBlock.connection_status}
          </div>
          <div
            style={{
              marginTop: 8,
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit,minmax(180px,1fr))",
              gap: 8,
              fontFamily: "JetBrains Mono",
              fontSize: 11,
            }}
          >
            <div
              style={{
                border: `1px solid ${C.border}`,
                borderRadius: 10,
                padding: "6px 8px",
                background: "rgba(255,255,255,0.28)",
              }}
            >
              target_domain:{" "}
              {remoteMetrics?.live_app_inputs?.target_domain || ""}
            </div>
            <div
              style={{
                border: `1px solid ${C.border}`,
                borderRadius: 10,
                padding: "6px 8px",
                background: "rgba(255,255,255,0.28)",
              }}
            >
              endpoint_category:{" "}
              {remoteMetrics?.live_app_inputs?.endpoint_category ||
                endpointCategory}
            </div>
            <div
              style={{
                border: `1px solid ${C.border}`,
                borderRadius: 10,
                padding: "6px 8px",
                background: "rgba(255,255,255,0.28)",
              }}
            >
              current_cipher_suite:{" "}
              {remoteMetrics?.live_app_inputs?.current_cipher_suite ||
                currentCipherSuite}
            </div>
            <div
              style={{
                border: `1px solid ${C.border}`,
                borderRadius: 10,
                padding: "6px 8px",
                background: "rgba(255,255,255,0.28)",
              }}
            >
              measured_rtt_ms:{" "}
              {Number(
                remoteMetrics?.live_app_inputs?.measured_rtt_ms || 0,
              ).toFixed(1)}
            </div>
            <div
              style={{
                border: `1px solid ${C.border}`,
                borderRadius: 10,
                padding: "6px 8px",
                background: "rgba(255,255,255,0.28)",
              }}
            >
              baseline_ttfb_ms:{" "}
              {Number(
                remoteMetrics?.live_app_inputs?.baseline_ttfb_ms || 0,
              ).toFixed(2)}
            </div>
            <div
              style={{
                border: `1px solid ${C.border}`,
                borderRadius: 10,
                padding: "6px 8px",
                background: "rgba(255,255,255,0.28)",
              }}
            >
              estimated_packet_loss_pct:{" "}
              {Number(
                remoteMetrics?.live_app_inputs?.estimated_packet_loss_pct ||
                  lossPct,
              ).toFixed(2)}
              %
            </div>
            <div
              style={{
                border: `1px solid ${C.border}`,
                borderRadius: 10,
                padding: "6px 8px",
                background: "rgba(255,255,255,0.28)",
              }}
            >
              hybrid_latency_degradation:{" "}
              {Number(
                outputBlock.pqc_hybrid_metrics.latency_degradation_percentage ||
                  0,
              ).toFixed(2)}
              %
            </div>
            <div
              style={{
                border: `1px solid ${C.border}`,
                borderRadius: 10,
                padding: "6px 8px",
                background: "rgba(255,255,255,0.28)",
              }}
            >
              detected_network_type: {networkStatus?.network?.type || "unknown"}
            </div>
            <div
              style={{
                border: `1px solid ${C.border}`,
                borderRadius: 10,
                padding: "6px 8px",
                background: "rgba(255,255,255,0.28)",
              }}
            >
              ip: {networkStatus?.network?.ip || networkStatus?.ip || "unknown"}
            </div>
            <div
              style={{
                border: `1px solid ${C.border}`,
                borderRadius: 10,
                padding: "6px 8px",
                background: "rgba(255,255,255,0.28)",
              }}
            >
              vpn_status: {networkStatus?.vpn_detected ? "detected" : "not detected"}
            </div>
          </div>
        </div>

        <div
          style={{
            border: `1px solid ${C.border}`,
            borderRadius: 14,
            padding: 12,
            background:
              "linear-gradient(145deg, rgba(214,230,215,0.52), rgba(244,232,209,0.58))",
            boxShadow:
              "inset 0 1px 0 rgba(255,255,255,0.8), 0 12px 24px rgba(106,95,70,0.1)",
            display: "grid",
            gap: 10,
          }}
        >
          <div
            style={{ color: C.dim, fontFamily: "JetBrains Mono", fontSize: 10 }}
          >
            HEADLINE METRICS (ANALYSIS)
          </div>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit,minmax(200px,1fr))",
              gap: 8,
              fontFamily: "JetBrains Mono",
              fontSize: 11,
            }}
          >
            <div
              style={{
                border: `1px solid ${C.border}`,
                borderRadius: 10,
                padding: "6px 8px",
                background: "rgba(255,255,255,0.28)",
              }}
            >
              absolute_latency_delta_ms:{" "}
              {Number(headline.absolute_latency_delta_ms || 0).toFixed(2)}
            </div>
            <div
              style={{
                border: `1px solid ${C.border}`,
                borderRadius: 10,
                padding: "6px 8px",
                background: "rgba(255,255,255,0.28)",
              }}
            >
              latency_degradation_percentage:{" "}
              {Number(headline.latency_degradation_percentage || 0).toFixed(2)}%
            </div>
            <div
              style={{
                border: `1px solid ${C.border}`,
                borderRadius: 10,
                padding: "6px 8px",
                background: "rgba(255,255,255,0.28)",
              }}
            >
              risk_categorization:{" "}
              {headline.risk_categorization?.label || "Safe"}
            </div>
            <div
              style={{
                border: `1px solid ${C.border}`,
                borderRadius: 10,
                padding: "6px 8px",
                background: "rgba(255,255,255,0.28)",
              }}
            >
              thresholds(ms): Safe &lt; 100 | Warning 100-300 | Critical &gt;
              300
            </div>
          </div>
        </div>

        <div
          style={{
            border: `1px solid ${C.border}`,
            borderRadius: 14,
            padding: 12,
            background:
              "linear-gradient(145deg, rgba(255,245,214,0.56), rgba(219,241,229,0.48))",
            boxShadow:
              "inset 0 1px 0 rgba(255,255,255,0.8), 0 12px 24px rgba(106,95,70,0.1)",
            display: "grid",
            gap: 8,
          }}
        >
          <div style={{ color: C.dim, fontFamily: "JetBrains Mono", fontSize: 10 }}>
            LATENCY PROOF PANEL
          </div>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit,minmax(240px,1fr))",
              gap: 8,
              fontFamily: "JetBrains Mono",
              fontSize: 11,
            }}
          >
            <div style={{ border: `1px solid ${C.border}`, borderRadius: 10, padding: "8px 10px", background: "rgba(255,255,255,0.28)" }}>
              <div style={{ color: C.dim, marginBottom: 4 }}>Baseline RTT (ms)</div>
              <div style={{ color: C.text }}>
                Current ping = {baselineRttDisplay.toFixed(2)} ms
              </div>
            </div>
            <div style={{ border: `1px solid ${C.border}`, borderRadius: 10, padding: "8px 10px", background: "rgba(255,255,255,0.28)" }}>
              <div style={{ color: C.dim, marginBottom: 4 }}>TCP Segments Required</div>
              <div style={{ color: C.text }}>
                ceil(S_TLS/MSS) = ceil({hybridPayloadForMath}/{MSS}) = {hybridSegmentsDisplay}
              </div>
            </div>
            <div style={{ border: `1px solid ${C.border}`, borderRadius: 10, padding: "8px 10px", background: "rgba(255,255,255,0.28)" }}>
              <div style={{ color: C.dim, marginBottom: 4 }}>Extra TCP Flights</div>
              <div style={{ color: C.text }}>
                {hybridSegmentsDisplay > IW
                  ? `N_seg(${hybridSegmentsDisplay}) > iw(${IW}) -> extra_flights = ${extraFlightsDisplay}`
                  : `N_seg(${hybridSegmentsDisplay}) <= iw(${IW}) -> extra_flights = 0`}
              </div>
            </div>
            <div style={{ border: `1px solid ${C.border}`, borderRadius: 10, padding: "8px 10px", background: "rgba(255,255,255,0.28)" }}>
              <div style={{ color: C.dim, marginBottom: 4 }}>Latency Degradation %</div>
              <div style={{ color: C.text }}>
                (({hybridTtfbDisplay.toFixed(2)} - {baselineTtfbDisplay.toFixed(2)}) / {baselineTtfbDisplay > 0 ? baselineTtfbDisplay.toFixed(2) : "baseline"}) x 100 = {latencyDegradationDisplay.toFixed(2)}%
              </div>
            </div>
          </div>
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
            gap: 10,
          }}
        >
          <div
            style={{
              border: `1px solid ${C.border}`,
              borderRadius: 12,
              padding: 10,
              background:
                "linear-gradient(160deg, rgba(185,152,112,0.18), rgba(185,152,112,0.07))",
            }}
          >
            <div
              style={{
                color: C.dim,
                fontFamily: "JetBrains Mono",
                fontSize: 10,
              }}
            >
              S_TLS
            </div>
            <div
              style={{
                color: C.orange,
                fontFamily: "JetBrains Mono",
                fontSize: 18,
              }}
            >
              {payloadBytes.toLocaleString()} B
            </div>
            <div
              style={{
                color: C.dim,
                fontFamily: "JetBrains Mono",
                fontSize: 10,
                marginTop: 4,
              }}
            >
              {hasRemote
                ? profile === "hybrid"
                  ? "PQC chain modeled"
                  : "Base TLS modeled"
                : "Run scan to populate"}
            </div>
          </div>
          <div
            style={{
              border: `1px solid ${C.border}`,
              borderRadius: 12,
              padding: 10,
              background:
                "linear-gradient(160deg, rgba(111,194,148,0.2), rgba(111,194,148,0.07))",
            }}
          >
            <div
              style={{
                color: C.dim,
                fontFamily: "JetBrains Mono",
                fontSize: 10,
              }}
            >
              N_SEG
            </div>
            <div
              style={{
                color: C.green,
                fontFamily: "JetBrains Mono",
                fontSize: 18,
              }}
            >
              {nSeg}
            </div>
          </div>
          <div
            style={{
              border: `1px solid ${C.border}`,
              borderRadius: 12,
              padding: 10,
              background:
                "linear-gradient(160deg, rgba(111,194,148,0.16), rgba(132,170,208,0.08))",
            }}
          >
            <div
              style={{
                color: C.dim,
                fontFamily: "JetBrains Mono",
                fontSize: 10,
              }}
            >
              FLIGHTS
            </div>
            <div
              style={{
                color: C.green,
                fontFamily: "JetBrains Mono",
                fontSize: 18,
              }}
            >
              {flights}
            </div>
          </div>
          <div
            style={{
              border: `1px solid ${C.border}`,
              borderRadius: 12,
              padding: 10,
              background:
                "linear-gradient(160deg, rgba(185,152,112,0.18), rgba(132,170,208,0.07))",
            }}
          >
            <div
              style={{
                color: C.dim,
                fontFamily: "JetBrains Mono",
                fontSize: 10,
              }}
            >
              TOTAL_TTFB
            </div>
            <div
              style={{
                color: ttfb > 220 ? C.red : C.orange,
                fontFamily: "JetBrains Mono",
                fontSize: 18,
              }}
            >
              {ttfb.toFixed(1)} ms
            </div>
          </div>
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit,minmax(240px,1fr))",
            gap: 10,
          }}
        >
          <div
            style={{
              border: `1px solid rgba(185,152,112,0.48)`,
              borderRadius: 12,
              padding: 10,
              background:
                "linear-gradient(155deg, rgba(185,152,112,0.19), rgba(185,152,112,0.08))",
              backdropFilter: "blur(8px)",
            }}
          >
            <div
              style={{
                color: C.orange,
                fontFamily: "Orbitron",
                fontSize: 11,
                marginBottom: 6,
              }}
            >
              CLASSICAL METRICS
            </div>
            <div
              style={{
                color: C.text,
                fontFamily: "JetBrains Mono",
                fontSize: 11,
                lineHeight: 1.8,
              }}
            >
              <div>
                tcp_segments_required:{" "}
                {outputBlock.classical_metrics.tcp_segments_required}
              </div>
              <div>
                extra_tcp_flights:{" "}
                {outputBlock.classical_metrics.extra_tcp_flights}
              </div>
              <div>
                expected_packet_loss_penalty_ms:{" "}
                {Number(
                  outputBlock.classical_metrics.expected_packet_loss_penalty_ms,
                ).toFixed(2)}
              </div>
              <div>
                total_handshake_ttfb_ms:{" "}
                {Number(
                  outputBlock.classical_metrics.total_handshake_ttfb_ms,
                ).toFixed(2)}
              </div>
            </div>
          </div>
          <div
            style={{
              border: `1px solid rgba(111,194,148,0.48)`,
              borderRadius: 12,
              padding: 10,
              background:
                "linear-gradient(155deg, rgba(111,194,148,0.2), rgba(111,194,148,0.08))",
              backdropFilter: "blur(8px)",
            }}
          >
            <div
              style={{
                color: C.green,
                fontFamily: "Orbitron",
                fontSize: 11,
                marginBottom: 6,
              }}
            >
              PQC HYBRID METRICS
            </div>
            <div
              style={{
                color: C.text,
                fontFamily: "JetBrains Mono",
                fontSize: 11,
                lineHeight: 1.8,
              }}
            >
              <div>
                tcp_segments_required:{" "}
                {outputBlock.pqc_hybrid_metrics.tcp_segments_required}
              </div>
              <div>
                extra_tcp_flights:{" "}
                {outputBlock.pqc_hybrid_metrics.extra_tcp_flights}
              </div>
              <div>
                expected_packet_loss_penalty_ms:{" "}
                {Number(
                  outputBlock.pqc_hybrid_metrics
                    .expected_packet_loss_penalty_ms,
                ).toFixed(2)}
              </div>
              <div>
                total_handshake_ttfb_ms:{" "}
                {Number(
                  outputBlock.pqc_hybrid_metrics.total_handshake_ttfb_ms,
                ).toFixed(2)}
              </div>
              <div>
                latency_degradation_percentage:{" "}
                {Number(
                  outputBlock.pqc_hybrid_metrics.latency_degradation_percentage,
                ).toFixed(2)}
                %
              </div>
            </div>
          </div>
        </div>
      </Card>

      <Card style={{ padding: 18 }}>
        <div
          style={{ color: C.cyan, fontFamily: "Orbitron", marginBottom: 10 }}
        >
          <PressureText glow={C.cyan}>
            * LIQUID CHROME MESH: SCANNER TO BANK GRAPH
          </PressureText>
        </div>
        <div
          style={{
            position: "relative",
            borderRadius: 18,
            border: `1px solid ${C.border}`,
            background:
              "linear-gradient(180deg, rgba(185,152,112,0.1), rgba(132,170,208,0.08))",
            boxShadow:
              "inset 0 20px 34px rgba(255,255,255,0.04), inset 0 -20px 28px rgba(0,0,0,0.14)",
            overflow: "hidden",
            padding: 16,
          }}
        >
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              color: C.dim,
              fontFamily: "JetBrains Mono",
              fontSize: 10,
              marginBottom: 8,
            }}
          >
            <span>QUANTHUNT SCANNER CORE</span>
            <span>{cleanedDomain || "target pending"}</span>
          </div>

          <div
            style={{
              position: "relative",
              height: 280,
              borderRadius: 14,
              border: `1px solid ${C.border}`,
              background:
                "linear-gradient(160deg, rgba(176,191,208,0.28), rgba(157,173,191,0.2))",
            }}
          >
            <div
              style={{
                position: "absolute",
                left: 16,
                top: "50%",
                width: 155,
                transform: "translateY(-50%)",
                borderRadius: 999,
                border: `1px solid ${C.green}`,
                background: "rgba(111,194,148,0.14)",
                color: C.green,
                padding: "8px 10px",
                fontFamily: "JetBrains Mono",
                fontSize: 10,
                textAlign: "center",
              }}
            >
              QUANTHUNT SCANNER
            </div>

            <div
              style={{
                position: "absolute",
                right: 16,
                top: 18,
                width: 220,
                borderRadius: 999,
                border: `1px solid ${C.orange}`,
                background: "rgba(185,152,112,0.14)",
                color: C.orange,
                padding: "8px 10px",
                fontFamily: "JetBrains Mono",
                fontSize: 10,
                textAlign: "center",
              }}
            >
              BANK CORE: {cleanedDomain || "target pending"}
            </div>

            {(cleanedDomain
              ? subBranches
              : [
                  "api.target-domain",
                  "payments.target-domain",
                  "auth.target-domain",
                ]
            ).map((b, idx) => (
              <div
                key={b}
                style={{
                  position: "absolute",
                  right: 22,
                  top: `${94 + idx * 50}px`,
                  width: 214,
                  borderRadius: 999,
                  border: `1px solid ${C.border}`,
                  background: "rgba(132,170,208,0.12)",
                  color: C.text,
                  padding: "7px 10px",
                  fontFamily: "JetBrains Mono",
                  fontSize: 10,
                  textAlign: "center",
                }}
              >
                BRANCH: {b}
              </div>
            ))}

            {[16, 36, 58, 80].map((lane) => (
              <div
                key={lane}
                style={{
                  position: "absolute",
                  left: 180,
                  right: 248,
                  top: `${lane}%`,
                  height: 1,
                  background:
                    "linear-gradient(90deg, rgba(111,194,148,0.22), rgba(185,152,112,0.4), rgba(132,170,208,0.22))",
                }}
              />
            ))}

            {streamNodes.map(
              ({ id, overflow, lane, targetSlot, delay, dur }) => (
                <div
                  key={`${animateTick}-${id}`}
                  className={`qh-latency-frag ${overflow ? "overflow" : "ok"}`}
                  style={{
                    animationDelay: `${delay}s`,
                    animationDuration: `${dur}s`,
                    top: `${lane}%`,
                    "--travel": `${targetSlot === 0 ? 640 : 610}px`,
                  }}
                  title={
                    targetSlot === 0
                      ? "Core routing fragment"
                      : "Branch routing fragment"
                  }
                />
              ),
            )}

            {showAnnotations && nSeg > IW && (
              <div
                style={{
                  position: "absolute",
                  right: 12,
                  bottom: 14,
                  zIndex: 3,
                  color: C.orange,
                  border: `1px solid ${C.orange}`,
                  background: "rgba(185,152,112,0.14)",
                  borderRadius: 10,
                  fontFamily: "JetBrains Mono",
                  fontSize: 10,
                  padding: "5px 10px",
                  maxWidth: 250,
                }}
              >
                IW=10 EXCEEDED. SECOND FLIGHT + EXTRA RTT
              </div>
            )}

            {showAnnotations && (
              <div
                style={{
                  position: "absolute",
                  left: 14,
                  bottom: 10,
                  zIndex: 2,
                  color: C.text,
                  background: "rgba(245,238,224,0.5)",
                  border: `1px solid ${C.border}`,
                  borderRadius: 10,
                  padding: "5px 8px",
                  fontFamily: "JetBrains Mono",
                  fontSize: 10,
                }}
              >
                P_success {(pSuccess * 100).toFixed(2)}% | T_loss{" "}
                {tLoss.toFixed(1)} ms | Flights {flights}
              </div>
            )}
          </div>
        </div>
      </Card>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit,minmax(300px,1fr))",
          gap: 14,
        }}
      >
        <Card style={{ padding: 16 }}>
          <div
            style={{ fontFamily: "Orbitron", color: C.orange, marginBottom: 8 }}
          >
            <PressureText glow={C.orange}>
              * GOLD-EMERALD FORMULA MATRIX
            </PressureText>
          </div>
          <div
            style={{
              display: "grid",
              gap: 8,
              fontFamily: "JetBrains Mono",
              fontSize: 12,
            }}
          >
            <div className="qh-formula-chip gold">
              TOTAL_TTFB = T_crypto + T_prop + T_loss
            </div>
            <div className="qh-formula-chip emerald">
              S_TLS = S_base + S_KEM_ct + S_cert_server + S_cert_intermediate +
              S_chain_overhead
            </div>
            <div className="qh-formula-chip gold">
              N_seg = ceil(S_TLS / MSS)
            </div>
            <div className="qh-formula-chip emerald">
              Flights = ceil(log2((N_seg / iw) + 1))
            </div>
            <div className="qh-formula-chip gold">
              P_success = (1 - p)^N_seg
            </div>
            <div className="qh-formula-chip emerald">
              T_loss = ((1 - P_success) / P_success) x RTO
            </div>
          </div>
        </Card>
        <Card style={{ padding: 16 }}>
          <div
            style={{ fontFamily: "Orbitron", color: C.blue, marginBottom: 8 }}
          >
            <PressureText glow={C.blue}>
              * INTERACTIVE ANALYST NOTES
            </PressureText>
          </div>
          <div
            style={{
              color: C.dim,
              fontFamily: "JetBrains Mono",
              fontSize: 11,
              lineHeight: 1.75,
            }}
          >
            <div>
              - Scanner fragments split between bank core and branch endpoints
              to mimic enterprise routing behavior.
            </div>
            <div>
              - Hybrid profile increases fragment count and pushes
              congestion-window pressure into second-flight territory.
            </div>
            <div>
              - Gold chips highlight latency-critical equations; emerald chips
              highlight transport and probability mechanics.
            </div>
            <div>
              - This section directly mirrors how QuantHunt can explain TTFB
              degradations during PQC migration planning.
            </div>
          </div>
        </Card>
      </div>

      <style>{`
        .qh-latency-btn {
          border: 1px solid;
          border-radius: 11px;
          padding: 8px 12px;
          cursor: pointer;
          font-family: JetBrains Mono;
          font-size: 11px;
          letter-spacing: .04em;
          backdrop-filter: blur(6px);
        }
        .qh-latency-frag {
          position: absolute;
          left: 182px;
          width: 14px;
          height: 7px;
          border-radius: 999px;
          opacity: .9;
          animation: qhLatencyBranchLoop 2.8s linear infinite;
        }
        .qh-latency-frag.ok {
          background: linear-gradient(90deg, rgba(111,194,148,0.95), rgba(185,152,112,0.9));
          box-shadow: 0 0 10px rgba(111,194,148,0.45);
        }
        .qh-latency-frag.overflow {
          background: linear-gradient(90deg, rgba(185,152,112,1), rgba(227,165,128,0.95));
          box-shadow: 0 0 11px rgba(185,152,112,0.58);
        }
        .qh-formula-chip {
          border-radius: 10px;
          padding: 8px 10px;
          border: 1px solid;
          backdrop-filter: blur(5px);
        }
        .qh-formula-chip.gold {
          color: #b27f1f;
          border-color: rgba(185,152,112,0.58);
          background: linear-gradient(155deg, rgba(185,152,112,0.2), rgba(185,152,112,0.08));
        }
        .qh-formula-chip.emerald {
          color: #2f7f58;
          border-color: rgba(111,194,148,0.58);
          background: linear-gradient(155deg, rgba(111,194,148,0.22), rgba(111,194,148,0.08));
        }
        @keyframes qhLatencyBranchLoop {
          0% { transform: translateX(0) scale(.85); opacity: 0; }
          8% { opacity: .92; }
          86% { opacity: .92; }
          100% { transform: translateX(var(--travel, 610px)) scale(1); opacity: 0; }
        }
      `}</style>
    </div>
  );
}

function App() {
  const [theme, setTheme] = useState(() => {
    try {
      return localStorage.getItem("quanthunt_theme") || "light";
    } catch {
      return "light";
    }
  });
  const [unlocked, setUnlocked] = useState(false);
  const [tab, setTab] = useState("scanner");
  const [prevTab, setPrevTab] = useState("scanner");
  const [tabFxTick, setTabFxTick] = useState(0);
  const [scanModel, setScanModel] = useState("general");
  const [prevScanModel, setPrevScanModel] = useState("general");
  const [modeFxTick, setModeFxTick] = useState(0);
  const [modeFlash, setModeFlash] = useState(null);
  const [pendingAutoScan, setPendingAutoScan] = useState(null);
  const [networkStatus, setNetworkStatus] = useState({
    ip: "unknown",
    vpn_detected: false,
    blocked: false,
    permissible: true,
    reason: "",
    score: 0,
    message: "",
  });
  const [isNarrow, setIsNarrow] = useState(() =>
    typeof window !== "undefined" ? window.innerWidth < 980 : false,
  );
  const [clock, setClock] = useState(new Date());

  const switchTab = (id) => {
    if (id === tab) return;
    setPrevTab(tab);
    setTab(id);
    setTabFxTick((v) => v + 1);
  };

  const handleLogout = () => {
    setUnlocked(false);
    setTab("scanner");
    setPrevTab("scanner");
    setTabFxTick(0);
    setScanModel("general");
    setPrevScanModel("general");
    setModeFxTick(0);
    setModeFlash(null);
    setPendingAutoScan(null);
  };

  const switchScanModel = (nextModel, options = {}) => {
    const normalized = normalizeScanModel(nextModel);
    if (normalized === scanModel) return;
    setPrevScanModel(scanModel);
    setScanModel(normalized);
    setModeFxTick((v) => v + 1);
    const message =
      options.message ||
      (normalized === "banking"
        ? "BANKING MATRIX ONLINE: STRICT PQC-S1 ENFORCEMENT"
        : "NON-BANK MATRIX ONLINE: ADAPTIVE PQC-M2 INTEL MODE");
    const tone =
      options.tone || (normalized === "banking" ? "banking" : "general");
    setModeFlash({ text: message, tone });
  };

  const handleAutoSwitchForDomain = (domain, targetModel) => {
    const normalizedTarget = normalizeScanModel(targetModel);
    if (normalizedTarget === normalizeScanModel(scanModel)) return;
    setPendingAutoScan({
      domain: normalizeDomain(domain),
      scan_model: normalizedTarget,
      requested_at: Date.now(),
    });
    if (normalizedTarget === "banking") {
      switchScanModel("banking", {
        tone: "banking",
        message: `DOMAIN ${normalizeDomain(domain).toUpperCase()} IS OF BANK TYPE. SWITCHING TO BANKING MODE.`,
      });
      return;
    }
    switchScanModel("general", {
      tone: "general",
      message: `DOMAIN ${normalizeDomain(domain).toUpperCase()} IS NON-BANK TYPE. SWITCHING TO NON-BANK MODE.`,
    });
  };

  const consumePendingAutoScan = () => setPendingAutoScan(null);

  useEffect(() => {
    const id = setInterval(() => setClock(new Date()), 1000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    let alive = true;
    const loadNetworkStatus = () => {
      fetch(`${API}/api/network-status`)
        .then((r) => (r.ok ? r.json() : null))
        .then((d) => {
          if (!alive || !d) return;
          setNetworkStatus(d);
        })
        .catch(() => {
          if (!alive) return;
          setNetworkStatus({
            ip: "unknown",
            vpn_detected: false,
            blocked: false,
            permissible: true,
            reason: "",
            score: 0,
            message: "Network check unavailable",
          });
        });
    };

    loadNetworkStatus();
    const id = setInterval(loadNetworkStatus, 30000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  useEffect(() => {
    const onResize = () => setIsNarrow(innerWidth < 980);
    addEventListener("resize", onResize);
    onResize();
    return () => removeEventListener("resize", onResize);
  }, []);

  useEffect(() => {
    applyTheme(theme);
    try {
      localStorage.setItem("quanthunt_theme", theme);
    } catch {}
  }, [theme]);

  useEffect(() => {
    if (!modeFlash) return;
    const id = setTimeout(() => setModeFlash(null), 11000);
    return () => clearTimeout(id);
  }, [modeFlash]);

  applyTheme(theme);
  if (!unlocked)
    return (
      <LockScreen
        onUnlock={() => setUnlocked(true)}
        theme={theme}
        onThemeChange={setTheme}
      />
    );
  return (
    <div
      style={{
        minHeight: "100vh",
        background:
          theme === "dark"
            ? "linear-gradient(155deg, #132019 0%, #101a14 56%, #0c1410 100%)"
            : "linear-gradient(160deg, #f2e7d2 0%, #e7dac0 52%, #dbcaa8 100%)",
        color: C.text,
        fontFamily: "Outfit",
        overflow: isNarrow ? "visible" : "hidden",
      }}
    >
      <div
        style={{
          display: "grid",
          gridTemplateColumns: isNarrow ? "1fr" : "260px 1fr",
          minHeight: "100vh",
          position: "relative",
          zIndex: 2,
        }}
      >
        <aside
          style={{
            position: isNarrow ? "relative" : "sticky",
            top: 0,
            alignSelf: "start",
            height: isNarrow ? "auto" : "100vh",
            padding: 14,
            borderRight: isNarrow
              ? "none"
              : theme === "dark"
                ? "1px solid rgba(174,158,110,0.44)"
                : "1px solid rgba(186,161,101,0.48)",
            borderBottom: isNarrow
              ? theme === "dark"
                ? "1px solid rgba(174,158,110,0.38)"
                : "1px solid rgba(186,161,101,0.42)"
              : "none",
            borderRadius: isNarrow ? "0 0 26px 26px" : "0 34px 34px 0",
            background:
              theme === "dark"
                ? "linear-gradient(165deg, rgba(35,60,46,0.9), rgba(28,49,38,0.86) 52%, rgba(22,39,30,0.84) 100%)"
                : "linear-gradient(165deg, rgba(245,235,214,0.93), rgba(236,223,195,0.89) 52%, rgba(228,209,171,0.85) 100%)",
            backgroundSize: "100% 100%",
            backdropFilter: "blur(38px) saturate(1.12) contrast(1.02)",
            WebkitBackdropFilter: "blur(38px) saturate(1.12) contrast(1.02)",
            boxShadow:
              theme === "dark"
                ? "26px 0 44px rgba(5,10,8,0.58), inset 0 2px 0 rgba(215,199,153,0.18), inset -2px 0 0 rgba(121,138,112,0.26), inset 10px 0 22px rgba(7,12,9,0.44), inset 0 -8px 18px rgba(4,8,6,0.3)"
                : "24px 0 42px rgba(178,156,106,0.36), inset 0 2px 0 rgba(255,250,238,0.88), inset -2px 0 0 rgba(205,179,120,0.34), inset 10px 0 20px rgba(219,198,152,0.3), inset 0 -8px 18px rgba(184,162,114,0.2)",
            display: "grid",
            gridTemplateRows: "auto auto 1fr auto",
            gap: 12,
            overflow: "hidden",
            transition:
              "box-shadow 320ms ease, border-color 280ms ease, backdrop-filter 340ms ease",
            animation: "none",
            isolation: "isolate",
          }}
        >
          <div
            style={{
              position: "relative",
              zIndex: 1,
              display: "flex",
              alignItems: "center",
              gap: 10,
            }}
          >
            <div
              style={{
                width: 38,
                height: 38,
                borderRadius: "50%",
                display: "grid",
                placeItems: "center",
                background:
                  theme === "dark"
                    ? "linear-gradient(165deg, rgba(87,76,45,0.64), rgba(64,54,30,0.68))"
                    : "linear-gradient(165deg, rgba(249,239,216,0.9), rgba(225,205,158,0.72))",
                border:
                  theme === "dark"
                    ? "1px solid rgba(201,174,108,0.34)"
                    : "1px solid rgba(186,151,72,0.34)",
                boxShadow:
                  theme === "dark"
                    ? "8px 8px 16px rgba(10,9,6,0.5), -5px -5px 12px rgba(116,100,58,0.22), inset 0 1px 0 rgba(255,243,210,0.18)"
                    : "7px 7px 14px rgba(178,154,104,0.34), -5px -5px 12px rgba(255,252,241,0.84), inset 0 1px 0 rgba(255,255,255,0.9)",
              }}
            >
              <Logo size={30} animated clay />
            </div>
            <div>
              <div
                className="quanthunt-heading"
                style={{
                  letterSpacing: 2.4,
                  color: theme === "dark" ? "#f0e4bf" : "#5c4a23",
                  fontSize: 20,
                  textShadow:
                    theme === "dark"
                      ? "0 1px 0 rgba(247,234,188,0.16), 0 8px 20px rgba(176,143,73,0.2)"
                      : "0 1px 0 rgba(255,255,255,0.72), 0 8px 16px rgba(175,146,83,0.24)",
                }}
              >
                QUANTHUNT
              </div>
              <div
                style={{
                  color: theme === "dark" ? "#bfd0bd" : "#7a6840",
                  fontFamily: "JetBrains Mono",
                  fontSize: 10,
                }}
              >
                Bank cyber risk intelligence
              </div>
            </div>
          </div>

          <div
            style={{
              position: "relative",
              zIndex: 1,
              display: "flex",
              alignItems: "center",
              gap: 8,
            }}
          >
            <button
              onClick={() => setTheme("light")}
              style={{
                borderRadius: 999,
                border:
                  theme === "light"
                    ? "1px solid rgba(179,156,96,0.68)"
                    : "1px solid rgba(179,156,96,0.38)",
                background:
                  theme === "light" ? "rgba(193,166,99,0.22)" : "transparent",
                color:
                  theme === "light"
                    ? "#5d4a24"
                    : theme === "dark"
                      ? "#ccb477"
                      : "#7a6840",
                padding: "4px 10px",
                fontFamily: "JetBrains Mono",
                fontSize: 10,
                cursor: "pointer",
              }}
            >
              Light
            </button>
            <button
              onClick={() => setTheme("dark")}
              style={{
                borderRadius: 999,
                border:
                  theme === "dark"
                    ? "1px solid rgba(199,175,111,0.72)"
                    : "1px solid rgba(179,156,96,0.38)",
                background:
                  theme === "dark" ? "rgba(201,177,113,0.18)" : "transparent",
                color: theme === "dark" ? "#f1dfb6" : "#7a6840",
                boxShadow:
                  theme === "dark"
                    ? "inset 0 1px 0 rgba(250,234,191,0.18)"
                    : "none",
                padding: "4px 10px",
                fontFamily: "JetBrains Mono",
                fontSize: 10,
                cursor: "pointer",
              }}
            >
              Dark
            </button>
            <button
              onClick={handleLogout}
              style={{
                marginLeft: 4,
                borderRadius: 999,
                border:
                  theme === "dark"
                    ? "1px solid rgba(194,169,106,0.74)"
                    : "1px solid rgba(178,150,84,0.62)",
                background:
                  theme === "dark"
                    ? "rgba(191,162,94,0.22)"
                    : "rgba(194,164,94,0.18)",
                color: theme === "dark" ? "#f1dfb6" : "#5f4a1f",
                padding: "4px 10px",
                fontFamily: "JetBrains Mono",
                fontSize: 10,
                cursor: "pointer",
              }}
            >
              Logout
            </button>
            <div
              style={{
                marginLeft: "auto",
                color: theme === "dark" ? "#c6d5c4" : "#78663d",
                fontFamily: "JetBrains Mono",
                fontSize: 11,
              }}
            >
              {clock.toLocaleTimeString()}
            </div>
          </div>

          <div
            style={{
              position: "relative",
              zIndex: 1,
              borderRadius: 14,
              padding: "8px 10px",
              background:
                theme === "dark"
                  ? "linear-gradient(165deg, rgba(44,55,51,0.74), rgba(37,47,43,0.64))"
                  : "linear-gradient(165deg, rgba(228,240,230,0.74), rgba(214,228,216,0.64))",
              border:
                theme === "dark"
                  ? "1px solid rgba(130,147,137,0.34)"
                  : "1px solid rgba(149,173,153,0.36)",
              boxShadow:
                theme === "dark"
                  ? "inset 0 0 12px rgba(124,142,132,0.1)"
                  : "inset 2px 2px 7px rgba(167,189,172,0.26), inset -2px -2px 7px rgba(248,255,249,0.86)",
              display: "grid",
              gap: 4,
            }}
          >
            <div
              style={{
                fontFamily: "JetBrains Mono",
                fontSize: 9,
                color: theme === "dark" ? "#a9bdb2" : "#66806f",
                letterSpacing: 1.1,
              }}
            >
              NETWORK STATUS
            </div>
            <div
              style={{
                fontFamily: "JetBrains Mono",
                fontSize: 10,
                color: theme === "dark" ? "#dce8e0" : "#446553",
              }}
            >
              IP: {networkStatus?.ip || "unknown"}
            </div>
            <div
              style={{
                fontFamily: "JetBrains Mono",
                fontSize: 10,
                color: networkStatus?.blocked
                  ? C.red
                  : networkStatus?.vpn_detected
                    ? C.orange
                    : C.green,
              }}
            >
              VPN:{" "}
              {networkStatus?.blocked
                ? "BLOCKED"
                : networkStatus?.vpn_detected
                  ? networkStatus?.permissible
                    ? "DETECTED (PERMISSIBLE)"
                    : "DETECTED"
                  : "NOT DETECTED"}
            </div>
          </div>

          <div
            style={{ position: "relative", zIndex: 1, display: "grid", gap: 8 }}
          >
            <div
              style={{
                fontFamily: "JetBrains Mono",
                fontSize: 9,
                color: theme === "dark" ? "#a9bdb2" : "#66806f",
                letterSpacing: 1.1,
              }}
            >
              SCAN MODEL
            </div>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1fr 1fr",
                gap: 8,
              }}
            >
              <button
                className="liquid-tap"
                onClick={() => switchScanModel("general")}
                style={{
                  borderRadius: 12,
                  border:
                    scanModel === "general"
                      ? "1px solid rgba(154,176,161,0.74)"
                      : "1px solid rgba(142,164,150,0.36)",
                  background:
                    scanModel === "general"
                      ? theme === "dark"
                        ? "linear-gradient(165deg, rgba(74,101,89,0.74), rgba(56,79,69,0.72))"
                        : "linear-gradient(165deg, rgba(228,241,232,0.9), rgba(204,223,210,0.8))"
                      : theme === "dark"
                        ? "linear-gradient(165deg, rgba(41,56,50,0.7), rgba(33,46,41,0.62))"
                        : "linear-gradient(165deg, rgba(217,230,220,0.74), rgba(203,219,206,0.66))",
                  color:
                    scanModel === "general"
                      ? theme === "dark"
                        ? "#e3efe7"
                        : "#3f6251"
                      : theme === "dark"
                        ? "#b2c8bb"
                        : "#63806f",
                  padding: "8px 10px",
                  fontFamily: "Orbitron",
                  fontSize: 10,
                  letterSpacing: 0.8,
                  cursor: "pointer",
                }}
              >
                NON-BANK
              </button>
              <button
                className="liquid-tap"
                onClick={() => switchScanModel("banking")}
                style={{
                  borderRadius: 12,
                  border:
                    scanModel === "banking"
                      ? "1px solid rgba(211,183,118,0.72)"
                      : "1px solid rgba(179,156,96,0.38)",
                  background:
                    scanModel === "banking"
                      ? theme === "dark"
                        ? "linear-gradient(165deg, rgba(114,92,49,0.74), rgba(91,70,33,0.72))"
                        : "linear-gradient(165deg, rgba(248,234,196,0.9), rgba(232,210,156,0.82))"
                      : theme === "dark"
                        ? "linear-gradient(165deg, rgba(56,47,32,0.7), rgba(46,39,27,0.62))"
                        : "linear-gradient(165deg, rgba(233,219,184,0.74), rgba(220,203,164,0.66))",
                  color:
                    scanModel === "banking"
                      ? theme === "dark"
                        ? "#f2e0b6"
                        : "#6b4f1b"
                      : theme === "dark"
                        ? "#ccb477"
                        : "#7a6840",
                  padding: "8px 10px",
                  fontFamily: "Orbitron",
                  fontSize: 10,
                  letterSpacing: 0.8,
                  cursor: "pointer",
                }}
              >
                BANKING
              </button>
            </div>
          </div>

          <div
            style={{ position: "relative", zIndex: 1, display: "grid", gap: 8 }}
          >
            {TABS.map(([id, label]) => {
              const active = tab === id;
              const visual = TAB_VISUALS[id] || TAB_VISUALS.scanner;
              return (
                <button
                  className="liquid-tap"
                  key={id}
                  onClick={() => switchTab(id)}
                  style={{
                    position: "relative",
                    overflow: "hidden",
                    borderRadius: 14,
                    border: active
                      ? theme === "dark"
                        ? "1px solid rgba(161,175,168,0.54)"
                        : "1px solid rgba(149,169,152,0.62)"
                      : theme === "dark"
                        ? "1px solid rgba(112,126,121,0.26)"
                        : "1px solid rgba(162,179,168,0.3)",
                    background: active
                      ? theme === "dark"
                        ? "linear-gradient(162deg, rgba(74,86,80,0.74), rgba(58,69,64,0.7) 60%, rgba(50,60,56,0.66) 100%)"
                        : "linear-gradient(162deg, rgba(236,244,236,0.9), rgba(221,233,222,0.82) 60%, rgba(208,222,209,0.76) 100%)"
                      : theme === "dark"
                        ? "linear-gradient(160deg, rgba(46,56,53,0.64), rgba(41,50,48,0.56))"
                        : "linear-gradient(160deg, rgba(224,236,226,0.7), rgba(211,228,215,0.6))",
                    color: active
                      ? theme === "dark"
                        ? "#e4ece6"
                        : "#3f5d4b"
                      : theme === "dark"
                        ? "#a8bbb1"
                        : "#65806e",
                    backdropFilter: "blur(18px) saturate(1.08)",
                    WebkitBackdropFilter: "blur(18px) saturate(1.08)",
                    boxShadow: active
                      ? theme === "dark"
                        ? "0 10px 24px rgba(8,13,12,0.54), inset 0 1px 0 rgba(215,225,219,0.18), inset 0 -2px 7px rgba(8,13,12,0.42)"
                        : "9px 9px 16px rgba(166,182,171,0.32), -7px -7px 14px rgba(247,252,248,0.78), inset 0 1px 0 rgba(255,255,255,0.86), inset 0 -2px 6px rgba(179,198,184,0.3)"
                      : theme === "dark"
                        ? "inset 0 1px 0 rgba(136,153,145,0.16)"
                        : "inset 0 1px 0 rgba(248,252,248,0.74)",
                    padding: "10px 12px",
                    textAlign: "left",
                    cursor: "pointer",
                    transform: active ? "translateX(2px)" : "translateX(0)",
                    transition: "all 280ms cubic-bezier(0.22, 1, 0.36, 1)",
                  }}
                >
                  {active && (
                    <span
                      style={{
                        position: "absolute",
                        inset: 1,
                        borderRadius: 13,
                        background:
                          theme === "dark"
                            ? "linear-gradient(170deg, rgba(255,255,255,0.12), rgba(255,255,255,0.02) 36%, transparent 58%)"
                            : "linear-gradient(170deg, rgba(238,243,248,0.72), rgba(238,243,248,0.24) 40%, transparent 62%)",
                        pointerEvents: "none",
                      }}
                    />
                  )}
                  <div
                    style={{
                      position: "relative",
                      zIndex: 2,
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      gap: 8,
                    }}
                  >
                    <span
                      style={{
                        fontFamily: "Orbitron",
                        fontSize: 11,
                        letterSpacing: active ? 1.15 : 0.8,
                        fontWeight: active ? 700 : 600,
                        textShadow:
                          active && theme === "dark"
                            ? "0 1px 0 rgba(230,236,232,0.2)"
                            : "none",
                      }}
                    >
                      {label}
                    </span>
                    {active ? (
                      <span
                        style={{
                          minWidth: 46,
                          borderRadius: 999,
                          padding: "2px 8px",
                          textAlign: "center",
                          fontFamily: "JetBrains Mono",
                          fontSize: 9,
                          letterSpacing: 1,
                          border:
                            theme === "dark"
                              ? "1px solid rgba(171,184,176,0.56)"
                              : "1px solid rgba(139,160,143,0.56)",
                          background:
                            theme === "dark"
                              ? "rgba(152,166,158,0.18)"
                              : "rgba(165,189,169,0.2)",
                          color: theme === "dark" ? "#dce7df" : "#43614f",
                        }}
                      >
                        {visual.chip}
                      </span>
                    ) : (
                      <span
                        style={{
                          width: 8,
                          height: 8,
                          borderRadius: "50%",
                          background:
                            theme === "dark"
                              ? "rgba(153,168,160,0.5)"
                              : "rgba(150,172,155,0.55)",
                        }}
                      />
                    )}
                  </div>
                </button>
              );
            })}
          </div>

          <div
            style={{
              position: "relative",
              zIndex: 1,
              borderRadius: 14,
              padding: "8px 10px",
              background:
                theme === "dark"
                  ? "linear-gradient(165deg, rgba(44,55,51,0.74), rgba(37,47,43,0.64))"
                  : "linear-gradient(165deg, rgba(228,240,230,0.74), rgba(214,228,216,0.64))",
              border:
                theme === "dark"
                  ? "1px solid rgba(130,147,137,0.34)"
                  : "1px solid rgba(149,173,153,0.36)",
              boxShadow:
                theme === "dark"
                  ? "inset 0 0 12px rgba(124,142,132,0.1)"
                  : "inset 2px 2px 7px rgba(167,189,172,0.26), inset -2px -2px 7px rgba(248,255,249,0.86)",
            }}
          >
            <div
              style={{
                fontFamily: "JetBrains Mono",
                fontSize: 9,
                color: theme === "dark" ? "#a9bdb2" : "#66806f",
                letterSpacing: 1.1,
                marginBottom: 2,
              }}
            >
              TAB TRANSITION
            </div>
            <div
              style={{
                fontFamily: "Orbitron",
                fontSize: 10,
                letterSpacing: 0.8,
                color: theme === "dark" ? "#dce8e0" : "#446553",
              }}
            >
              {getTabLabel(prevTab)} {"->"} {getTabLabel(tab)}
            </div>
            <div
              style={{
                marginTop: 5,
                fontFamily: "JetBrains Mono",
                fontSize: 10,
                color: theme === "dark" ? "#cddccd" : "#4e6758",
              }}
            >
              MODEL: {scanModelUiLabel(prevScanModel)} {"->"}{" "}
              {scanModelUiLabel(scanModel)}
            </div>
          </div>
        </aside>

        <main
          className="qh-main-scroll"
          style={{
            padding: isNarrow ? 14 : 20,
            margin: isNarrow ? 0 : "12px 14px 12px 10px",
            borderRadius: isNarrow ? 20 : 30,
            border:
              theme === "dark"
                ? "1px solid rgba(170,152,102,0.34)"
                : "1px solid rgba(180,157,103,0.44)",
            background:
              theme === "dark"
                ? "linear-gradient(160deg, rgba(20,34,28,0.9) 0%, rgba(16,28,23,0.88) 58%, rgba(13,22,18,0.9) 100%)"
                : "linear-gradient(160deg, rgba(244,235,216,0.94) 0%, rgba(235,224,200,0.92) 58%, rgba(226,211,182,0.92) 100%)",
            boxShadow:
              theme === "dark"
                ? "24px 24px 48px rgba(5,10,8,0.62), -16px -16px 36px rgba(28,50,40,0.36), inset 0 2px 0 rgba(216,197,147,0.16), inset 0 -3px 10px rgba(6,12,9,0.5)"
                : "24px 24px 44px rgba(188,164,109,0.42), -16px -16px 34px rgba(255,249,236,0.8), inset 0 2px 0 rgba(255,253,246,0.82), inset 0 -3px 9px rgba(196,171,114,0.4)",
            position: "relative",
            height: isNarrow ? "auto" : "calc(100vh - 24px)",
            overflowY: isNarrow ? "visible" : "auto",
            overflowX: "hidden",
            scrollBehavior: "smooth",
            paddingRight: isNarrow ? 0 : 8,
            backdropFilter: "blur(24px) saturate(1.28)",
            WebkitBackdropFilter: "blur(24px) saturate(1.28)",
          }}
        >
          <div
            style={{
              position: "absolute",
              inset: 0,
              pointerEvents: "none",
              background:
                theme === "dark"
                  ? "linear-gradient(140deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02) 42%, transparent 68%)"
                  : "linear-gradient(140deg, rgba(255,255,255,0.58), rgba(255,255,255,0.18) 42%, transparent 68%)",
            }}
          />
          {tabFxTick > 0 && (
            <div
              key={tabFxTick}
              style={{
                position: "absolute",
                inset: 10,
                borderRadius: 22,
                pointerEvents: "none",
                background:
                  theme === "dark"
                    ? "linear-gradient(120deg, rgba(210,220,235,0.14), rgba(210,220,235,0.02) 38%, transparent 60%)"
                    : "linear-gradient(120deg, rgba(236,241,246,0.5), rgba(236,241,246,0.16) 36%, transparent 62%)",
                border:
                  theme === "dark"
                    ? "1px solid rgba(160,177,201,0.26)"
                    : "1px solid rgba(171,188,212,0.34)",
                backdropFilter: "blur(10px)",
                WebkitBackdropFilter: "blur(10px)",
                animation: "tabGlassShift 520ms ease-out forwards",
                zIndex: 0,
              }}
            />
          )}
          {modeFxTick > 0 && (
            <div
              key={`modefx-${modeFxTick}`}
              style={{
                position: "absolute",
                left: "50%",
                top: 14,
                transform: "translateX(-50%)",
                minWidth: isNarrow ? "86%" : 520,
                maxWidth: "92%",
                borderRadius: 16,
                padding: "10px 14px",
                textAlign: "center",
                fontFamily: "Orbitron",
                fontSize: 11,
                letterSpacing: 1.2,
                color: scanModel === "banking" ? "#fff3cf" : "#d9f4e7",
                border:
                  scanModel === "banking"
                    ? "1px solid rgba(219,186,112,0.62)"
                    : "1px solid rgba(123,199,168,0.54)",
                background:
                  scanModel === "banking"
                    ? "linear-gradient(140deg, rgba(126,95,36,0.42), rgba(97,71,24,0.26), rgba(146,110,42,0.4))"
                    : "linear-gradient(140deg, rgba(42,112,86,0.38), rgba(26,86,66,0.24), rgba(55,140,108,0.38))",
                boxShadow:
                  "0 12px 22px rgba(0,0,0,0.24), inset 0 1px 0 rgba(255,255,255,0.28)",
                backdropFilter: "blur(12px) saturate(130%)",
                WebkitBackdropFilter: "blur(12px) saturate(130%)",
                pointerEvents: "none",
                animation:
                  "modeLiquidMorph 5400ms cubic-bezier(0.22, 1, 0.36, 1) forwards",
                zIndex: 2,
              }}
            >
              {modeFlash?.text || "SCAN MODEL SHIFTED"}
            </div>
          )}
          {modeFlash && (
            <div
              style={{
                position: "absolute",
                right: 16,
                bottom: 16,
                borderRadius: 999,
                padding: "8px 14px",
                border:
                  modeFlash.tone === "banking"
                    ? "1px solid rgba(218,186,117,0.64)"
                    : "1px solid rgba(121,200,167,0.58)",
                background:
                  modeFlash.tone === "banking"
                    ? "linear-gradient(155deg, rgba(118,88,33,0.82), rgba(94,69,25,0.72))"
                    : "linear-gradient(155deg, rgba(35,106,80,0.82), rgba(28,84,64,0.72))",
                color: modeFlash.tone === "banking" ? "#ffefca" : "#d6f6e7",
                fontFamily: "JetBrains Mono",
                fontSize: 10,
                letterSpacing: 0.8,
                boxShadow:
                  "0 10px 18px rgba(0,0,0,0.26), inset 0 1px 0 rgba(255,255,255,0.22)",
                pointerEvents: "none",
                animation: "modeFlashPulse 1200ms ease-in-out infinite",
                zIndex: 2,
              }}
            >
              MODE SWITCH ACTIVE
            </div>
          )}
          <div
            style={{
              maxWidth: 1350,
              margin: "0 auto",
              position: "relative",
              zIndex: 1,
              paddingBottom: 14,
            }}
          >
            <div
              key={`${tab}-${scanModel}`}
              style={{
                animation: "mainPanelIn 360ms cubic-bezier(0.22, 1, 0.36, 1)",
              }}
            >
              <TabContentErrorBoundary key={`tab-boundary-${tab}`}>
                {tab === "scanner" && <OpsStrip />}
                {tab === "scanner" && <CyberIntelPanel scanModel={scanModel} />}
                {tab === "scanner" && (
                  <ScannerTab
                    scanModel={scanModel}
                    onAutoSwitchForDomain={handleAutoSwitchForDomain}
                    pendingAutoScan={pendingAutoScan}
                    onAutoScanConsumed={consumePendingAutoScan}
                  />
                )}
                {tab === "banklab" && (
                  <BankSignalLabTab scanModel={scanModel} />
                )}
                {tab === "assets" && <AssetMapTab scanModel={scanModel} />}
                {tab === "crypto" && <CryptoTab scanModel={scanModel} />}
                {tab === "xport" && <CBOMTab scanModel={scanModel} />}
                {tab === "roadmap" && <RoadmapTab scanModel={scanModel} />}
                {tab === "leaderboard" && (
                  <LeaderboardTab scanModel={scanModel} />
                )}
                {tab === "docs" && <DocsTab scanModel={scanModel} />}
                {tab === "latency" && <PQCLatencyTab scanModel={scanModel} />}
              </TabContentErrorBoundary>
            </div>
          </div>
          <style>{`@keyframes tabGlassShift{0%{opacity:.84;transform:scale(1.03)}100%{opacity:0;transform:scale(1)}}@keyframes mainPanelIn{0%{opacity:.22;transform:translateY(14px)}100%{opacity:1;transform:translateY(0)}}@keyframes modeLiquidMorph{0%{opacity:0;transform:translateX(-50%) translateY(-10px) scale(.96);filter:blur(3px)}12%{opacity:1;transform:translateX(-50%) translateY(0) scale(1.02);filter:blur(0)}82%{opacity:1;transform:translateX(-50%) translateY(0) scale(1)}100%{opacity:0;transform:translateX(-50%) translateY(8px) scale(.99)}}@keyframes modeFlashPulse{0%,100%{opacity:.42;transform:translateY(0)}50%{opacity:1;transform:translateY(-1px)}}@keyframes liquidTapPulse{0%{transform:scale(1);filter:saturate(1)}45%{transform:scale(.986);filter:saturate(1.18)}100%{transform:scale(1);filter:saturate(1)}}.liquid-tap{transition:transform 180ms ease,filter 180ms ease,box-shadow 220ms ease}.liquid-tap:hover{filter:saturate(1.08)}.liquid-tap:active{animation:liquidTapPulse 360ms ease}.qh-main-scroll{scrollbar-width:thin;scrollbar-color:rgba(140,162,190,0.6) transparent}.qh-main-scroll::-webkit-scrollbar{width:10px}.qh-main-scroll::-webkit-scrollbar-track{background:transparent}.qh-main-scroll::-webkit-scrollbar-thumb{border-radius:999px;background:linear-gradient(180deg,rgba(156,176,205,0.75),rgba(132,154,184,0.55));border:2px solid transparent;background-clip:padding-box}`}</style>
        </main>
      </div>
      <QuantHuntFloating theme={theme} scanModel={scanModel} />
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
