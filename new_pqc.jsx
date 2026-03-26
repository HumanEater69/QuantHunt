
function PQCLatencyTab({ scanModel }) {
  const [theme, setTheme] = useState(
    () => localStorage.getItem("quanthunt_theme") || "light"
  );
  const [simulationState, setSimulationState] = useState("idle");
  const [packets, setPackets] = useState([]);
  const [flightInfo, setFlightInfo] = useState({ rtts: 0, time: 0 });

  useEffect(() => {
    const handleStorage = () => setTheme(localStorage.getItem("quanthunt_theme") || "light");
    window.addEventListener("storage", handleStorage);
    return () => window.removeEventListener("storage", handleStorage);
  }, []);

  const isDark = theme === "dark";

  const paneBg = isDark
    ? "linear-gradient(135deg, rgba(16,32,48,0.7) 0%, rgba(8,16,28,0.85) 100%)"
    : "linear-gradient(135deg, rgba(240,246,252,0.75) 0%, rgba(220,230,240,0.85) 100%)";
  const paneBorder = isDark ? "rgba(100,140,200,0.3)" : "rgba(180,200,220,0.5)";
  const textMain = isDark ? "#E2E8F0" : "#2D3748";
  const textMuted = isDark ? "#A0AEC0" : "#4A5568";
  const accentNeon = isDark ? "#4FD1C5" : "#3182CE";
  const dangerNeon = isDark ? "#FC8181" : "#E53E3E";
  const successNeon = isDark ? "#68D391" : "#38A169";

  const runSimulation = (type) => {
    setSimulationState(type);
    setPackets([]);
    setFlightInfo({ rtts: 0, time: 0 });

    const isPQC = type === "pqc";
    const totalPackets = isPQC ? 16 : 4;
    const windowSize = 10;

    setTimeout(() => {
      let p = [];
      for(let i=0; i < Math.min(totalPackets, windowSize); i++) {
        p.push({ id: i, flight: 1, type: isPQC ? "pqc" : "classical" });
      }
      setPackets(p);
      setFlightInfo({ rtts: 1, time: 45 });
    }, 500);

    if (isPQC) {
      setTimeout(() => {
        setPackets(prev => {
          let p = [...prev];
          for(let i=windowSize; i < totalPackets; i++) {
            p.push({ id: i, flight: 2, type: "pqc_overflow" });
          }
          return p;
        });
        setFlightInfo({ rtts: 2, time: 90 });
      }, 2500);
    }
  };

  return (
    <div style={{ padding: "20px", display: "flex", flexDirection: "column", gap: "24px", color: textMain }}>

      <div style={{
        background: paneBg, border: "1px solid " + paneBorder, borderRadius: "16px", padding: "24px",
        backdropFilter: "blur(16px)", boxShadow: "0 12px 40px rgba(0,0,0,0.2)", position: "relative", overflow: "hidden"
      }}>
        <div style={{ position: "absolute", top: -50, right: -50, width: 200, height: 200, background: accentNeon, filter: "blur(120px)", opacity: 0.15 }} />
        <h2 style={{ margin: "0 0 12px 0", fontSize: "28px", display: "flex", alignItems: "center", gap: "12px", textShadow: "0 0 20px " + accentNeon }}>
          <span style={{ fontSize: "1.2em" }}>?</span> QUANTHUNT KINETIC SCANNER SIMULATOR
        </h2>
        <p style={{ color: textMuted, fontSize: "16px", lineHeight: "1.6", maxWidth: "900px" }}>
          This module visualizes how the QuantHunt engine maps network latency across financial domains. By replacing standard cryptography with Post-Quantum bounds (ML-KEM + ML-DSA), the TLS payload artificially inflates beyond a default TCP Initial Window (iw=10). This visualizer proves that forced network truncation triggers slow-start flight penalties, compounding Time-To-First-Byte on fragile mobile banking connections.
        </p>
      </div>

      <div style={{
        background: paneBg, border: "1px solid " + paneBorder, borderRadius: "16px", padding: "30px",
        backdropFilter: "blur(16px)", boxShadow: "0 12px 40px rgba(0,0,0,0.2)", display: "flex", flexDirection: "column", gap: "30px"
      }}>

        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <h3 style={{ margin: 0, textTransform: "uppercase", letterSpacing: "2px", color: accentNeon }}>Scan Operations Simulator</h3>
          <div style={{ display: "flex", gap: "12px" }}>
            <button onClick={() => runSimulation("classical")} className="latency-btn hover-glow" style={{ background: simulationState === "classical" ? "rgba(72,187,120,0.2)" : "rgba(255,255,255,0.05)", border: "1px solid " + successNeon, color: successNeon }}>
              ? LAUNCH CLASSICAL TLS SCAN
            </button>
            <button onClick={() => runSimulation("pqc")} className="latency-btn hover-glow" style={{ background: simulationState === "pqc" ? "rgba(245,101,101,0.2)" : "rgba(255,255,255,0.05)", border: "1px solid " + dangerNeon, color: dangerNeon }}>
              ? LAUNCH PQC HYBRID SCAN
            </button>
          </div>
        </div>

        <div style={{ display: "flex", gap: "24px" }}>
          <div className="hud-metric">
            <span className="hud-lbl">Network Flights</span>
            <span className="hud-val">{flightInfo.rtts} RTT</span>
          </div>
          <div className="hud-metric">
            <span className="hud-lbl">Latency (TTFB)</span>
            <span className="hud-val" style={{ color: flightInfo.time > 50 ? dangerNeon : successNeon }}>{flightInfo.time}ms</span>
          </div>
          <div className="hud-metric">
            <span className="hud-lbl">Handshake Size</span>
            <span className="hud-val">{simulationState === "idle" ? "0" : (simulationState === "classical" ? "500 B" : "6,241 B")}</span>
          </div>
        </div>

        <div style={{
          height: "200px", position: "relative",
          background: isDark ? "rgba(5,10,15,0.4)" : "rgba(200,210,225,0.4)",
          borderRadius: "100px", border: "2px solid " + (isDark ? "rgba(255,255,255,0.05)" : "rgba(0,0,0,0.05)"),
          boxShadow: isDark ? "inset 0 10px 40px rgba(0,0,0,0.8)" : "inset 0 10px 40px rgba(0,0,0,0.1)",
          display: "flex", alignItems: "center", padding: "0 40px", overflow: "hidden"
        }}>

          <div className="scanner-node pulse-node">?? QuantHunt Client</div>
          <div className="scanner-node" style={{ marginLeft: "auto" }}>?? Banking Gateway</div>

          <div style={{
            position: "absolute", left: "220px", right: "220px", height: "4px",
            background: "linear-gradient(90deg, transparent, " + paneBorder + ", transparent)",
            opacity: 0.5, top: "50%", transform: "translateY(-50%)"
          }} />

          <div style={{ position: "absolute", left: 230, right: 230, height: "100%", pointerEvents: "none" }}>
            {packets.map((pkt, i) => (
              <div key={i} style={{
                position: "absolute", top: "50%", transform: "translateY(" + ((i % 3 - 1) * 10 - 6) + "px)",
                width: "28px", height: "12px", borderRadius: "6px",
                background: pkt.type === "pqc_overflow" ? dangerNeon : (pkt.type === "pqc" ? accentNeon : successNeon),
                boxShadow: "0 0 15px " + (pkt.type === "pqc_overflow" ? dangerNeon : (pkt.type === "pqc" ? accentNeon : successNeon)),
                animation: "shootPacket 1.5s ease-in-out forwards " + (pkt.flight === 1 ? (Math.random() * 0.4) : (0.5 + Math.random() * 0.4)) + "s"
              }} />
            ))}
          </div>

          {simulationState === "pqc" && flightInfo.rtts === 1 && (
            <div style={{
               position: "absolute", top: "50%", left: "50%", transform: "translate(-50%, -50%)",
               color: dangerNeon, fontSize: "16px", fontWeight: "bold", background: "rgba(20,0,0,0.8)",
               padding: "10px 20px", borderRadius: "10px", border: "1px solid " + dangerNeon,
               animation: "pulseWarning 0.5s infinite alternate", backdropFilter: "blur(5px)"
            }}>
              ?? iw=10 REACHED: SECOND RTT INITIATING
            </div>
          )}

        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "24px" }}>

        <div style={{
          background: paneBg, border: "1px solid " + paneBorder, borderRadius: "16px", padding: "24px",
          backdropFilter: "blur(16px)", boxShadow: "0 12px 40px rgba(0,0,0,0.2)"
        }}>
          <h3 style={{ color: accentNeon, fontSize: "18px", marginTop: 0 }}>Math Engine: Kinematics</h3>
          <p>Scanner computes overall packet payload logic during remote checks:</p>
          <div className="math-box">S_TLS = S_base + S_KEM + S_DSA</div>
          <p>Slow-start calculation triggers based on total payload segments:</p>
          <div className="math-box">Flights = log2( (N_seg / iw) + 1 )</div>
        </div>

        <div style={{
          background: paneBg, border: "1px solid " + paneBorder, borderRadius: "16px", padding: "24px",
          backdropFilter: "blur(16px)", boxShadow: "0 12px 40px rgba(0,0,0,0.2)"
        }}>
          <h3 style={{ color: dangerNeon, fontSize: "18px", marginTop: 0 }}>Math Engine: Entropy</h3>
          <p>QuantHunt projects drop rates (p) to predict connection failure margins:</p>
          <div className="math-box">P_success = (1 - p)^N_seg</div>
          <div className="math-box" style={{ borderLeftColor: dangerNeon }}>T_loss = ( (1 - P_success) / P_success ) × RTO</div>
        </div>

      </div>

      <style dangerouslySetInnerHTML={{__html: `
        @keyframes shootPacket {
          0% { left: 0%; opacity: 0; transform: scale(0.5) translateY(-5px); }
          20% { opacity: 1; transform: scale(1.1) translateY(-5px); }
          80% { opacity: 1; transform: scale(1.1) translateY(-5px); }
          100% { left: calc(100% - 28px); opacity: 0; transform: scale(0.5) translateY(-5px); }
        }
        @keyframes pulseWarning {
          0% { box-shadow: 0 0 10px rgba(229,62,62,0.2); }
          100% { box-shadow: 0 0 30px rgba(229,62,62,0.8); }
        }
        @keyframes glowingNode {
          0% { box-shadow: 0 0 10px ${accentNeon}40; }
          50% { box-shadow: 0 0 30px ${accentNeon}A0; }
          100% { box-shadow: 0 0 10px ${accentNeon}40; }
        }
        .latency-btn {
          padding: 10px 24px; border-radius: 8px; font-weight: bold; cursor: pointer; transition: all 0.3s ease; text-shadow: 0 0 10px currentColor; font-family: inherit;
        }
        .hover-glow:hover {
          filter: brightness(1.2); transform: translateY(-2px); box-shadow: 0 10px 20px rgba(0,0,0,0.4);
        }
        .hud-metric {
          background: rgba(0,0,0,0.3); padding: 16px 24px; border-radius: 12px; border: 1px solid ${paneBorder}; display: flex; flex-direction: column; align-items: center; min-width: 140px; box-shadow: inset 0 0 20px rgba(0,0,0,0.5);
        }
        .hud-lbl { font-size: 13px; color: ${textMuted}; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; font-weight: bold; }
        .hud-val { font-size: 32px; font-weight: bold; font-family: monospace; text-shadow: 0 0 15px currentColor; }
        .scanner-node {
          background: ${paneBg}; border: 1px solid ${paneBorder}; padding: 14px 28px; border-radius: 30px; backdrop-filter: blur(10px); z-index: 2; font-weight: bold; letter-spacing: 1px; color: ${textMain}; text-transform: uppercase; box-shadow: 0 5px 20px rgba(0,0,0,0.5);
        }
        .pulse-node { animation: glowingNode 3s infinite; }
        .math-box {
          font-family: inherit; font-size: 20px; font-weight: bold; padding: 16px; margin: 12px 0; background: rgba(0,0,0,0.4); border-radius: 8px; border-left: 4px solid ${accentNeon}; letter-spacing: 1px; box-shadow: inset 0 2px 10px rgba(0,0,0,0.5); color: ${textMain};
        }
      `}} />
    </div>
  );
}
