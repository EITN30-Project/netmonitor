import { useEffect, useMemo, useState } from "react";
import { motion } from "framer-motion";
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";
import { Activity } from "lucide-react";
import { getAnalysisMetrics } from "../api";

const formatTime = (iso) => {
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString([], { hour12: false });
  } catch {
    return "";
  }
};

export default function Analysis() {
  const [points, setPoints] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;

    const tick = async () => {
      try {
        const data = await getAnalysisMetrics(180);
        if (cancelled) return;
        setPoints(Array.isArray(data?.points) ? data.points : []);
        setError("");
      } catch (e) {
        if (cancelled) return;
        setError(e?.message || "Failed to load metrics");
      }
    };

    tick();
    const id = window.setInterval(tick, 1000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, []);

  const data = useMemo(() => {
    return (points || []).map((p) => ({
      ...p,
      t: formatTime(p.ts),
      throughput_mbps: p.throughput_mbps ?? null,
      latency_ms: p.latency_ms ?? null
    }));
  }, [points]);

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 text-white p-6">
      <motion.h1
        initial={{ opacity: 0, y: -16 }}
        animate={{ opacity: 1, y: 0 }}
        className="text-3xl font-bold mb-2 flex items-center gap-2"
      >
        <Activity className="w-8 h-8 text-blue-400" /> Firewall Analysis
      </motion.h1>
      <p className="text-gray-400 mb-6">
        Live throughput and latency over time.
      </p>

      {error && (
        <div className="mb-6 rounded-xl border border-red-700 bg-red-900/40 px-4 py-3 text-red-100">
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}>
          <div className="bg-gray-800 rounded-2xl p-4 shadow">
            <div className="flex items-baseline justify-between mb-3">
              <h2 className="text-lg font-semibold">Throughput (Mbps)</h2>
              <span className="text-xs text-gray-400">last {data.length} samples</span>
            </div>
            <div className="h-72">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={data} margin={{ top: 10, right: 12, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis dataKey="t" tick={{ fill: "#9CA3AF", fontSize: 12 }} minTickGap={24} />
                  <YAxis tick={{ fill: "#9CA3AF", fontSize: 12 }} width={42} />
                  <Tooltip
                    contentStyle={{ background: "#111827", border: "1px solid #374151" }}
                    labelStyle={{ color: "#E5E7EB" }}
                    itemStyle={{ color: "#E5E7EB" }}
                  />
                  <Line
                    type="monotone"
                    dataKey="throughput_mbps"
                    stroke="#60A5FA"
                    strokeWidth={2}
                    dot={false}
                    isAnimationActive
                    animationDuration={450}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}>
          <div className="bg-gray-800 rounded-2xl p-4 shadow">
            <div className="flex items-baseline justify-between mb-3">
              <h2 className="text-lg font-semibold">Latency (ms)</h2>
              <span className="text-xs text-gray-400">ping-based</span>
            </div>
            <div className="h-72">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={data} margin={{ top: 10, right: 12, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis dataKey="t" tick={{ fill: "#9CA3AF", fontSize: 12 }} minTickGap={24} />
                  <YAxis tick={{ fill: "#9CA3AF", fontSize: 12 }} width={42} />
                  <Tooltip
                    contentStyle={{ background: "#111827", border: "1px solid #374151" }}
                    labelStyle={{ color: "#E5E7EB" }}
                    itemStyle={{ color: "#E5E7EB" }}
                  />
                  <Line
                    type="monotone"
                    dataKey="latency_ms"
                    stroke="#34D399"
                    strokeWidth={2}
                    dot={false}
                    isAnimationActive
                    animationDuration={450}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
}
