import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Trash2, Shield, Activity, Loader2 } from "lucide-react";
import { getRules, addRule, deleteRule, applyRules, applyRule } from "../api";

export default function Dashboard() {
  const [rules, setRules] = useState([]);
  const [form, setForm] = useState({ ip: "", port: "", action: "allow" });
  const [loading, setLoading] = useState(false);
  const [applyingRuleId, setApplyingRuleId] = useState(null);
  const [deletingRuleId, setDeletingRuleId] = useState(null);
  const [toasts, setToasts] = useState([]);

  const pushToast = (message, type = "error") => {
    const id =
      (typeof crypto !== "undefined" && crypto.randomUUID && crypto.randomUUID()) ||
      `${Date.now()}-${Math.random().toString(16).slice(2)}`;

    setToasts((prev) => [...prev, { id, message, type }]);
    window.setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 4000);
  };

  const getErrorMessage = (err, fallback) => {
    if (err instanceof Error && err.message) return err.message;
    if (typeof err === "string" && err) return err;
    return fallback;
  };

  const load = async () => {
    try {
      const data = await getRules();
      setRules(data);
    } catch (err) {
      pushToast(getErrorMessage(err, "Failed to load rules"));
    }
  };

  useEffect(() => { load(); }, []);

  const handleAdd = async () => {
    if (!form.ip) return;
    try {
      await addRule(form);
      setForm({ ip: "", port: "", action: "allow" });
      await load();
      pushToast("Rule added successfully", "success");
    } catch (err) {
      pushToast(getErrorMessage(err, "Failed to add rule"));
    }
  };

  const handleApplyRule = async (ruleId) => {
    const ok = window.confirm("Apply this rule to the firewall now?");
    if (!ok) return;
    try {
      setApplyingRuleId(ruleId);
      await applyRule(ruleId);
      await load();
      pushToast("Rule applied successfully", "success");
    } catch (err) {
      pushToast(getErrorMessage(err, "Failed to apply rule"));
    } finally {
      setApplyingRuleId(null);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 text-white p-6">
      <div className="fixed top-16 right-4 z-50 space-y-2">
        {toasts.map((t) => (
          <div
            key={t.id}
            role="alert"
            className={
              "max-w-sm rounded-lg px-4 py-3 shadow-lg border " +
              (t.type === "success"
                ? "bg-green-900/80 border-green-700 text-green-100"
                : "bg-red-900/80 border-red-700 text-red-100")
            }
          >
            {t.message}
          </div>
        ))}
      </div>

      <motion.h1
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="text-3xl font-bold mb-6 flex items-center gap-2"
      >
        <Shield className="w-8 h-8 text-green-400" /> NRF24 Firewall Dashboard
      </motion.h1>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        {[{ label: "Staged Rules", value: rules.length, icon: Shield },
          { label: "Blocked Packets", value: "--", icon: Activity },
          { label: "Throughput", value: "-- Mbps", icon: Activity }].map((stat, i) => (
          <motion.div key={i} whileHover={{ scale: 1.05 }}>
            <div className="bg-gray-800 rounded-2xl p-4 flex justify-between items-center shadow">
              <div>
                <p className="text-sm text-gray-400">{stat.label}</p>
                <h2 className="text-xl font-semibold">{stat.value}</h2>
              </div>
              <stat.icon className="w-6 h-6 text-green-400" />
            </div>
          </motion.div>
        ))}
      </div>

      {/* Add Rule */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
        <div className="bg-gray-800 rounded-2xl p-4 mb-6 flex flex-col md:flex-row gap-3 shadow">
          <input
            className="p-2 rounded bg-gray-700"
            placeholder="IP Address"
            value={form.ip}
            onChange={(e) => setForm({ ...form, ip: e.target.value })}
          />
          <input
            className="p-2 rounded bg-gray-700"
            placeholder="Port (optional)"
            value={form.port}
            onChange={(e) => setForm({ ...form, port: e.target.value })}
          />
          <select
            className="p-2 rounded bg-gray-700"
            value={form.action}
            onChange={(e) => setForm({ ...form, action: e.target.value })}
          >
            <option value="allow">Allow</option>
            <option value="block">Block</option>
          </select>
          <button onClick={handleAdd} className="bg-green-500 hover:bg-green-600 px-4 py-2 rounded">
            Add Rule
          </button>
          <button
            onClick={async () => {
              const ok = window.confirm("Apply all staged rules to the firewall now?");
              if (!ok) return;
              setLoading(true);
              try {
                await applyRules();
                await load();
                pushToast("Rules applied successfully", "success");
              } catch (err) {
                pushToast(getErrorMessage(err, "Failed to apply rules"));
              } finally {
                setLoading(false);
              }
            }}
            className="bg-blue-500 hover:bg-blue-600 px-4 py-2 rounded"
          >
            {loading ? "Applying..." : "Apply Rules"}
          </button>
        </div>
      </motion.div>

      {/* Rules List */}
      <div className="space-y-3">
        {rules.map((rule) => (
          <motion.div
            key={rule.id}
            initial={{ opacity: 0, x: 50 }}
            animate={{ opacity: 1, x: 0 }}
            whileHover={{ scale: 1.02 }}
          >
            <div className="bg-gray-800 rounded-2xl p-4 flex justify-between items-center shadow">
              <div>
                <p className="font-medium">{rule.ip}:{rule.port || "*"}</p>
                <p className={`text-sm ${rule.action === "block" ? "text-red-400" : "text-green-400"}`}>
                  {rule.action.toUpperCase()}
                </p>
              </div>
              <div className="flex items-center gap-3">
                <span
                  className={
                    `text-xs px-2 py-1 rounded-full ` +
                    (rule.applied
                      ? "bg-green-500/20 text-green-400"
                      : "bg-yellow-500/20 text-yellow-300")
                  }
                >
                  {rule.applied ? "Applied" : "Not Applied"}
                </span>

                {!rule.applied && (
                  <button
                    onClick={() => handleApplyRule(rule.id)}
                    disabled={applyingRuleId === rule.id}
                    className="bg-blue-500 hover:bg-blue-600 disabled:opacity-60 disabled:hover:bg-blue-500 px-3 py-1 rounded text-sm"
                  >
                    {applyingRuleId === rule.id ? "Applying..." : "Apply Rule"}
                  </button>
                )}

                <button
                  onClick={async () => {
                      const ok = window.confirm("Delete this rule?");
                      if (!ok) return;
                    try {
                        setDeletingRuleId(rule.id);
                      await deleteRule(rule.id);
                      await load();
                        pushToast("Rule deleted successfully", "success");
                    } catch (err) {
                      pushToast(getErrorMessage(err, "Failed to delete rule"));
                      } finally {
                        setDeletingRuleId(null);
                    }
                  }}
                    disabled={deletingRuleId === rule.id}
                    className="text-red-400 hover:text-red-500 disabled:opacity-60 disabled:hover:text-red-400"
                >
                    {deletingRuleId === rule.id ? (
                      <Loader2 className="animate-spin" />
                    ) : (
                      <Trash2 />
                    )}
                </button>
              </div>
            </div>
          </motion.div>
        ))}
      </div>
    </div>
  );
}