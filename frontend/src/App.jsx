import { useState } from "react";
import Dashboard from "./components/Dashboard.jsx";
import Analysis from "./components/Analysis.jsx";

export default function App() {
  const [tab, setTab] = useState("dashboard");

  return (
    <>
      <div className="fixed top-4 right-4 z-50 flex items-center gap-1 rounded-2xl border border-gray-700 bg-gray-900/60 p-1 backdrop-blur">
        <button
          onClick={() => setTab("dashboard")}
          className={
            "px-3 py-1.5 rounded-xl text-sm transition " +
            (tab === "dashboard"
              ? "bg-gray-700 text-white"
              : "text-gray-300 hover:text-white hover:bg-gray-800")
          }
        >
          Dashboard
        </button>
        <button
          onClick={() => setTab("analysis")}
          className={
            "px-3 py-1.5 rounded-xl text-sm transition " +
            (tab === "analysis"
              ? "bg-gray-700 text-white"
              : "text-gray-300 hover:text-white hover:bg-gray-800")
          }
        >
          Analysis
        </button>
      </div>

      {tab === "dashboard" ? <Dashboard /> : <Analysis />}
    </>
  );
}
