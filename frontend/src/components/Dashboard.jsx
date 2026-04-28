import { useEffect, useState } from "react";
import { getRules, addRule, deleteRule } from "../api";

export default function Dashboard() {
  const [rules, setRules] = useState([]);
  const [ip, setIp] = useState("");

  const load = async () => {
    const data = await getRules();
    setRules(data);
  };

  useEffect(() => { load(); }, []);

  return (
    <div style={{ padding: 20 }}>
      <h1>Firewall Dashboard</h1>
      <input value={ip} onChange={e => setIp(e.target.value)} placeholder="IP" />
      <button onClick={async () => {
        await addRule({ ip, port: "", action: "allow" });
        load();
      }}>
        Add Rule
      </button>

      <ul>
        {rules.map(r => (
          <li key={r.id}>
            {r.ip}
            <button onClick={async () => {
              await deleteRule(r.id);
              load();
            }}>X</button>
          </li>
        ))}
      </ul>
    </div>
  );
}
