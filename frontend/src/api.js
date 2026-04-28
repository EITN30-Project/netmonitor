const API = "http://localhost:8000/api";

export const getRules = async () => {
  const res = await fetch(`${API}/rules`);
  return res.json();
};

export const addRule = async (data) => {
  await fetch(`${API}/rules`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data)
  });
};

export const deleteRule = async (id) => {
  await fetch(`${API}/rules/${id}`, { method: "DELETE" });
};
