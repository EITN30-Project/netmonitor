const API = "http://localhost:8000/api";

const apiFetch = async (path, options) => {
  let res;
  try {
    res = await fetch(`${API}${path}`, options);
  } catch {
    throw new Error(
      "Can't reach the backend API (http://localhost:8000). Is it running?"
    );
  }

  if (!res.ok) {
    let message = `Request failed (${res.status})`;
    try {
      const data = await res.json();
      if (data && typeof data === "object" && "detail" in data) {
        message = data.detail;
      }
    } catch {
      // ignore JSON parse errors
    }
    throw new Error(message);
  }

  // Some endpoints may return an empty body
  const contentType = res.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    return res.json();
  }
  return null;
};

export const getRules = async () => {
  return apiFetch("/rules");
};

export const addRule = async (data) => {
  await apiFetch("/rules", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data)
  });
};

export const deleteRule = async (id) => {
  await apiFetch(`/rules/${id}`, { method: "DELETE" });
};

export const applyRules = async () => {
  await apiFetch("/apply", { method: "POST" });
};

export const applyRule = async (id) => {
  await apiFetch(`/rules/${id}/apply`, { method: "POST" });
};