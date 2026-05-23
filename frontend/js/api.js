const API_BASE = window.KPASS_API_BASE || (
    window.location.protocol === "file:"
        ? "http://127.0.0.1:8000/api"
        : `${window.location.origin}/api`
);

function getToken() {
    return localStorage.getItem("kpass_token");
}

function setToken(token) {
    localStorage.setItem("kpass_token", token);
}

function logout() {
    localStorage.removeItem("kpass_token");
    window.location.href = "login.html";
}

async function apiRequest(path, options = {}) {
    const headers = {
        "Content-Type": "application/json",
        ...(options.headers || {})
    };

    const token = getToken();

    if (token) {
        headers["Authorization"] = `Bearer ${token}`;
    }

    const response = await fetch(`${API_BASE}${path}`, {
        ...options,
        headers
    });

    const text = await response.text();
    const data = text ? JSON.parse(text) : {};

    if (!response.ok) {
        throw new Error(data.detail || "Something went wrong");
    }

    return data;
}
