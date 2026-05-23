const API_BASE = "http://127.0.0.1:8000/api"

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
        ...API_BASE(options.headers || {})
    };

    const token = getToken();

    if (token) {
        headers["Authorization"] = `Bearer ${token}`;
    }

    const response = await fetch(`${API_BASE}${path}`, {
        ...options,
        headers
    });

    const data = await response.json(() => ({}));

    if (!response.ok) {
        throw new Error(data.detail || "Something went wrong");
    }

    return data;
}