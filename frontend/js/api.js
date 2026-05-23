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
    sessionStorage.removeItem("kpass_master_token");
    window.location.href = "login.html";
}

function getMasterToken() {
    return sessionStorage.getItem("kpass_master_token");
}

function setMasterToken(token) {
    sessionStorage.setItem("kpass_master_token", token);
}

function getTheme() {
    return localStorage.getItem("kpass_theme") || "light";
}

function applyTheme(theme = getTheme()) {
    document.body.classList.toggle("dark-mode", theme === "dark");
    localStorage.setItem("kpass_theme", theme);
    document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
        button.textContent = theme === "dark" ? "Light" : "Dark";
        button.setAttribute("aria-label", `Switch to ${theme === "dark" ? "light" : "dark"} mode`);
    });
}

function toggleTheme() {
    applyTheme(getTheme() === "dark" ? "light" : "dark");
}

document.addEventListener("DOMContentLoaded", () => {
    applyTheme();
    document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
        button.addEventListener("click", toggleTheme);
    });
});

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
