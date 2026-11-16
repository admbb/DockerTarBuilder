import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { Dashboard } from "./pages/Dashboard";
import "./styles.css";
import { isChinese } from "./lib/i18n";

document.documentElement.lang = isChinese() ? "zh-CN" : "en";

// /dashboard is the unattended wall display; everything else is the full app.
const wallDisplay = window.location.pathname.replace(/\/+$/, "") === "/dashboard";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    {wallDisplay ? <Dashboard /> : <App />}
  </StrictMode>,
);
