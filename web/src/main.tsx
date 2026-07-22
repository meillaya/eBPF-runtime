// SPDX-License-Identifier: Apache-2.0 OR MIT
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import "./styles/tokens.css";
import "./styles/app.css";
import "./styles/shell.css";
import "./styles/ui.css";
import "./styles/ui-data.css";
import "./styles/ui-feedback.css";
import "./styles/ui-ops.css";
import "./styles/ui-telemetry.css";
import "./styles/ui-tree.css";
import "./styles/ui-views.css";

const rootEl = document.getElementById("root");
if (rootEl === null) throw new Error("#root mount point missing from index.html");

createRoot(rootEl).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
