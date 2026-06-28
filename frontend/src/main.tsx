import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "performative-ui/styles.css";
import "dockview-core/dist/styles/dockview.css";
import "./index.css";
import "./shell/dockview-theme.css";
import "./lib/accent"; // applies the saved accent on load
import { pinWindowEngagement } from "./lib/windowEngagement";

pinWindowEngagement(); // adopt ?engagement=<id> before first render

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
