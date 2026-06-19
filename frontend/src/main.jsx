import React from "react";
import ReactDOM from "react-dom/client";
import { createBrowserRouter, RouterProvider } from "react-router-dom";

import "./index.css";
import Landing from "./pages/Landing";
import WarRoom from "./pages/WarRoom";
import Summary from "./pages/Summary";

const router = createBrowserRouter([
  { path: "/", element: <Landing /> },
  { path: "/war-room/:invId", element: <WarRoom /> },
  { path: "/summary/:invId", element: <Summary /> },
]);

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <RouterProvider router={router} />
  </React.StrictMode>
);
