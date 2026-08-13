import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import { AppearanceProvider } from "./app/appearance";
import { queryClient, router } from "./app/router";
import "./styles/global.css";

const root = document.getElementById("root");
if (!root) throw new Error("Arca could not find its application root.");

createRoot(root).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <AppearanceProvider>
        <RouterProvider router={router} />
      </AppearanceProvider>
    </QueryClientProvider>
  </StrictMode>,
);
