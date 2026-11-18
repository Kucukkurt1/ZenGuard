"use client";

import { createContext, useContext, useEffect, useState } from "react";

export type ThemeName = "soft" | "dark";

const ThemeContext = createContext<{
  theme: ThemeName;
  toggle: () => void;
}>({ theme: "soft", toggle: () => undefined });

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setTheme] = useState<ThemeName>("soft");

  useEffect(() => {
    const saved = window.localStorage.getItem("zg-palette");
    if (saved === "dark" || saved === "soft") setTheme(saved);
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    window.localStorage.setItem("zg-palette", theme);
  }, [theme]);

  return (
    <ThemeContext.Provider
      value={{
        theme,
        toggle: () => setTheme((current) => (current === "soft" ? "dark" : "soft")),
      }}
    >
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme() {
  return useContext(ThemeContext);
}
