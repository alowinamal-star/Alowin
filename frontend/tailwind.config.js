/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        navy: {
          950: "#04070f",
          900: "#070b1a",
          850: "#0a1024",
          800: "#0e162e",
          700: "#16203d",
          600: "#1e2b4d",
        },
        shield: {
          cyan: "#22d3ee",
          blue: "#3b82f6",
          purple: "#a855f7",
        },
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "monospace"],
      },
      boxShadow: {
        glow: "0 0 24px rgba(34, 211, 238, 0.18)",
        "glow-lg": "0 0 60px rgba(59, 130, 246, 0.22)",
      },
      keyframes: {
        "fade-up": {
          "0%": { opacity: "0", transform: "translateY(8px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        pulseRing: {
          "0%": { boxShadow: "0 0 0 0 rgba(34, 211, 238, 0.35)" },
          "70%": { boxShadow: "0 0 0 10px rgba(34, 211, 238, 0)" },
          "100%": { boxShadow: "0 0 0 0 rgba(34, 211, 238, 0)" },
        },
      },
      animation: {
        "fade-up": "fade-up 0.35s ease-out both",
        "pulse-ring": "pulseRing 2s infinite",
      },
    },
  },
  plugins: [],
};
