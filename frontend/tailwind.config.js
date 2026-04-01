export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Bahnschrift", "Segoe UI", "sans-serif"],
        mono: ["Consolas", "Monaco", "monospace"],
      },
      boxShadow: {
        glow: "0 0 0 1px rgba(102, 255, 224, 0.14), 0 24px 60px rgba(0, 0, 0, 0.42)",
      },
    },
  },
  plugins: [],
};
