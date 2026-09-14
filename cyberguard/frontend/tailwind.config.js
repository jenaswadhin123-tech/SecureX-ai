/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        darkBg: "#0D1016",
        cardBg: "#141820",
        cardBorder: "#30343B",
        accentBlue: "#3B9EFF",
        primaryText: "#F5F5F5",
        secondaryText: "#A1A1AA",
      }
    },
  },
  plugins: [],
}
