/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        darkBg: "#0B081A",
        cardBg: "#11152F",
        cardBorder: "#292852",
        accentBlue: "#A855F7",
        primaryText: "#F5F5F5",
        secondaryText: "#9B9AB8",
      }
    },
  },
  plugins: [],
}
