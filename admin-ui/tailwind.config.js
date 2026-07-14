/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: [
    './index.html',
    './src/**/*.{js,ts,jsx,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        argus: {
          bg: '#0f172a',
          card: '#1e293b',
          border: '#334155',
          text: '#e2e8f0',
          muted: '#94a3b8',
          accent: '#38bdf8',
          success: '#34d399',
          warning: '#fbbf24',
          danger: '#f87171',
          purple: '#a78bfa',
        },
      },
    },
  },
  plugins: [],
}
