/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        bg: {
          darkest: '#031F1D',
          dark: '#042724',
          deep: '#061A19',
        },
        surface: {
          default: '#071E1D',
          hover: '#0A2523',
          card: '#0C2927',
          border: 'rgba(22, 217, 208, 0.15)',
        },
        teal: {
          accent: '#16D9D0',
          hover: '#13CFC7',
          vibrant: '#1DE9E1',
          secondary: '#20AFA8',
          muted: '#168F8A',
        },
        text: {
          primary: '#E8FFFD',
          secondary: '#9AB8B5',
          muted: '#668582',
        },
        status: {
          critical: '#FF5C67',
          high: '#FF9F43',
          medium: '#F6D365',
          low: '#38D39F',
          info: '#45C7FF',
        }
      },
      boxShadow: {
        'teal-glow': '0 0 15px -3px rgba(22, 217, 208, 0.25)',
        'teal-glow-lg': '0 0 25px -2px rgba(22, 217, 208, 0.35)',
        'critical-glow': '0 0 15px -3px rgba(255, 92, 103, 0.3)',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      }
    },
  },
  plugins: [],
}
