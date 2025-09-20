/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        // Updated primary color to a cyber blue palette
        primary: {
          50: '#e6f1fe',
          100: '#cce3fd',
          200: '#99c8fb',
          300: '#66acf9',
          400: '#3391f7',
          500: '#0075f5',
          600: '#005ec4',
          700: '#004693',
          800: '#002f62',
          900: '#001731',
          950: '#000c19',
        },
        // Keeping danger/red for phishing warnings
        danger: {
          50: '#fef2f2',
          100: '#fee2e2',
          200: '#fecaca',
          300: '#fca5a5',
          400: '#f87171',
          500: '#ef4444',
          600: '#dc2626',
          700: '#b91c1c',
          800: '#991b1b',
          900: '#7f1d1d',
          950: '#450a0a',
        },
        // Keeping success/green for legitimate URLs
        success: {
          50: '#f0fdf4',
          100: '#dcfce7',
          200: '#bbf7d0',
          300: '#86efac',
          400: '#4ade80',
          500: '#22c55e',
          600: '#16a34a',
          700: '#15803d',
          800: '#166534',
          900: '#14532d',
          950: '#052e16',
        },
        // Adding a cyber theme dark palette for backgrounds and accents
        cyber: {
          dark: '#0a1929',
          darker: '#061324',
          darkest: '#030a12',
          light: '#173d5c',
          accent: '#00ccff',
          warning: '#ffcc00',
          glow: '#00eeff',
        },
      },
      // Adding gradients for cybersecurity theme
      backgroundImage: {
        'cyber-gradient': 'linear-gradient(to right, #0a1929, #173d5c)',
        'cyber-gradient-vertical': 'linear-gradient(to bottom, #0a1929, #173d5c)',
        'cyber-card': 'linear-gradient(135deg, rgba(10, 25, 41, 0.95), rgba(23, 61, 92, 0.95))',
        'glow-effect': 'radial-gradient(circle, rgba(0, 238, 255, 0.15) 0%, rgba(10, 25, 41, 0) 70%)',
      },
      // Adding text shadow for cybersecurity glow effects
      textShadow: {
        'cyber-glow': '0 0 8px rgba(0, 238, 255, 0.7)',
        'cyber-text': '0 0 5px rgba(0, 204, 255, 0.5)',
      },
      // Adding box shadow for cybersecurity glow effects
      boxShadow: {
        'cyber-glow': '0 0 10px rgba(0, 238, 255, 0.5)',
        'cyber-glow-lg': '0 0 20px rgba(0, 238, 255, 0.7)',
        'card': '0 0 0 1px rgba(0, 0, 0, 0.05), 0 1px 3px 0 rgba(0, 0, 0, 0.1)',
      },
      // Border styles for cyber-themed elements
      borderWidth: {
        'cyber': '1px',
      },
      animation: {
        'pulse-glow': 'pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'cyber-scan': 'cyber-scan 2s ease-in-out infinite',
      },
      keyframes: {
        'cyber-scan': {
          '0%, 100%': { boxShadow: '0 0 5px rgba(0, 238, 255, 0.3)' },
          '50%': { boxShadow: '0 0 20px rgba(0, 238, 255, 0.8)' },
        },
      },
      fontFamily: {
        'cyber': ['Orbitron', 'Rajdhani', 'sans-serif'],
      },
      screens: {
        'xs': '480px',
      },
      typography: {
        DEFAULT: {
          css: {
            maxWidth: '100ch',
          },
        },
      },
      strokeWidth: {
        '3': '3',
        '4': '4',
      },
      listStyleType: {
        square: 'square',
        circle: 'circle',
      },
      opacity: {
        '85': '0.85',
        '95': '0.95',
      },
      rotate: {
        '270': '270deg',
      },
      scale: {
        '175': '1.75',
      },
      transitionDuration: {
        '400': '400ms',
      },
      zIndex: {
        '60': '60',
        '70': '70',
      },
      blur: {
        'xs': '2px',
      },
      backdropBlur: {
        'xs': '2px',
      },
      outline: {
        'cyber': '1px solid rgba(0, 238, 255, 0.5)',
      },
      ringWidth: {
        '3': '3px',
      },
      ringOffsetWidth: {
        '3': '3px',
      },
      borderRadius: {
        'xl': '1rem',
        '2xl': '1.5rem',
      },
    },
  },
  plugins: [],
}
