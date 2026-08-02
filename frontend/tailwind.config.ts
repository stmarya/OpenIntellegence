import type { Config } from 'tailwindcss';

const config: Config = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        surface: {
          DEFAULT: '#0E1014',
          deep: '#0A0C0F',
          card: '#141720',
          elevated: '#1A1F2E',
        },
        border: {
          DEFAULT: '#1E2130',
          muted: '#252A3A',
        },
        accent: {
          DEFAULT: '#16A9A0',
          hover: '#14948B',
          muted: '#16A9A020',
        },
        risk: {
          critical: '#DC2626',
          high: '#EA580C',
          medium: '#CA8A04',
          low: '#2563EB',
          info: '#6B7280',
          unknown: '#374151',
        },
        text: {
          primary: '#E8EAF0',
          secondary: '#9BA3B8',
          muted: '#6B7280',
          accent: '#16A9A0',
        },
      },
      fontSize: {
        xs: ['11px', { lineHeight: '1.4' }],
        sm: ['13px', { lineHeight: '1.4' }],
        base: ['13px', { lineHeight: '1.5' }],
        md: ['14px', { lineHeight: '1.5' }],
        lg: ['16px', { lineHeight: '1.5' }],
        xl: ['18px', { lineHeight: '1.4' }],
        '2xl': ['22px', { lineHeight: '1.3' }],
      },
      borderRadius: {
        DEFAULT: '4px',
        sm: '2px',
        md: '4px',
        lg: '6px',
        xl: '8px',
        full: '9999px',
        none: '0',
      },
      transitionDuration: {
        fast: '120ms',
        DEFAULT: '120ms',
      },
      transitionTimingFunction: {
        DEFAULT: 'cubic-bezier(0.0, 0.0, 0.2, 1)',
        'ease-out': 'cubic-bezier(0.0, 0.0, 0.2, 1)',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
      },
      spacing: {
        sidebar: '240px',
        'sidebar-collapsed': '48px',
        topbar: '48px',
      },
      ringColor: {
        DEFAULT: '#16A9A0',
        accent: '#16A9A0',
      },
      ringOffsetColor: {
        DEFAULT: '#0E1014',
      },
    },
  },
  plugins: [],
};

export default config;
