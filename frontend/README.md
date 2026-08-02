# OpenIntellegence Frontend

A production-oriented Next.js 14 + TypeScript frontend for the OpenIntellegence threat intelligence platform.

## Status

⚠️ **DEMO MODE**: When `NEXT_PUBLIC_API_BASE_URL` is not set, the application uses clearly-labeled mock data. No live backend integration is active.

## Tech Stack

- **Next.js 14** (App Router)
- **TypeScript** (strict mode)
- **Tailwind CSS** with custom design tokens
- **Jest + React Testing Library**

## Getting Started

```bash
# Install dependencies
npm install

# Copy env template
cp .env.example .env.local

# Start development server (uses mock data by default)
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

## Available Scripts

| Command | Description |
|---|---|
| `npm run dev` | Start development server |
| `npm run build` | Build for production |
| `npm run start` | Start production server |
| `npm run lint` | Run ESLint |
| `npm run type-check` | Run TypeScript type checking |
| `npm test` | Run test suite |

## Environment Variables

See `.env.example` for all available variables.

| Variable | Description |
|---|---|
| `NEXT_PUBLIC_API_BASE_URL` | Backend API base URL. **Leave empty to use mock data.** |
| `NEXT_PUBLIC_ENV_LABEL` | Environment label shown in top bar |
| `NEXT_PUBLIC_TENANT_NAME` | Tenant name shown in top bar |
| `API_KEY` | Server-side API key (not exposed to browser) |

## Data Mode

- **Mock mode** (default): `NEXT_PUBLIC_API_BASE_URL` is empty. All data is static demo data clearly labeled `[DEMO DATA]`. No external requests are made.
- **Live mode**: Set `NEXT_PUBLIC_API_BASE_URL` to your backend URL. The API client will make authenticated requests.

## Design System

The UI uses a dark surface design system:

- **Backgrounds**: `#0E1014` (main), `#0A0C0F` (sidebar), `#141720` (cards)
- **Accent**: `#16A9A0` (teal)
- **Risk colors**: critical=`#DC2626`, high=`#EA580C`, medium=`#CA8A04`, low=`#2563EB`, info=`#6B7280`
- **Typography**: 13px base, monospace for code/hashes
- **Motion**: 120ms ease-out, respects `prefers-reduced-motion`

## Project Structure

```
src/
├── app/
│   ├── (app)/           # Authenticated app shell
│   │   ├── overview/
│   │   ├── intelligence/
│   │   ├── indicators/
│   │   ├── assets/
│   │   ├── vulnerabilities/
│   │   ├── alerts/
│   │   ├── correlations/
│   │   ├── investigations/
│   │   ├── automation/
│   │   ├── commands/
│   │   ├── reports/
│   │   ├── connectors/
│   │   └── ai-analyst/
│   ├── globals.css
│   ├── layout.tsx
│   └── page.tsx
├── components/
│   ├── layout/          # AppShell, Sidebar, TopBar, CommandPalette
│   └── ui/              # RiskBadge, DataTable, etc.
├── lib/
│   ├── api/             # Typed API client + mock data
│   └── utils.ts
└── types/
    └── index.ts
```

## Notes

- All mock data is clearly labeled in code with `// [DEMO DATA - not connected to backend]`
- A visible "DEMO" badge appears in the UI when using mock data
- The Commands page is approval-gated — no autonomous execution
- The AI Analyst page is read-only with citation support; no autonomous execution buttons
