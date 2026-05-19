# Contributing

## Development Rules

- Use Node `22.19.0` or newer and npm `10.x` or newer.
- Run `npm run typecheck`, `npm run lint`, `npm test`, and `npm run build` before opening a PR.
- Do not commit local artifacts, generated files, or secrets.

## File Ownership

- `src/`: renderer app, React UI, Zustand stores, AI logic
- `electron/`: main process and preload bridge
- `engine/`: scanning, reporting, and low-level analysis logic
- `public/`: static assets served into the renderer build

## Naming Conventions

- React components: `PascalCase.tsx`
- Hooks and Zustand stores: `camelCase.ts` with `use...` prefixes where applicable
- Utility modules: descriptive `kebab-case` or `camelCase`, but keep the style consistent with the folder you edit
- Tests: `*.test.ts`, `*.test.tsx`, `*.spec.ts`, or `*.spec.tsx`

## Import Rules

- Allowed aliases:
  - `@/` for renderer code under `src/`
  - `@engine/` for engine code under `engine/`
- Prefer short relative imports inside the same folder subtree.
- Avoid deep `../../../` chains when an alias makes the import clearer.

## Source Of Truth Rules

- Edit TypeScript source, not generated JavaScript copies.
- Do not add compiled `.js` siblings inside `src/`.
- Keep build output in `dist-electron/` only.

## Documentation Rules

- Update `README.md` when setup, scripts, runtime requirements, or build flow change.
- Document any new environment variable in `.env.example`.
