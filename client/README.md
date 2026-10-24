# LAN-CAP client

React 19 + Vite dashboard for the LAN-CAP API. It is served by the Express
server in production; during development Vite proxies `/api` to the API.

```bash
npm install
npm run dev     # http://localhost:5173 (API must be on :5174)
npm run build   # production bundle in dist/
npm run lint    # oxlint
```

The 3D topology lives in `src/topo.jsx` and is intentionally dependency-free:
positions are computed on tilted 3D orbits, camera rotation and perspective are
plain trigonometry, and the result is rendered as depth-sorted SVG.
