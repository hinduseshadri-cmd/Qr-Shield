# QR Shield — AI-Based QR Attack Detection

Scans QR codes (camera or uploaded image), checks URLs, and classifies each as **Safe / Suspicious / Malicious**.
Includes a dashboard, threat alerts, scan history and downloadable reports (TXT, CSV, JSON).

## Step-by-step in VS Code
1. Install **Node.js 18+** from https://nodejs.org (LTS). Check: `node -v`
2. Unzip this project, then in VS Code: **File → Open Folder…** → choose the `qr-shield` folder.
3. Open the terminal: **Terminal → New Terminal** (Ctrl + `).
4. Install dependencies: `npm install`
5. Start the server: `npm start`  → you should see `QR Shield running at http://localhost:3000`
6. Open **http://localhost:3000** in Chrome/Edge.
7. (Optional) Run the 26 automated checks: `npm test`
8. Stop the server with Ctrl + C. Debug with F5 ("Run QR Shield").

## Project structure
    qr-shield/
    ├── server.js        Express API: scan, upload, URL check, history, stats, reports
    ├── analyzer.js      Rule-based threat scoring engine
    ├── public/
    │   └── index.html   The whole app (HTML + CSS + JS in one file)
    ├── test/run-tests.js  End-to-end tests
    ├── data/            Created automatically: scans.json, settings.json
    └── package.json

## API
| Endpoint | Purpose |
|---|---|
| `POST /api/analyze` `{content}` | Analyse text/URL decoded by the camera, and save it |
| `POST /api/upload` (multipart `image`) | Server decodes the QR image, analyses and saves it |
| `POST /api/url` `{url}` | URL checker |
| `GET /api/history`, `DELETE /api/history[/:id]` | Scan history |
| `GET /api/stats` · `GET /api/alerts` | Dashboard data · threats only |
| `GET/PUT /api/settings` | Sensitivity: low / medium / high |
| `GET /api/report?format=txt\|csv\|json` | Report download |

## Notes
- `public/index.html` also works on its own: double-click it with no server and it runs in
  "Standalone mode" (analysis in the browser, history in browser storage).
- Camera scanning needs `http://localhost:3000` (or HTTPS) plus browser permission.
- The server never opens the scanned URLs, so scanning a malicious QR can't make the server contact it.
- Needs internet for the icon/chart/scanner libraries (loaded from CDNs).
