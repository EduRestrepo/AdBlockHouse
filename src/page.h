#pragma once
// C3 AdBlock Pro - Modern, high-performance Glassmorphism Dashboard
// Self-contained vanilla HTML/CSS/JS in PROGMEM

const char PAGE[] PROGMEM = R"HTML(<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>C3 AdBlock Pro</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root {
  --bg: #090d16;
  --surface: #111726;
  --surface-hover: #172033;
  --surface-border: #1e293b;
  --text: #f1f5f9;
  --text-muted: #94a3b8;
  --primary: #38bdf8;
  --primary-glow: rgba(56, 189, 248, 0.15);
  --success: #10b981;
  --success-glow: rgba(16, 185, 129, 0.15);
  --danger: #ef4444;
  --danger-glow: rgba(239, 68, 68, 0.15);
  --warning: #f59e0b;
  --radius: 12px;
  --font: 'Plus Jakarta Sans', system-ui, -apple-system, sans-serif;
  --mono: 'JetBrains Mono', monospace;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: var(--font);
  background: var(--bg);
  color: var(--text);
  line-height: 1.5;
  min-height: 100vh;
}
header {
  background: rgba(17, 23, 38, 0.85);
  backdrop-filter: blur(12px);
  border-bottom: 1px solid var(--surface-border);
  padding: 14px 24px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  position: sticky;
  top: 0;
  z-index: 100;
}
.brand {
  display: flex;
  align-items: center;
  gap: 12px;
}
.logo-icon {
  width: 36px;
  height: 36px;
  background: linear-gradient(135deg, #0ea5e9, #10b981);
  border-radius: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 20px;
  box-shadow: 0 0 20px rgba(14, 165, 233, 0.3);
}
.brand h1 {
  font-size: 18px;
  font-weight: 700;
  letter-spacing: -0.02em;
}
.brand h1 span {
  background: linear-gradient(135deg, #38bdf8, #34d399);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}
.badge-pro {
  background: rgba(56, 189, 248, 0.2);
  color: #38bdf8;
  font-size: 11px;
  font-weight: 600;
  padding: 2px 7px;
  border-radius: 6px;
  border: 1px solid rgba(56, 189, 248, 0.4);
}
.header-actions {
  display: flex;
  align-items: center;
  gap: 12px;
}
.status-pill {
  display: flex;
  align-items: center;
  gap: 8px;
  background: var(--surface);
  border: 1px solid var(--surface-border);
  padding: 6px 14px;
  border-radius: 20px;
  font-size: 13px;
  font-weight: 500;
}
.dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--success);
  box-shadow: 0 0 8px var(--success);
}
.dot.paused {
  background: var(--warning);
  box-shadow: 0 0 8px var(--warning);
}
.container {
  max-width: 1200px;
  margin: 0 auto;
  padding: 24px 20px;
}
.nav-tabs {
  display: flex;
  gap: 8px;
  border-bottom: 1px solid var(--surface-border);
  margin-bottom: 24px;
  overflow-x: auto;
  padding-bottom: 2px;
}
.tab-btn {
  background: transparent;
  border: none;
  color: var(--text-muted);
  font-family: var(--font);
  font-size: 14px;
  font-weight: 600;
  padding: 10px 16px;
  border-radius: 8px 8px 0 0;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 8px;
  transition: all 0.2s;
  white-space: nowrap;
}
.tab-btn:hover {
  color: var(--text);
  background: var(--surface-hover);
}
.tab-btn.active {
  color: var(--primary);
  border-bottom: 2px solid var(--primary);
  background: rgba(56, 189, 248, 0.08);
}
.tab-pane {
  display: none;
}
.tab-pane.active {
  display: block;
}
/* Pause Bar */
.pause-banner {
  background: linear-gradient(135deg, rgba(30, 41, 59, 0.7), rgba(15, 23, 42, 0.7));
  border: 1px solid var(--surface-border);
  border-radius: var(--radius);
  padding: 14px 20px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 24px;
}
.pause-banner.is-paused {
  border-color: var(--warning);
  background: rgba(245, 158, 11, 0.08);
}
/* Cards Grid */
.grid-stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
}
.stat-card {
  background: var(--surface);
  border: 1px solid var(--surface-border);
  border-radius: var(--radius);
  padding: 18px 20px;
  display: flex;
  flex-direction: column;
  transition: transform 0.2s, border-color 0.2s;
}
.stat-card:hover {
  border-color: #334155;
  transform: translateY(-2px);
}
.stat-title {
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--text-muted);
  margin-bottom: 6px;
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.stat-value {
  font-size: 28px;
  font-weight: 700;
  letter-spacing: -0.02em;
}
.stat-sub {
  font-size: 12px;
  color: var(--text-muted);
  margin-top: 4px;
}
.c-blocked { color: var(--danger); }
.c-allowed { color: var(--success); }
.c-cache { color: #a855f7; }
.c-primary { color: var(--primary); }

/* Visual Chart Area */
.charts-grid {
  display: grid;
  grid-template-columns: 320px 1fr;
  gap: 20px;
  margin-bottom: 24px;
}
@media (max-width: 860px) {
  .charts-grid { grid-template-columns: 1fr; }
}
.card {
  background: var(--surface);
  border: 1px solid var(--surface-border);
  border-radius: var(--radius);
  padding: 20px;
  margin-bottom: 20px;
}
.card-title {
  font-size: 15px;
  font-weight: 600;
  margin-bottom: 16px;
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.donut-wrap {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 16px;
}
.donut-chart {
  width: 170px;
  height: 170px;
  transform: rotate(-90deg);
}
.donut-legend {
  display: flex;
  gap: 14px;
  font-size: 12px;
  flex-wrap: wrap;
  justify-content: center;
}
.legend-item {
  display: flex;
  align-items: center;
  gap: 6px;
}
.legend-dot {
  width: 10px;
  height: 10px;
  border-radius: 3px;
}
/* Tables */
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}
th {
  text-align: left;
  padding: 10px 14px;
  background: rgba(15, 23, 42, 0.6);
  color: var(--text-muted);
  font-weight: 600;
  border-bottom: 1px solid var(--surface-border);
}
td {
  padding: 12px 14px;
  border-bottom: 1px solid #172033;
}
tr:hover td {
  background: rgba(255, 255, 255, 0.02);
}
.mono { font-family: var(--mono); }
/* Badges */
.badge {
  display: inline-flex;
  align-items: center;
  padding: 2px 8px;
  border-radius: 6px;
  font-size: 11px;
  font-weight: 600;
}
.badge-blocked { background: var(--danger-glow); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.3); }
.badge-allowed { background: var(--success-glow); color: var(--success); border: 1px solid rgba(16, 185, 129, 0.3); }
.badge-cache { background: rgba(168, 85, 247, 0.15); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.3); }
.badge-whitelist { background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3); }

/* Forms & Inputs */
input, select, textarea {
  background: #0b0f19;
  border: 1px solid var(--surface-border);
  color: var(--text);
  font-family: var(--font);
  font-size: 13px;
  padding: 8px 12px;
  border-radius: 8px;
  outline: none;
  transition: border-color 0.2s;
}
input:focus, select:focus {
  border-color: var(--primary);
  box-shadow: 0 0 0 2px var(--primary-glow);
}
button {
  font-family: var(--font);
  font-size: 13px;
  font-weight: 600;
  padding: 8px 14px;
  border-radius: 8px;
  border: 1px solid var(--surface-border);
  background: var(--surface-hover);
  color: var(--text);
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  transition: all 0.2s;
}
button:hover {
  background: #243048;
  border-color: #3b4d6b;
}
button.btn-primary {
  background: #0284c7;
  border-color: #0369a1;
  color: #fff;
}
button.btn-primary:hover {
  background: #0369a1;
}
button.btn-danger {
  background: rgba(239, 68, 68, 0.15);
  border-color: rgba(239, 68, 68, 0.3);
  color: #f87171;
}
button.btn-danger:hover {
  background: rgba(239, 68, 68, 0.25);
}
button.btn-sm {
  padding: 4px 8px;
  font-size: 11px;
}
.action-bar {
  display: flex;
  gap: 10px;
  align-items: center;
  margin-bottom: 14px;
  flex-wrap: wrap;
}
/* System Info Table */
.sys-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 12px;
}
.sys-item {
  background: #0d1322;
  border: 1px solid var(--surface-border);
  border-radius: 8px;
  padding: 12px 14px;
}
.sys-label {
  font-size: 11px;
  color: var(--text-muted);
  text-transform: uppercase;
}
.sys-val {
  font-size: 15px;
  font-weight: 600;
  margin-top: 4px;
}
.editable-alias {
  cursor: pointer;
  border-bottom: 1px dashed var(--text-muted);
}
.editable-alias:hover {
  color: var(--primary);
}
</style>
</head>
<body>

<header>
  <div class="brand">
    <div class="logo-icon">🛡️</div>
    <div>
      <h1>C3 AdBlock <span>PRO</span> <span class="badge-pro">v2.0 Turbo</span></h1>
    </div>
  </div>
  <div class="header-actions">
    <div class="status-pill">
      <div id="statDot" class="dot"></div>
      <span id="statText">Activo</span>
    </div>
    <span id="headerIP" class="mono" style="font-size: 13px; color: var(--text-muted);">@ 0.0.0.0</span>
  </div>
</header>

<div class="container">
  <!-- Nav Tabs -->
  <div class="nav-tabs">
    <button class="tab-btn active" onclick="setTab('dash')">📊 Panel Principal</button>
    <button class="tab-btn" onclick="setTab('log')">⚡ Registro en Vivo</button>
    <button class="tab-btn" onclick="setTab('clients')">💻 Clientes</button>
    <button class="tab-btn" onclick="setTab('lists')">🚫 Listas y Filtros</button>
    <button class="tab-btn" onclick="setTab('settings')">⚙️ Configuración DNS</button>
    <button class="tab-btn" onclick="setTab('ota')">🔄 Actualizaciones OTA</button>
  </div>

  <!-- Pause bar -->
  <div id="pauseBar" class="pause-banner">
    <div style="display:flex;align-items:center;gap:12px">
      <span id="pauseIcon" style="font-size:24px">🛡️</span>
      <div>
        <b id="pauseTitle">Filtrado y Bloqueo Activo</b>
        <div id="pauseSubtitle" style="font-size:12px;color:var(--text-muted)">Las consultas DNS son filtradas en menos de 1 ms</div>
      </div>
    </div>
    <div style="display:flex;gap:10px;align-items:center">
      <select id="pauseSelect">
        <option value="30">30 segundos</option>
        <option value="300" selected>5 minutos</option>
        <option value="900">15 minutos</option>
        <option value="1800">30 minutos</option>
        <option value="0">Indefinido</option>
      </select>
      <button id="pauseBtn" class="btn-primary" onclick="togglePause()">Pausar</button>
    </div>
  </div>

  <!-- TAB: DASHBOARD -->
  <div id="pane-dash" class="tab-pane active">
    <div class="grid-stats">
      <div class="stat-card">
        <div class="stat-title">Bloqueados <span>🔴</span></div>
        <div id="stBlocked" class="stat-value c-blocked">0</div>
        <div id="stBlockedPct" class="stat-sub">0% del tráfico total</div>
      </div>
      <div class="stat-card">
        <div class="stat-title">Permitidos <span>🟢</span></div>
        <div id="stAllowed" class="stat-value c-allowed">0</div>
        <div id="stAllowedSub" class="stat-sub">Resueltos por upstream</div>
      </div>
      <div class="stat-card">
        <div class="stat-title">Caché RAM Ultra-Fast <span>⚡</span></div>
        <div id="stCache" class="stat-value c-cache">0</div>
        <div id="stCacheSub" class="stat-sub">Latencia &lt; 0.1 ms</div>
      </div>
      <div class="stat-card">
        <div class="stat-title">Dominios en Flash <span>📚</span></div>
        <div id="stDomains" class="stat-value c-primary">0</div>
        <div class="stat-sub">Índice en RAM acelerado</div>
      </div>
    </div>

    <div class="charts-grid">
      <!-- Donut Chart -->
      <div class="card">
        <div class="card-title">Distribución de Tráfico</div>
        <div class="donut-wrap">
          <svg class="donut-chart" viewBox="0 0 36 36">
            <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="#1e293b" stroke-width="3.8"/>
            <path id="donutBlocked" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="#ef4444" stroke-width="3.8" stroke-dasharray="0, 100"/>
            <path id="donutCache" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="#a855f7" stroke-width="3.8" stroke-dasharray="0, 100"/>
          </svg>
          <div class="donut-legend">
            <div class="legend-item"><div class="legend-dot" style="background:#ef4444"></div> Bloqueado (<span id="lgBlocked">0%</span>)</div>
            <div class="legend-item"><div class="legend-dot" style="background:#a855f7"></div> Caché (<span id="lgCache">0%</span>)</div>
            <div class="legend-item"><div class="legend-dot" style="background:#10b981"></div> Upstream (<span id="lgUpstream">0%</span>)</div>
          </div>
        </div>
      </div>

      <!-- System Health Card -->
      <div class="card">
        <div class="card-title">Estado del Dispositivo ESP32-C3</div>
        <div class="sys-grid">
          <div class="sys-item">
            <div class="sys-label">Clientes Activos</div>
            <div id="sysClients" class="sys-val">0</div>
          </div>
          <div class="sys-item">
            <div class="sys-label">Memoria RAM Libre</div>
            <div id="sysHeap" class="sys-val">0 KB</div>
          </div>
          <div class="sys-item">
            <div class="sys-label">Temperatura CPU</div>
            <div id="sysTemp" class="sys-val">0 °C</div>
          </div>
          <div class="sys-item">
            <div class="sys-label">Señal WiFi (RSSI)</div>
            <div id="sysRssi" class="sys-val">0 dBm</div>
          </div>
          <div class="sys-item">
            <div class="sys-label">Tiempo Activo</div>
            <div id="sysUptime" class="sys-val">0d 0h 0m</div>
          </div>
          <div class="sys-item">
            <div class="sys-label">Velocidad Búsqueda</div>
            <div class="sys-val" style="color:var(--success)">~1 ms (RAM Index)</div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- TAB: LIVE LOG -->
  <div id="pane-log" class="tab-pane">
    <div class="card">
      <div class="card-title">
        <span>Registro de Consultas en Tiempo Real (Últimas peticiones)</span>
        <div style="display:flex;gap:8px">
          <input type="text" id="logSearch" placeholder="Filtrar por dominio o IP..." onkeyup="renderLogTable()">
          <select id="logFilter" onchange="renderLogTable()">
            <option value="all">Todas</option>
            <option value="blocked">Solo Bloqueadas</option>
            <option value="allowed">Solo Permitidas</option>
            <option value="cache">Solo Caché</option>
          </select>
          <button onclick="fetchLog()">🔄 Actualizar</button>
        </div>
      </div>
      <div style="overflow-x:auto">
        <table id="tblLog">
          <thead>
            <tr>
              <th>Hora</th>
              <th>Cliente</th>
              <th>Tipo</th>
              <th>Dominio</th>
              <th>Resultado</th>
              <th style="text-align:right">Acciones Rápidas</th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- TAB: CLIENTS -->
  <div id="pane-clients" class="tab-pane">
    <div class="card">
      <div class="card-title">
        <span>Dispositivos Conectados en la Red</span>
        <span style="font-size:12px;color:var(--text-muted)">Haz clic en el alias para poner nombre a tus dispositivos</span>
      </div>
      <div style="overflow-x:auto">
        <table id="tblClients">
          <thead>
            <tr>
              <th>Dispositivo / Alias</th>
              <th>IP</th>
              <th>Dirección MAC</th>
              <th>Bloqueadas</th>
              <th>Permitidas</th>
              <th>Total</th>
              <th style="text-align:right">Acción</th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- TAB: LISTS (BLOCKLIST & WHITELIST) -->
  <div id="pane-lists" class="tab-pane">
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
      <!-- Whitelist -->
      <div class="card">
        <div class="card-title" style="color:#38bdf8">
          <span>🛡️ Lista Blanca (Whitelist)</span>
        </div>
        <p style="font-size:12px;color:var(--text-muted);margin-bottom:12px">Los dominios aquí NUNCA serán bloqueados, incluso si están en listas públicas.</p>
        <div class="action-bar">
          <input type="text" id="inAllow" placeholder="ejemplo.com" style="flex:1">
          <button class="btn-primary" onclick="addAllow()">+ Permitir</button>
        </div>
        <table id="tblAllow">
          <thead><tr><th>Dominio Excluido</th><th style="text-align:right">Quitar</th></tr></thead>
          <tbody></tbody>
        </table>
      </div>

      <!-- Blacklist -->
      <div class="card">
        <div class="card-title" style="color:#ef4444">
          <span>🚫 Lista Negra Personalizada</span>
        </div>
        <p style="font-size:12px;color:var(--text-muted);margin-bottom:12px">Dominios que deseas bloquear de inmediato en toda tu red.</p>
        <div class="action-bar">
          <input type="text" id="inBlock" placeholder="anuncios.ejemplo.com" style="flex:1">
          <button class="btn-danger" onclick="addCustom()">+ Bloquear</button>
        </div>
        <table id="tblBlock">
          <thead><tr><th>Dominio Bloqueado</th><th style="text-align:right">Quitar</th></tr></thead>
          <tbody></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- TAB: SETTINGS & DNS -->
  <div id="pane-settings" class="tab-pane">
    <div class="card">
      <div class="card-title">Configuración de Servidores DNS Upstream</div>
      <p style="font-size:13px;color:var(--text-muted);margin-bottom:16px">Configura los resolvers hacia donde se reenviarán las consultas permitidas con tolerancia a fallos.</p>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px">
        <div>
          <label style="font-size:12px;color:var(--text-muted);display:block;margin-bottom:4px">DNS Primario</label>
          <input type="text" id="dnsPrimary" placeholder="9.9.9.9" style="width:100%">
        </div>
        <div>
          <label style="font-size:12px;color:var(--text-muted);display:block;margin-bottom:4px">DNS Secundario (Fallback)</label>
          <input type="text" id="dnsSecondary" placeholder="1.1.1.1" style="width:100%">
        </div>
      </div>
      <button class="btn-primary" onclick="saveUpstreamDNS()">Guardar Servidores DNS</button>
    </div>

    <div class="card">
      <div class="card-title">Auto-Actualización Remota de Listas</div>
      <p style="font-size:13px;color:var(--text-muted);margin-bottom:16px">El dispositivo descargará periódicamente una lista binaria precompilada sin intervención.</p>
      <div style="display:flex;gap:10px;margin-bottom:12px;flex-wrap:wrap">
        <input type="text" id="uurl" placeholder="https://servidor.com/blocklist.bin" style="flex:1;min-width:250px">
        <span>cada</span>
        <input type="number" id="uiv" value="24" min="1" max="168" style="width:70px">
        <span>horas</span>
        <button class="btn-primary" onclick="saveUpd()">Guardar</button>
        <button onclick="fetchNow()">Descargar Ahora</button>
      </div>
      <div style="font-size:12px;color:var(--text-muted)">Estado último intento: <span id="ustat" style="color:var(--text)">—</span></div>
    </div>
  </div>

  <!-- TAB: OTA & UPDATES -->
  <div id="pane-ota" class="tab-pane">
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
      <!-- Firmware OTA -->
      <div class="card">
        <div class="card-title">Actualizar Firmware (WiFi OTA)</div>
        <p style="font-size:12px;color:var(--text-muted);margin-bottom:12px">Sube el archivo <code>firmware.bin</code> compilado. El ESP32 lo verificará e iniciará el nuevo sistema.</p>
        <form id="fwForm">
          <input type="file" id="fwFile" accept=".bin" style="width:100%;margin-bottom:10px">
          <button type="submit" class="btn-primary">⚡ Flashear Firmware</button>
          <span id="fwMsg" style="margin-left:10px;font-size:12px;color:var(--text-muted)"></span>
        </form>
      </div>

      <!-- Blocklist Upload -->
      <div class="card">
        <div class="card-title">Subir Archivo de Lista (blocklist.bin)</div>
        <p style="font-size:12px;color:var(--text-muted);margin-bottom:12px">Carga una nueva lista binaria generada con <code>tools/build_blocklist.py</code> sin usar cable USB.</p>
        <form id="blForm">
          <input type="file" id="blFile" accept=".bin" style="width:100%;margin-bottom:10px">
          <button type="submit" class="btn-primary">Subir Lista</button>
          <span id="blMsg" style="margin-left:10px;font-size:12px;color:var(--text-muted)"></span>
        </form>
      </div>
    </div>

    <!-- Management actions -->
    <div class="card" style="border-color:rgba(239,68,68,0.3)">
      <div class="card-title" style="color:#ef4444">Zona de Mantenimiento de Red</div>
      <div style="display:flex;gap:12px;flex-wrap:wrap">
        <button class="btn-danger" onclick="if(confirm('¿Reiniciar el dispositivo?')) fetch('/reboot')">🔄 Reiniciar Dispositivo</button>
        <button class="btn-danger" onclick="if(confirm('¿Borrar credenciales WiFi y volver al portal cautivo?')) fetch('/forgetwifi')">📶 Olvidar WiFi y Abrir Portal</button>
      </div>
    </div>
  </div>

</div>

<script>
let stats = {};
let queryLogs = [];

function setTab(name) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  event.target.classList.add('active');
  document.getElementById('pane-' + name).classList.add('active');
  if (name === 'log') fetchLog();
}

function fmt(n) { return (n || 0).toLocaleString(); }

async function loadStats() {
  try {
    let r = await fetch('/stats.json');
    stats = await r.json();
    renderStats();
  } catch (e) {
    console.error(e);
  }
}

function renderStats() {
  headerIP.textContent = '@ ' + stats.ip;
  let on = stats.blocking !== false;
  statDot.className = 'dot' + (on ? '' : ' paused');
  statText.textContent = on ? 'Activo' : 'En Pausa';
  pauseIcon.textContent = on ? '🛡️' : '⏸️';
  pauseBar.className = 'pause-banner' + (on ? '' : ' is-paused');
  pauseTitle.textContent = on ? 'Filtrado y Bloqueo Activo' : (stats.resumeIn > 0 ? 'Pausado temporalmente — se reanuda en ' + stats.resumeIn + 's' : 'Pausado indefinidamente');
  pauseBtn.textContent = on ? 'Pausar' : 'Reanudar';
  pauseSelect.style.display = on ? '' : 'none';

  stBlocked.textContent = fmt(stats.blocked);
  stAllowed.textContent = fmt(stats.allowed);
  stCache.textContent = fmt(stats.cacheHits || 0);
  stDomains.textContent = fmt(stats.domains);

  let total = (stats.blocked || 0) + (stats.allowed || 0) + (stats.cacheHits || 0);
  let bPct = total ? ((stats.blocked / total) * 100).toFixed(1) : 0;
  let cPct = total ? (((stats.cacheHits || 0) / total) * 100).toFixed(1) : 0;
  let aPct = (100 - bPct - cPct).toFixed(1);

  stBlockedPct.textContent = bPct + '% del tráfico bloqueado';
  lgBlocked.textContent = bPct + '%';
  lgCache.textContent = cPct + '%';
  lgUpstream.textContent = aPct + '%';

  // SVG donut stroke dasharray
  let bLen = (bPct * 100) / 100;
  let cLen = (cPct * 100) / 100;
  donutBlocked.setAttribute('stroke-dasharray', `${bLen} ${100 - bLen}`);
  donutCache.setAttribute('stroke-dasharray', `${cLen} ${100 - cLen}`);
  donutCache.setAttribute('stroke-dashoffset', `-${bLen}`);

  sysClients.textContent = (stats.clients || []).length;
  sysHeap.textContent = Math.round(stats.heap / 1024) + ' KB';
  sysTemp.textContent = (stats.temp || 0) + ' °C';
  sysRssi.textContent = (stats.rssi || 0) + ' dBm';
  sysUptime.textContent = stats.uptime || '0m';

  // Render clients table
  let ctBody = document.querySelector('#tblClients tbody');
  ctBody.innerHTML = (stats.clients || []).sort((a,b) => (b.blocked + b.allowed) - (a.blocked + a.allowed)).map(c => `
    <tr>
      <td>
        <span class="editable-alias" onclick="renameClient('${c.ip}', '${c.label || ''}')">
          <b>${c.label || 'Dispositivo'}</b> ✎
        </span>
        ${c.banned ? '<span class="badge badge-blocked" style="margin-left:6px">BANEADO</span>' : ''}
      </td>
      <td class="mono">${c.ip}</td>
      <td class="mono" style="color:var(--text-muted)">${c.mac}</td>
      <td class="c-blocked" style="font-weight:600">${fmt(c.blocked)}</td>
      <td class="c-allowed">${fmt(c.allowed)}</td>
      <td>${fmt(c.blocked + c.allowed)}</td>
      <td style="text-align:right">
        <button class="btn-sm ${c.banned ? '' : 'btn-danger'}" onclick="fetch('/ban?ip=${c.ip}').then(loadStats)">
          ${c.banned ? 'Desbanear' : 'Bloquear Todo'}
        </button>
      </td>
    </tr>
  `).join('') || '<tr><td colspan="7" style="color:var(--text-muted);text-align:center">Sin clientes registrados aún</td></tr>';

  // Render custom blocklist
  let tblB = document.querySelector('#tblBlock tbody');
  tblB.innerHTML = (stats.custom || []).map(d => `
    <tr>
      <td class="mono">${d}</td>
      <td style="text-align:right">
        <button class="btn-sm btn-danger" onclick="fetch('/unblock?d='+encodeURIComponent('${d}')).then(loadStats)">Quitar</button>
      </td>
    </tr>
  `).join('') || '<tr><td colspan="2" style="color:var(--text-muted)">Ninguno</td></tr>';

  // Render whitelist
  let tblA = document.querySelector('#tblAllow tbody');
  tblA.innerHTML = (stats.whitelist || []).map(d => `
    <tr>
      <td class="mono">${d}</td>
      <td style="text-align:right">
        <button class="btn-sm btn-danger" onclick="fetch('/unallow?d='+encodeURIComponent('${d}')).then(loadStats)">Quitar</button>
      </td>
    </tr>
  `).join('') || '<tr><td colspan="2" style="color:var(--text-muted)">Ninguno</td></tr>';

  if (document.activeElement != uurl) uurl.value = stats.upurl || '';
  if (document.activeElement != uiv) uiv.value = stats.upiv || 24;
  if (document.activeElement != dnsPrimary && stats.dnsPri) dnsPrimary.value = stats.dnsPri;
  if (document.activeElement != dnsSecondary && stats.dnsSec) dnsSecondary.value = stats.dnsSec;
  ustat.textContent = stats.upstat || '—';
}

async function renameClient(ip, currentName) {
  let name = prompt(`Nombre / Alias para ${ip}:`, currentName);
  if (name !== null) {
    await fetch(`/setlabel?ip=${ip}&name=${encodeURIComponent(name.trim())}`);
    loadStats();
  }
}

async function fetchLog() {
  try {
    let r = await fetch('/log.json');
    queryLogs = await r.json();
    renderLogTable();
  } catch (e) {
    console.error(e);
  }
}

function renderLogTable() {
  let filter = logFilter.value;
  let q = (logSearch.value || '').toLowerCase().trim();
  let filtered = queryLogs.filter(item => {
    if (filter === 'blocked' && (item.st !== 0 && item.st !== 1)) return false;
    if (filter === 'allowed' && item.st !== 2) return false;
    if (filter === 'cache' && item.st !== 3) return false;
    if (q && !item.d.toLowerCase().includes(q) && !item.ip.includes(q)) return false;
    return true;
  });

  let tb = document.querySelector('#tblLog tbody');
  tb.innerHTML = filtered.map(item => {
    let badge = '';
    if (item.st === 0 || item.st === 1) badge = '<span class="badge badge-blocked">Bloqueado</span>';
    else if (item.st === 3) badge = '<span class="badge badge-cache">Caché RAM</span>';
    else if (item.st === 4) badge = '<span class="badge badge-whitelist">Lista Blanca</span>';
    else badge = '<span class="badge badge-allowed">Permitido</span>';

    return `
      <tr>
        <td style="color:var(--text-muted)">${item.t}s ago</td>
        <td class="mono">${item.ip}</td>
        <td><span class="badge" style="background:#1e293b">${item.q === 28 ? 'AAAA' : 'A'}</span></td>
        <td class="mono" style="font-weight:500">${item.d}</td>
        <td>${badge}</td>
        <td style="text-align:right">
          <button class="btn-sm" onclick="quickAllow('${item.d}')">+ Whitelist</button>
          <button class="btn-sm btn-danger" onclick="quickBlock('${item.d}')">+ Bloquear</button>
        </td>
      </tr>
    `;
  }).join('') || '<tr><td colspan="6" style="text-align:center;color:var(--text-muted)">No hay registros coincidentes</td></tr>';
}

function quickAllow(d) { fetch('/addallow?d=' + encodeURIComponent(d)).then(() => { loadStats(); fetchLog(); }); }
function quickBlock(d) { fetch('/addblock?d=' + encodeURIComponent(d)).then(() => { loadStats(); fetchLog(); }); }

function togglePause() {
  if (statDot.classList.contains('paused')) {
    fetch('/resume').then(loadStats);
  } else {
    fetch('/pause?s=' + pauseSelect.value).then(loadStats);
  }
}

function addAllow() {
  let d = inAllow.value.trim();
  if (d) fetch('/addallow?d=' + encodeURIComponent(d)).then(() => { inAllow.value = ''; loadStats(); });
}
function addCustom() {
  let d = inBlock.value.trim();
  if (d) fetch('/addblock?d=' + encodeURIComponent(d)).then(() => { inBlock.value = ''; loadStats(); });
}

function saveUpstreamDNS() {
  let p = dnsPrimary.value.trim();
  let s = dnsSecondary.value.trim();
  fetch(`/setupstream?p=${encodeURIComponent(p)}&s=${encodeURIComponent(s)}`).then(() => alert('DNS Guardado correctamente'));
}

function saveUpd() {
  fetch('/setupdate?u=' + encodeURIComponent(uurl.value.trim()) + '&h=' + (parseInt(uiv.value) || 24)).then(loadStats);
}
function fetchNow() {
  ustat.textContent = 'Descargando lista...';
  fetch('/fetchnow').then(r => r.text()).then(t => { ustat.textContent = t; loadStats(); });
}

// OTA Form handlers
fwForm.onsubmit = async e => {
  e.preventDefault();
  let f = fwFile.files[0];
  if (!f) return;
  fwMsg.textContent = 'Subiendo ' + (f.size / 1048576).toFixed(2) + ' MB...';
  let fd = new FormData();
  fd.append('f', f);
  try {
    let r = await fetch('/update', { method: 'POST', body: fd });
    fwMsg.textContent = r.ok ? '✓ Reiniciando...' : '✗ ' + await r.text();
  } catch (_) { fwMsg.textContent = '✓ Reiniciando...'; }
};

blForm.onsubmit = async e => {
  e.preventDefault();
  let f = blFile.files[0];
  if (!f) return;
  blMsg.textContent = 'Subiendo lista ' + (f.size / 1048576).toFixed(2) + ' MB...';
  let fd = new FormData();
  fd.append('f', f);
  try {
    let r = await fetch('/upload', { method: 'POST', body: fd });
    blMsg.textContent = r.ok ? '✓ Lista actualizada' : '✗ ' + await r.text();
  } catch (_) { blMsg.textContent = '✗ Error en subida'; }
  blFile.value = '';
  setTimeout(loadStats, 1000);
};

loadStats();
setInterval(loadStats, 3000);
</script>
</body>
</html>)HTML";
