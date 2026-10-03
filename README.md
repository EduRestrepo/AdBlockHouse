# AdBlockHouse 🛡️

[English](#english) | [Español](#español)

---

<a name="english"></a>
## English

A **Pi-hole-class DNS ad-blocker** that runs on a **$2 ESP32-C3** plugged straight into your router's USB port — *no PSRAM required*.

> 📌 **Credits & Origin**:  
> This project is based on the original work by [M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock).  
> It has been enhanced, extended, and optimized by **Eduardo Restrepo** to meet high-performance home network needs, featuring an expanded **500,000 domain** capacity, RAM-indexed flash searches, in-memory DNS caching, persistent whitelist support, dual-upstream DNS with failover, and automated daily Over-The-Air (OTA) updates via GitHub Actions.

---

### ✨ Features & Improvements in AdBlockHouse

1. **Extreme Capacity (~500,000 Domains)**:
   - Partition table customized with **2.625 MB for LittleFS**, packing half a million domains from **StevenBlack (Base)** and **HaGeZi Multi Normal**.
2. **RAM Checkpoint Search Index**:
   - In-memory index of 1,024 checkpoints that narrows the flash binary search down to a window of ~140 items.
   - Slashes flash reads from **~18 down to 5–7 per query** (~1 ms lookup latency).
3. **In-Memory DNS LRU Cache (< 0.1 ms)**:
   - Stores up to 96 recent upstream responses in SRAM respecting real TTLs. Repeat queries from apps and devices resolve instantly with zero router/upstream load.
4. **Persistent Whitelist (Allowlist)**:
   - One-click unblocking directly from the query log or manual domain entries (`allowlist.txt`) to prevent false positives (banking, streaming, work VPNs).
5. **Dual Upstream DNS with Instant Failover**:
   - Primary (Quad9 `9.9.9.9`) and Secondary (Cloudflare `1.1.1.1`) upstream resolvers configured via the web UI with a fast 350 ms timeout before failover.
6. **Native IPv6 Sinkholing (AAAA Records)**:
   - RFC-compliant synthesis returning `::` (null IPv6) to prevent ad leakage on modern dual-stack mobile devices and Windows 11.
7. **Client Aliases & Device Naming**:
   - Assign friendly names to connected IPs ("Living Room TV", "iPhone", "Work Laptop") persisted in flash.
8. **Live Real-Time Query Log**:
   - Rolling buffer of the last 64 DNS queries with colored status badges (Blocked, Allowed, Cache, Whitelist) and quick-action buttons.
9. **Modern Glassmorphism Web Dashboard**:
   - Dark mode interface with an interactive SVG donut chart (% blocked vs cache vs upstream) and live pause controls.
10. **Automated Daily Over-The-Air (OTA) Updates**:
    - Built-in GitHub Actions workflow compiles the freshest blocklists every night at 03:00 UTC. The ESP32 silently pulls the update over WiFi without dropping home internet.

---

### 🚀 Quick Start & Flashing

#### Option 1: 1-Click Browser Flash (Chrome / Edge)
No toolchains, no Python needed:
1. Connect your ESP32-C3 to your computer via USB.
2. Open the web flasher: **[https://edurestrepo.github.io/AdBlockHouse/](https://edurestrepo.github.io/AdBlockHouse/)**
3. Click **⚡ Connect & Install 500k PRO**, pick your COM port, and wait ~45 seconds.

#### Option 2: Build & Flash with PlatformIO
```powershell
# 1. Flash firmware
python -m platformio run -t upload

# 2. Flash filesystem with 500k domains
python -m platformio run -t uploadfs
```

---

### 🔌 Router Setup

1. Unplug the ESP32 from your PC and **plug it into any spare USB port on your router** for power.
2. From your phone or laptop, connect to the open setup network: **`AdBlock-House`**.
3. The captive portal will pop up: select your home WiFi network and enter its password.
4. In your router's DHCP settings, assign the ESP32 a static IP (e.g. `192.168.1.50`) and set it as your **Primary DNS**.
5. Open **`http://c3adblock.local`** in any browser to access the live dashboard.

---

### 🔄 Daily Automated Over-The-Air (OTA) Updates

The repository includes [`.github/workflows/update_blocklist.yml`](.github/workflows/update_blocklist.yml):
* Automatically executes daily at 03:00 UTC.
* Fetches the latest feeds and publishes a new `blocklist.bin` to a GitHub Release.
* In the ESP32 dashboard (**Settings → Remote Auto-Update**), enter:
  ```text
  https://github.com/EduRestrepo/AdBlockHouse/releases/latest/download/blocklist.bin
  ```
The device updates itself every 24 hours over WiFi with zero downtime.

---

<br>

---

<a name="español"></a>
## Español

Un **bloqueador de anuncios por DNS estilo Pi-hole** que funciona en un microcontrolador **ESP32-C3 de $2** conectado directamente al puerto USB de tu router — *sin necesidad de memoria PSRAM*.

> 📌 **Créditos y Origen**:  
> Este proyecto está basado originalmente en el ingenioso trabajo de [M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock).  
> Ha sido adaptado, ampliado y optimizado por **Eduardo Restrepo** para cubrir necesidades domésticas avanzadas, ampliando su capacidad a **500.000 dominios**, acelerando la latencia con índice en RAM, caché DNS, lista blanca, doble DNS con failover y actualizaciones diarias OTA automáticas con GitHub Actions.

---

### ✨ Mejoras y Novedades en AdBlockHouse

1. **Capacidad Extrema (~500.000 Dominios)**:
   - Tabla de particiones reajustada a **2.625 MB para LittleFS**, almacenando medio millón de dominios de **StevenBlack (Base)** y **HaGeZi Multi Normal**.
2. **Acelerador de Búsqueda por Puntos de Control en RAM**:
   - Tabla de 1.024 puntos de control en memoria que reduce la búsqueda binaria en flash a una ventana de solo ~140 dominios.
   - Reduce las lecturas en flash de **18 a solo 5–7 lecturas por consulta** (latencia ~1 ms).
3. **Caché DNS LRU en Memoria RAM (< 0.1 ms)**:
   - Guarda en memoria hasta 96 respuestas DNS recientes respetando el TTL real. Las consultas repetidas se resuelven de forma instantánea sin salir a internet.
4. **Lista Blanca Persistente (Whitelist / Allowlist)**:
   - Permite excluir dominios con 1 clic desde el registro de consultas o manualmente (`allowlist.txt`) para evitar falsos positivos (bancos, streaming, teletrabajo).
5. **Doble Upstream DNS con Failover Automático**:
   - Soporte para DNS Primario (Quad9 `9.9.9.9`) y Secundario (Cloudflare `1.1.1.1`), configurables desde la web con tolerancia a fallos en 350 ms.
6. **Soporte Completo para IPv6 (Registros AAAA)**:
   - Devuelve la dirección nula `::` o respuesta limpia sintética para evitar fugas de publicidad en redes y móviles modernos con IPv6.
7. **Nombres y Alias de Dispositivos**:
   - Posibilidad de etiquetar cada cliente conectado con un nombre amigable ("TV Salón", "iPhone", etc.) guardado en memoria permanente.
8. **Live Query Log (Registro en Tiempo Real)**:
   - Visualización de las últimas 64 consultas DNS con su estado (Bloqueada, Permitida, Caché, Whitelist) y botones para permitir/bloquear al instante.
9. **Dashboard Moderno con Glassmorphism**:
   - Modo oscuro con gráfico Donut interactivo de distribución de tráfico (% bloqueado vs caché vs upstream).
10. **Actualizaciones Diarias Automáticas (OTA) con GitHub Actions**:
    - Flujo automatizado en GitHub Actions que compila cada noche las listas más recientes y permite que el ESP32 se actualice solo por WiFi.

---

### 🚀 Puesta en Marcha Rápida

#### Opción 1: Grabar desde el Navegador (Chrome o Edge)
Sin instalar nada en el ordenador:
1. Conecta el ESP32-C3 a tu PC por cable USB.
2. Abre el instalador web: **[https://edurestrepo.github.io/AdBlockHouse/](https://edurestrepo.github.io/AdBlockHouse/)**
3. Haz clic en **⚡ Connect & Install 500k PRO**, selecciona tu puerto COM y se grabará en ~45 segundos.

#### Opción 2: Compilación con PlatformIO
```powershell
# 1. Compilar y subir firmware
python -m platformio run -t upload

# 2. Subir sistema de archivos con los 500.000 dominios
python -m platformio run -t uploadfs
```

---

### 🔌 Instalación en el Router

1. Desconecta el ESP32 del PC y **conéctalo a un puerto USB de tu router** (alimentación).
2. Conéctate desde tu móvil a la red WiFi abierta: **`AdBlock-House`**.
3. Se abrirá el portal cautivo: selecciona tu red WiFi e introduce la contraseña.
4. En la configuración DHCP de tu router, asigna como **DNS Primario** la IP del ESP32 (por ejemplo `192.168.1.50`).
5. Abre en tu navegador: **`http://c3adblock.local`** para entrar al panel de control.

---

### 🔄 Actualización Diaria Automática por WiFi (OTA)

El repositorio incluye el flujo [`.github/workflows/update_blocklist.yml`](.github/workflows/update_blocklist.yml):
* Se ejecuta automáticamente cada día a las 03:00 UTC.
* Compila la versión más reciente de la lista y la publica en una Release.
* En el panel web del dispositivo (`http://c3adblock.local` → **Configuración DNS**), configura la URL de descarga fija:
  ```text
  https://github.com/EduRestrepo/AdBlockHouse/releases/latest/download/blocklist.bin
  ```
El ESP32 descargará la nueva lista cada 24 horas sin interrumpir la conexión a internet.

---

## 📄 License / Licencia

MIT License — see [LICENSE](LICENSE).  
Based on original work by [M-Abozaid](https://github.com/M-Abozaid/esp32-c3-adblock).
