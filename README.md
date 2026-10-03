# AdBlockHouse 🛡️

**AdBlockHouse** es un bloqueador de publicidad y rastreo a nivel de red (estilo Pi-hole) diseñado para correr en un microcontrolador **ESP32-C3** de solo $2 conectado directamente al puerto USB de tu router, **sin necesidad de memoria PSRAM**.

> 📌 **Créditos y Origen**:  
> Este proyecto está basado originalmente en el ingenioso trabajo de [M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock).  
> Ha sido adaptado, ampliado y optimizado por **Eduardo Restrepo** para cubrir necesidades domésticas avanzadas, ampliando su capacidad a **500.000 dominios**, acelerando la latencia con caché en RAM, soporte de lista blanca, doble DNS con failover y panel de control moderno.

---

## ✨ Mejoras y Novedades en AdBlockHouse

1. **Capacidad Extrema de ~500.000 Dominios (StevenBlack + HaGeZi Multi)**:
   - Tabla de particiones reajustada a **2.625 MB para LittleFS**, permitiendo almacenar medio millón de dominios bloqueados en flash.
2. **Acelerador de Búsqueda por Puntos de Control en RAM**:
   - Tabla de 1.024 puntos de control en memoria que reduce el rango de búsqueda binaria en flash a una ventana de solo ~140 dominios.
   - Reduce las lecturas en flash de **18 a solo 5–7 lecturas por consulta** (latencia ~1 ms).
3. **Caché DNS LRU en Memoria RAM (< 0.1 ms)**:
   - Guarda en RAM hasta 96 respuestas DNS recientes respetando el TTL devuelto por los servidores upstream. Las consultas repetidas se resuelven de forma instantánea.
4. **Lista Blanca Completa (Whitelist / Allowlist)**:
   - Permite excluir dominios con 1 clic desde el registro de consultas o manualmente para evitar falsos positivos (bancos, streaming, trabajo).
5. **Doble Upstream DNS con Failover Automático**:
   - Soporte para DNS Primario (Quad9 `9.9.9.9`) y Secundario (Cloudflare `1.1.1.1`), configurables desde la interfaz web con tolerancia a fallos en 350 ms.
6. **Soporte Completo para IPv6 (Registros AAAA)**:
   - Devuelve la dirección nula `::` o respuesta limpia sintética para evitar fugas de publicidad en dispositivos con IPv6 activo.
7. **Nombres y Alias de Dispositivos**:
   - Posibilidad de etiquetar cada cliente conectado con un nombre amigable ("TV Salón", "iPhone", etc.) guardado en memoria permanente.
8. **Live Query Log (Registro en Tiempo Real)**:
   - Visualización de las últimas 64 consultas DNS con su estado (Bloqueada, Permitida, Caché, Whitelist) y botones para permitir/bloquear al instante.
9. **Dashboard Moderno con Glassmorphism**:
   - Modo oscuro pulido con gráfico Donut interactivo de distribución de tráfico (% bloqueado vs caché vs upstream).
10. **Actualizaciones Diarias Automáticas (OTA) con GitHub Actions**:
    - Flujo automatizado en GitHub Actions que compila cada noche las listas más recientes y permite que el ESP32 se actualice solo por WiFi.

---

## 🚀 Puesta en Marcha Rápida

### Opción 1: Grabar desde el Navegador (Chrome o Edge)
1. Conecta el ESP32-C3 a tu PC por cable USB.
2. Abre una terminal en el proyecto y lanza el instalador local:
   ```powershell
   python -m http.server 8000 --directory docs
   ```
3. Entra en tu navegador a `http://localhost:8000`.
4. Haz clic en **⚡ Connect & Install 500k PRO**, selecciona tu puerto COM y se grabará en ~45 segundos.

### Opción 2: Compilación con PlatformIO
```powershell
# 1. Compilar y subir firmware
python -m platformio run -t upload

# 2. Subir sistema de archivos con los 500.000 dominios
python -m platformio run -t uploadfs
```

---

## 🔌 Instalación en el Router

1. Desconecta el ESP32 del PC y **conéctalo a un puerto USB de tu router** (alimentación).
2. Conéctate desde tu móvil a la red WiFi abierta: **`C3-AdBlock-XXXX`**.
3. Se abrirá el portal cautivo: selecciona tu red WiFi e introduce la contraseña.
4. En la configuración DHCP de tu router, asigna como **DNS Primario** la IP del ESP32 (por ejemplo `192.168.1.50`).
5. Abre en tu navegador: **`http://c3adblock.local`** para entrar al panel de control.

---

## 🔄 Actualización Diaria Automática por WiFi (OTA)

El repositorio incluye el flujo [`.github/workflows/update_blocklist.yml`](.github/workflows/update_blocklist.yml):
* Se ejecuta automáticamente cada día a las 03:00 UTC.
* Compila la versión más reciente de la lista y la publica en una Release.
* En el panel web del dispositivo (`http://c3adblock.local` → **Configuración DNS**), configura la URL de descarga fija:
  ```text
  https://github.com/EduRestrepo/AdBlockHouse/releases/latest/download/blocklist.bin
  ```
El ESP32 descargará la nueva lista cada 24 horas sin interrumpir la conexión a internet.

---

## 📄 Licencia

MIT License — consulta el archivo [LICENSE](LICENSE) para más detalles.
Basado en el trabajo original de [M-Abozaid](https://github.com/M-Abozaid/esp32-c3-adblock).
