# VirusTotal Domain Scanner

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![PHP Version](https://img.shields.io/badge/PHP-8.0+-purple.svg)

> **[🇬🇧 English](#english)** | **[🇩🇪 Deutsch](#deutsch)**

---

## English

Automated VirusTotal domain scanner with web interface, real-time logging, and email notifications. Scans multiple domains sequentially and provides detailed security reports.

### Features

- 🔍 **Multi-Domain Scanning** - Scan multiple domains in one run
- 🌐 **Web Interface** - Real-time scanning dashboard with live updates
- 📊 **Live Logging** - Watch scan progress in real-time
- 📧 **Email Alerts** - Automatic HTML email reports via SMTP
- ⏰ **Cron Compatible** - Perfect for automated scheduled scans
- 🔒 **Optional Auth** - HTTP Basic Auth protection
- 💾 **JSON Export** - Persistent scan results storage
- 🚨 **Threat Detection** - Malicious/suspicious domain detection
- 🔄 **Auto-Rescan** - Triggers fresh VirusTotal analysis

### Requirements

- PHP 8.0 or higher
- PHPMailer library (included in `/PHPMailer/` directory)
- VirusTotal API Key (free tier available)
- SMTP account for email notifications
- cURL extension enabled
- Writable data directory for logs

### Installation

1. **Clone repository** to your webspace
   ```bash
   git clone https://github.com/AlexanderWagnerDev/virustotal-domains-scan.git
   cd virustotal-domains-scan
   ```

2. **Install PHPMailer** (if not included)
   ```bash
   # Download from https://github.com/PHPMailer/PHPMailer
   # Extract to ./PHPMailer/ directory
   ```

3. **Create data directory**
   ```bash
   mkdir -p data
   chmod 755 data
   ```

4. **Copy configuration file**
   ```bash
   cp .env.example .env
   ```

5. **Edit `.env` file** with your credentials:
   ```env
   # Get your API key from https://www.virustotal.com/gui/my-apikey
   VT_API_KEY=your_virustotal_api_key_here

   # Comma-separated list of domains to scan
   DOMAINS=example.com,yourdomain.net,anothersite.org

   # Data directory (must be writable)
   DATA_DIR=/absolute/path/to/data

   # SMTP Settings
   SMTP_HOST=smtp.gmail.com
   SMTP_PORT=465
   SMTP_USER=your-email@gmail.com
   SMTP_FROM="VT Scanner <your-email@gmail.com>"
   SMTP_PASS=your-app-password
   TO_EMAIL=alerts@yourdomain.com

   # Optional: HTTP Basic Auth (recommended)
   CRON_USER=admin
   CRON_PASS=strong-password-here
   ```

6. **Protect `.env` file** (see `.htaccess.example`)

7. **Access the scanner**
   ```
   https://yourdomain.com/path/to/domains-scan.php
   ```

### Configuration

| Variable | Description | Example |
|----------|-------------|----------|
| `VT_API_KEY` | VirusTotal API key | `abc123...` |
| `DOMAINS` | Comma-separated domain list | `example.com,test.org` |
| `DATA_DIR` | Directory for logs and JSON results | `/var/www/data` |
| `SMTP_HOST` | SMTP server hostname | `smtp.gmail.com` |
| `SMTP_PORT` | SMTP port (usually 465 or 587) | `465` |
| `SMTP_USER` | SMTP username | `user@gmail.com` |
| `SMTP_FROM` | Email sender address | `scanner@domain.com` |
| `SMTP_PASS` | SMTP password/app password | `yourpassword` |
| `TO_EMAIL` | Report recipient email | `admin@domain.com` |
| `CRON_USER` | Optional HTTP Auth username | `admin` |
| `CRON_PASS` | Optional HTTP Auth password | `securepass` |

### Usage

#### Manual Execution via Web Interface

1. Open `domains-scan.php` in your browser
2. Click **🔥 START SCAN**
3. Watch real-time progress
4. Receive email report when complete
5. View **📋 Full Log Viewer** for detailed history

#### Automated Execution (Webcron/Cronjob)

**For All-Inkl Webcron:**

1. Log into **All-Inkl KAS** (Customer Admin Panel)
2. Navigate to **Tools → Cronjobs**
3. Click **"Neuer Cronjob"** (New Cronjob)
4. Configure:
   - **URL:** `https://yourdomain.com/path/to/domains-scan.php?start=1`
   - **HTTP Auth Username:** Your `CRON_USER` from `.env`
   - **HTTP Auth Password:** Your `CRON_PASS` from `.env`
   - **Schedule:** Daily/Weekly (recommended: daily at 3:00 AM)
   - **E-Mail notification:** Optional

**For standard cron:**
```bash
# Daily scan at 3:00 AM
0 3 * * * curl -u "admin:password" "https://yourdomain.com/domains-scan.php?start=1" > /dev/null 2>&1
```

### API Endpoints

| Endpoint | Description | Output |
|----------|-------------|--------|
| `domains-scan.php` | Main dashboard | HTML UI |
| `?start=1` | Trigger full scan | Text status |
| `?status=1` | Log viewer (auto-refresh) | HTML log view |

### File Structure

```
virustotal-domains-scan/
├── domains-scan.php      # Main scanner script
├── .env                  # Configuration (DO NOT COMMIT!)
├── .env.example          # Example configuration
├── .htaccess.example     # Security rules example
├── LICENSE               # MIT License
├── PHPMailer/            # Email library
│   ├── PHPMailer.php
│   ├── SMTP.php
│   └── Exception.php
└── data/                 # Logs and results (auto-created)
    ├── scan.log          # Scan execution log
    └── last_result.json  # Latest scan results
```

### Getting VirusTotal API Key

1. Register at [VirusTotal](https://www.virustotal.com/)
2. Navigate to your [API Key page](https://www.virustotal.com/gui/my-apikey)
3. Copy your API key
4. **Free tier limits:** 4 requests/minute, 500 requests/day

### Email Report Format

The scanner sends HTML emails containing:

- **Summary:** Total domains, positives, malicious detections, scan duration
- **Detailed table** with:
  - Domain name (clickable link)
  - VirusTotal report link
  - Reputation score
  - Malicious detections
  - Suspicious detections
  - Total positives
  - Last scan timestamp
- **Visual alerts:** Rows with positives highlighted in red

### Security Recommendations

⚠️ **Important Security Notes:**

1. **Always use HTTPS** - Protect credentials in transit
2. **Protect `.env` file** - Use `.htaccess` to deny web access
3. **Enable HTTP Auth** - Set `CRON_USER` and `CRON_PASS` in `.env`
4. **Restrict data directory** - Prevent direct web access
5. **Use app passwords** - For Gmail, generate app-specific passwords
6. **Rate limiting** - Free API: 4 req/min, 500 req/day
7. **Monitor logs** - Check `data/scan.log` regularly

### Troubleshooting

#### Scan fails immediately
- Check `data/scan.log` for errors
- Verify `.env` configuration (API key, domains)
- Ensure `data/` directory is writable: `chmod 755 data`
- Check PHP error log

#### Email not received
- Verify SMTP credentials in `.env`
- Check spam/junk folder
- For Gmail: Enable "Less secure app access" or use App Password
- Test SMTP connection manually
- Check `scan.log` for email errors

#### API rate limit exceeded
- Free tier: 4 requests/minute
- Scanner waits 15 seconds between requests
- Reduce number of domains or upgrade API plan

#### Blank/empty results
- Verify API key is valid
- Check domain names (no http://, just domain)
- Some domains may not be in VirusTotal database yet
- Check `last_result.json` for raw data

#### Webcron not working
- Verify HTTP Auth credentials match `.env`
- Test URL manually with Basic Auth
- Check Webcron execution log in hosting panel
- Ensure script is accessible via web

### Known Limitations

- **API Rate Limits:** Free tier restricted to 4 req/min, 500 req/day
- **Sequential scanning:** Domains scanned one-by-one (15s delay each)
- **No parallel processing:** Designed for small domain lists (<30)
- **Email dependency:** Requires working SMTP configuration
- **No database:** Results stored in JSON files only

### Roadmap

- [ ] Database integration (MySQL/SQLite)
- [ ] Historical scan comparison
- [ ] Webhook notifications (Slack, Discord, Teams)
- [ ] CSV export functionality
- [ ] Custom scan scheduling (per-domain intervals)
- [ ] Multi-user support with roles
- [ ] Dashboard with charts and statistics
- [ ] API v3 full feature support

### License

MIT License - see [LICENSE](LICENSE) file

### Author

**Alexander Wagner** ([@AlexanderWagnerDev](https://github.com/AlexanderWagnerDev))

### Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

## Deutsch

Automatisierter VirusTotal Domain-Scanner mit Web-Interface, Echtzeit-Logging und E-Mail-Benachrichtigungen. Scannt mehrere Domains sequenziell und liefert detaillierte Sicherheitsberichte.

### Features

- 🔍 **Multi-Domain-Scanning** - Mehrere Domains in einem Durchlauf scannen
- 🌐 **Web-Interface** - Echtzeit-Scan-Dashboard mit Live-Updates
- 📊 **Live-Logging** - Scan-Fortschritt in Echtzeit verfolgen
- 📧 **E-Mail-Benachrichtigungen** - Automatische HTML-E-Mail-Berichte via SMTP
- ⏰ **Cron-Kompatibel** - Perfekt für automatisierte geplante Scans
- 🔒 **Optionale Authentifizierung** - HTTP Basic Auth Schutz
- 💾 **JSON-Export** - Persistente Speicherung der Scan-Ergebnisse
- 🚨 **Bedrohungserkennung** - Erkennung bösartiger/verdächtiger Domains
- 🔄 **Auto-Rescan** - Löst frische VirusTotal-Analyse aus

### Voraussetzungen

- PHP 8.0 oder höher
- PHPMailer Bibliothek (enthalten im `/PHPMailer/` Verzeichnis)
- VirusTotal API Key (kostenlose Version verfügbar)
- SMTP-Account für E-Mail-Benachrichtigungen
- cURL Extension aktiviert
- Beschreibbares Datenverzeichnis für Logs

### Installation

1. **Repository klonen** auf deinen Webspace
   ```bash
   git clone https://github.com/AlexanderWagnerDev/virustotal-domains-scan.git
   cd virustotal-domains-scan
   ```

2. **PHPMailer installieren** (falls nicht enthalten)
   ```bash
   # Download von https://github.com/PHPMailer/PHPMailer
   # Entpacken ins ./PHPMailer/ Verzeichnis
   ```

3. **Datenverzeichnis erstellen**
   ```bash
   mkdir -p data
   chmod 755 data
   ```

4. **Konfigurationsdatei kopieren**
   ```bash
   cp .env.example .env
   ```

5. **`.env` Datei bearbeiten** mit deinen Zugangsdaten:
   ```env
   # API Key von https://www.virustotal.com/gui/my-apikey
   VT_API_KEY=dein_virustotal_api_key

   # Komma-getrennte Liste der zu scannenden Domains
   DOMAINS=beispiel.de,deinedomain.com,andereseite.org

   # Datenverzeichnis (muss beschreibbar sein)
   DATA_DIR=/absoluter/pfad/zu/data

   # SMTP Einstellungen
   SMTP_HOST=smtp.gmail.com
   SMTP_PORT=465
   SMTP_USER=deine-email@gmail.com
   SMTP_FROM="VT Scanner <deine-email@gmail.com>"
   SMTP_PASS=dein-app-passwort
   TO_EMAIL=benachrichtigungen@deinedomain.de

   # Optional: HTTP Basic Auth (empfohlen)
   CRON_USER=admin
   CRON_PASS=starkes-passwort
   ```

6. **`.env` Datei schützen** (siehe `.htaccess.example`)

7. **Scanner aufrufen**
   ```
   https://deinedomain.de/pfad/zu/domains-scan.php
   ```

### Konfiguration

| Variable | Beschreibung | Beispiel |
|----------|--------------|----------|
| `VT_API_KEY` | VirusTotal API Schlüssel | `abc123...` |
| `DOMAINS` | Komma-getrennte Domain-Liste | `beispiel.de,test.org` |
| `DATA_DIR` | Verzeichnis für Logs und JSON | `/var/www/data` |
| `SMTP_HOST` | SMTP Server Hostname | `smtp.gmail.com` |
| `SMTP_PORT` | SMTP Port (meist 465 oder 587) | `465` |
| `SMTP_USER` | SMTP Benutzername | `user@gmail.com` |
| `SMTP_FROM` | E-Mail Absender-Adresse | `scanner@domain.de` |
| `SMTP_PASS` | SMTP Passwort/App-Passwort | `deinpasswort` |
| `TO_EMAIL` | Empfänger E-Mail | `admin@domain.de` |
| `CRON_USER` | Optional HTTP Auth Benutzername | `admin` |
| `CRON_PASS` | Optional HTTP Auth Passwort | `sicherespasswort` |

### Verwendung

#### Manuelle Ausführung über Web-Interface

1. Öffne `domains-scan.php` im Browser
2. Klicke auf **🔥 START SCAN**
3. Beobachte den Echtzeit-Fortschritt
4. Erhalte E-Mail-Bericht nach Abschluss
5. Ansicht **📋 Full Log Viewer** für detaillierte Historie

#### Automatisierte Ausführung (Webcron/Cronjob)

**Für All-Inkl Webcron:**

1. Melde dich im **All-Inkl KAS** (Kunden-Adminbereich) an
2. Navigiere zu **Tools → Cronjobs**
3. Klicke auf **"Neuer Cronjob"**
4. Konfiguriere:
   - **URL:** `https://deinedomain.de/pfad/zu/domains-scan.php?start=1`
   - **HTTP Auth Benutzername:** Dein `CRON_USER` aus der `.env`
   - **HTTP Auth Passwort:** Dein `CRON_PASS` aus der `.env`
   - **Zeitplan:** Täglich/Wöchentlich (empfohlen: täglich um 3:00 Uhr)
   - **E-Mail Benachrichtigung:** Optional

**Für Standard-Cron:**
```bash
# Täglicher Scan um 3:00 Uhr
0 3 * * * curl -u "admin:passwort" "https://deinedomain.de/domains-scan.php?start=1" > /dev/null 2>&1
```

### API Endpunkte

| Endpunkt | Beschreibung | Ausgabe |
|----------|--------------|--------|
| `domains-scan.php` | Haupt-Dashboard | HTML UI |
| `?start=1` | Kompletten Scan starten | Text-Status |
| `?status=1` | Log-Viewer (Auto-Refresh) | HTML Log-Ansicht |

### Dateistruktur

```
virustotal-domains-scan/
├── domains-scan.php      # Haupt-Scanner-Skript
├── .env                  # Konfiguration (NICHT COMMITTEN!)
├── .env.example          # Beispiel-Konfiguration
├── .htaccess.example     # Beispiel Sicherheitsregeln
├── LICENSE               # MIT Lizenz
├── PHPMailer/            # E-Mail Bibliothek
│   ├── PHPMailer.php
│   ├── SMTP.php
│   └── Exception.php
└── data/                 # Logs und Ergebnisse (auto-erstellt)
    ├── scan.log          # Scan-Ausführungslog
    └── last_result.json  # Letzte Scan-Ergebnisse
```

### VirusTotal API Key erhalten

1. Registriere dich bei [VirusTotal](https://www.virustotal.com/)
2. Navigiere zu deiner [API Key Seite](https://www.virustotal.com/gui/my-apikey)
3. Kopiere deinen API Key
4. **Kostenlose Version Limits:** 4 Anfragen/Minute, 500 Anfragen/Tag

### E-Mail-Berichtsformat

Der Scanner sendet HTML-E-Mails mit:

- **Zusammenfassung:** Anzahl Domains, Positives, Bösartige Erkennungen, Scan-Dauer
- **Detaillierte Tabelle** mit:
  - Domain-Name (anklickbarer Link)
  - VirusTotal Bericht-Link
  - Reputation Score
  - Bösartige Erkennungen
  - Verdächtige Erkennungen
  - Gesamt-Positives
  - Letzter Scan-Zeitstempel
- **Visuelle Warnungen:** Zeilen mit Positives rot hervorgehoben

### Sicherheitsempfehlungen

⚠️ **Wichtige Sicherheitshinweise:**

1. **Immer HTTPS verwenden** - Schütze Zugangsdaten bei Übertragung
2. **`.env` Datei schützen** - Verwende `.htaccess` um Web-Zugriff zu verweigern
3. **HTTP Auth aktivieren** - Setze `CRON_USER` und `CRON_PASS` in `.env`
4. **Datenverzeichnis einschränken** - Verhindere direkten Web-Zugriff
5. **App-Passwörter verwenden** - Für Gmail, generiere app-spezifische Passwörter
6. **Rate Limiting** - Kostenlose API: 4 Anf./Min, 500 Anf./Tag
7. **Logs überwachen** - Prüfe `data/scan.log` regelmäßig

### Fehlersuche

#### Scan schlägt sofort fehl
- Prüfe `data/scan.log` auf Fehler
- Verifiziere `.env` Konfiguration (API Key, Domains)
- Stelle sicher dass `data/` beschreibbar ist: `chmod 755 data`
- Prüfe PHP Error Log

#### E-Mail nicht empfangen
- Verifiziere SMTP-Zugangsdaten in `.env`
- Prüfe Spam/Junk-Ordner
- Für Gmail: Aktiviere "Zugriff für weniger sichere Apps" oder nutze App-Passwort
- Teste SMTP-Verbindung manuell
- Prüfe `scan.log` auf E-Mail-Fehler

#### API Rate Limit überschritten
- Kostenlose Version: 4 Anfragen/Minute
- Scanner wartet 15 Sekunden zwischen Anfragen
- Reduziere Anzahl der Domains oder upgrade API-Plan

#### Leere/keine Ergebnisse
- Verifiziere dass API Key gültig ist
- Prüfe Domain-Namen (kein http://, nur Domain)
- Manche Domains sind möglicherweise noch nicht in VirusTotal-Datenbank
- Prüfe `last_result.json` für Rohdaten

#### Webcron funktioniert nicht
- Verifiziere HTTP Auth Zugangsdaten mit `.env`
- Teste URL manuell mit Basic Auth
- Prüfe Webcron-Ausführungslog im Hosting-Panel
- Stelle sicher dass Skript über Web erreichbar ist

### Bekannte Einschränkungen

- **API Rate Limits:** Kostenlose Version limitiert auf 4 Anf./Min, 500 Anf./Tag
- **Sequenzielles Scannen:** Domains werden nacheinander gescannt (15s Verzögerung)
- **Keine parallele Verarbeitung:** Ausgelegt für kleine Domain-Listen (<30)
- **E-Mail-Abhängigkeit:** Erfordert funktionierende SMTP-Konfiguration
- **Keine Datenbank:** Ergebnisse nur in JSON-Dateien gespeichert

### Roadmap

- [ ] Datenbank-Integration (MySQL/SQLite)
- [ ] Historischer Scan-Vergleich
- [ ] Webhook-Benachrichtigungen (Slack, Discord, Teams)
- [ ] CSV-Export-Funktionalität
- [ ] Individuelle Scan-Zeitpläne (pro Domain)
- [ ] Multi-User-Unterstützung mit Rollen
- [ ] Dashboard mit Grafiken und Statistiken
- [ ] API v3 vollständige Feature-Unterstützung

### Lizenz

MIT License - siehe [LICENSE](LICENSE) Datei

### Autor

**Alexander Wagner** ([@AlexanderWagnerDev](https://github.com/AlexanderWagnerDev))

### Mitwirken

Beiträge sind willkommen! Bitte reiche einen Pull Request ein.

---

## Support

🇬🇧 If you encounter any issues or have questions, please open an issue on GitHub.

🇩🇪 Bei Problemen oder Fragen öffne bitte ein Issue auf GitHub.