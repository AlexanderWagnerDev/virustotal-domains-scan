<?php
/**
 * VirusTotal Domain Scanner - Web UI + Cron Compatible
 * 
 * Features:
 * - ?status=1  => HTML Log View (Auto-Refresh)
 * - ?start=1   => Full scan run (all domains sequentially), email summary
 * 
 * Files:
 * - Log:   $DATA_DIR/scan.log
 * - JSON:  $DATA_DIR/last_result.json (last completed result)
 * 
 * Requirements:
 * - PHPMailer
 * - .env file with API keys
 */

set_time_limit(3600);
ignore_user_abort(true);

require_once __DIR__ . '/PHPMailer/Exception.php';
require_once __DIR__ . '/PHPMailer/PHPMailer.php';
require_once __DIR__ . '/PHPMailer/SMTP.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

// =====================================================
// CONFIGURATION - Edit these values
// =====================================================
$DATA_DIR  = __DIR__ . '/data';
$LOG_FILE  = $DATA_DIR . '/scan.log';
$LAST_JSON = $DATA_DIR . '/last_result.json';

// =====================================================
// Helpers
// =====================================================
function ensureDirOrDie(string $dir): void {
    if (!is_dir($dir)) {
        http_response_code(500);
        die("DATA_DIR does not exist: $dir\n");
    }
    if (!is_writable($dir)) {
        http_response_code(500);
        die("DATA_DIR not writable: $dir\n");
    }
}

function log_status(string $msg): void {
    global $LOG_FILE;
    $timestamp = date('Y-m-d H:i:s');
    file_put_contents($LOG_FILE, "[$timestamp] $msg\n", FILE_APPEND | LOCK_EX);
}

function load_env(string $file): void {
    if (!file_exists($file)) return;
    $lines = file($file, FILE_IGNORE_NEWLINES | FILE_IGNORE_NEWLINES);
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#') || !str_contains($line, '=')) continue;
        
        $parts = explode('=', $line, 2);
        if (count($parts) !== 2) continue;
        $k = trim($parts[0]);
        $v = trim($parts[1]);
        
        if (str_starts_with($v, '"') && str_ends_with($v, '"')) {
            $v = substr($v, 1, -1);
        } elseif (str_starts_with($v, "'") && str_ends_with($v, "'")) {
            $v = substr($v, 1, -1);
        }
        $_ENV[$k] = $v;
    }
}

function fastcgi_basic_auth_fix(): void {
    if (!empty($_SERVER['PHP_AUTH_USER'])) return;

    foreach (['HTTP_AUTHORIZATION', 'REDIRECT_HTTP_AUTHORIZATION'] as $header) {
        if (empty($_SERVER[$header])) continue;
        $hdr = $_SERVER[$header];
        if (stripos($hdr, 'basic ') !== 0) continue;

        $decoded = base64_decode(substr($hdr, 6));
        if ($decoded === false || strpos($decoded, ':') === false) continue;

        [$u, $p] = explode(':', $decoded, 2);
        $_SERVER['PHP_AUTH_USER'] = $u;
        $_SERVER['PHP_AUTH_PW']   = $p;
        return;
    }
}

function require_auth(string $realm, string $auth_user, string $auth_pass): void {
    fastcgi_basic_auth_fix();

    if (!isset($_SERVER['PHP_AUTH_USER']) || $_SERVER['PHP_AUTH_USER'] !== $auth_user ||
        !isset($_SERVER['PHP_AUTH_PW'])   || $_SERVER['PHP_AUTH_PW']   !== $auth_pass) {
        header('WWW-Authenticate: Basic realm="' . $realm . '"');
        header('HTTP/1.0 401 Unauthorized');
        die('Access denied!');
    }
}

function html(string $s): string {
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

// =====================================================
// Bootstrap: Check directory + load .env first!
// =====================================================
ensureDirOrDie($DATA_DIR);
load_env(__DIR__ . '/.env');

// =====================================================
// Auth from .env (optional - disable for public demo)
// =====================================================
$auth_user = $_ENV['CRON_USER'] ?? '';
$auth_pass = $_ENV['CRON_PASS'] ?? '';
if ($auth_user !== '' && $auth_pass !== '') {
    require_auth('VirusTotal Scanner', $auth_user, $auth_pass);
}

// =====================================================
// Status View (HTML Dashboard)
// =====================================================
if (isset($_GET['status'])) {
    header('Content-Type: text/html; charset=UTF-8');

    $full_log = '🟢 Ready - Not started yet...';
    if (file_exists($LOG_FILE)) {
        $logs = file_get_contents($LOG_FILE);
        $log_lines = array_filter(explode("\n", trim((string)$logs)));
        $full_log = implode('<br>', array_map('htmlspecialchars', $log_lines));
    }

    $lastInfo = '';
    if (file_exists($LAST_JSON)) {
        $last = json_decode(file_get_contents($LAST_JSON), true);
        if (is_array($last)) {
            $lastInfo = 'Last run: ' . date('Y-m-d H:i:s', (int)($last['finished_time'] ?? time()))
                . ' | Domains: ' . (int)($last['domain_count'] ?? 0)
                . ' | Positives: ' . (int)($last['positives_total'] ?? 0);
        }
    }
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width">
        <title>📋 VirusTotal Log Viewer</title>
        <style>
            * { margin:0; padding:0; box-sizing:border-box; }
            body {
                font-family:'Roboto', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                background:linear-gradient(135deg,#0a0a0a 0%,#1a1a2e 50%,#16213e 100%);
                color:#e0e0e0;
                min-height:100vh;
                padding:20px;
            }
            .status-card {
                background:rgba(17,17,17,0.95);
                border:2px solid #00ff88;
                border-radius:20px;
                padding:30px;
                max-width:1000px;
                margin:0 auto;
                backdrop-filter:blur(20px);
            }
            .header { text-align:center; margin-bottom:25px; }
            .status-icon { font-size:3em; }
            .meta {
                background:#000;
                border:1px solid #333;
                border-radius:12px;
                padding:12px 16px;
                margin: 0 0 18px 0;
                font-family:'Roboto Mono','Courier New',monospace;
                color:#aaa;
            }
            #full-log {
                background:#000;
                border:1px solid #333;
                border-radius:12px;
                padding:25px;
                height:70vh;
                max-height:700px;
                overflow:auto;
                font-family:'Roboto Mono','Courier New',monospace;
                font-size:15px;
                line-height:1.6;
                white-space:pre-wrap;
            }
            .controls { text-align:center; margin-top:20px; }
            .refresh-btn {
                background:linear-gradient(45deg,#00ff88,#00ccff);
                color:#000;
                border:none;
                padding:12px 30px;
                border-radius:25px;
                font-size:1em;
                cursor:pointer;
                font-weight:bold;
                margin:0 10px;
            }
        </style>
    </head>
    <body>
    <div class="status-card">
        <div class="header">
            <div class="status-icon">📋</div>
            <h2>VirusTotal Scan Log</h2>
        </div>

        <div class="meta">
            DATA_DIR: <b><?php echo html($DATA_DIR); ?></b><br>
            <?php echo html($lastInfo ?: 'No last_result.json available yet.'); ?>
        </div>

        <div id="full-log"><?php echo $full_log; ?></div>

        <div class="controls">
            <button class="refresh-btn" onclick="location.reload()">🔄 REFRESH</button>
        </div>
        <p style="text-align:center;margin-top:15px;font-size:0.9em;color:#888;">Auto-refresh in 5s</p>
    </div>
    <script>setTimeout(() => location.reload(), 5000);</script>
    </body>
    </html>
    <?php
    exit;
}

// =====================================================
// Full Scan Run (?start=1)
// =====================================================
if (isset($_GET['start'])) {
    http_response_code(200);
    header('Content-Type: text/plain; charset=UTF-8');

    // Config from .env
    $api_key     = $_ENV['VT_API_KEY'] ?? '';
    $domains_str = $_ENV['DOMAINS'] ?? '';
    $domains     = array_values(array_filter(array_map('trim', explode(',', $domains_str))));

    $smtp_host  = $_ENV['SMTP_HOST'] ?? '';
    $smtp_port  = (int)($_ENV['SMTP_PORT'] ?? 465);
    $smtp_user  = $_ENV['SMTP_USER'] ?? '';
    $smtp_pass  = $_ENV['SMTP_PASS'] ?? '';
    $from_email = $_ENV['SMTP_FROM'] ?? '';
    $to_email   = $_ENV['TO_EMAIL'] ?? '';

    if ($api_key === '' || empty($domains) || $to_email === '') {
        log_status("❌ FATAL: VT_API_KEY/DOMAINS/TO_EMAIL missing in .env");
        echo "CONFIG MISSING\n";
        exit(1);
    }

    $start_ts = time();
    log_status("🚀 VT Scan started (" . count($domains) . " domains)");

    $results = [];
    $positives_total = 0;
    $malicious_total = 0;
    $errors_total = 0;

    foreach ($domains as $domain) {
        log_status("🔍 Scanning $domain ...");

        // Trigger rescan
        $rescan_url = "https://www.virustotal.com/api/v3/domains/" . urlencode($domain) . "/analyse";
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $rescan_url,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => '{}',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => [
                'Accept: application/json',
                'Content-Type: application/json',
                'x-apikey: ' . $api_key
            ],
            CURLOPT_TIMEOUT => 30,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_USERAGENT => 'VT-Scanner/1.0'
        ]);
        $rescan_resp = curl_exec($ch);
        $rescan_code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $rescan_err = curl_error($ch);
        unset($ch);

        if ($rescan_resp === false) {
            $results[$domain] = ['error' => "Rescan cURL: $rescan_err"];
            $errors_total++;
            log_status("❌ $domain Rescan cURL error: $rescan_err");
            sleep(15);
            continue;
        }
        if ($rescan_code !== 200) {
            log_status("⚠️ $domain Rescan HTTP $rescan_code (OK if already queued)");
        } else {
            log_status("🚀 $domain Rescan triggered");
        }

        sleep(15);

        // Get report
        $report_url = "https://www.virustotal.com/api/v3/domains/" . urlencode($domain);
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $report_url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => [
                'Accept: application/json',
                'x-apikey: ' . $api_key
            ],
            CURLOPT_TIMEOUT => 30,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_USERAGENT => 'VT-Scanner/1.0'
        ]);
        $response = curl_exec($ch);
        $http_code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curl_err = curl_error($ch);
        unset($ch);

        if ($response === false) {
            $results[$domain] = ['error' => "Report cURL: $curl_err"];
            $errors_total++;
            log_status("❌ $domain Report cURL error: $curl_err");
            sleep(15);
            continue;
        }

        if ($http_code !== 200) {
            $results[$domain] = ['error' => "Report HTTP $http_code"];
            $errors_total++;
            log_status("❌ $domain Report HTTP error: $http_code");
            sleep(15);
            continue;
        }

        $data = json_decode($response, true);
        $attrs = $data['data']['attributes'] ?? [];
        $stats = $attrs['last_analysis_stats'] ?? [];

        $mal = (int)($stats['malicious'] ?? 0);
        $sus = (int)($stats['suspicious'] ?? 0);
        $pos = $mal + $sus;

        $results[$domain] = [
            'reputation' => $attrs['reputation'] ?? 'N/A',
            'malicious'  => $mal,
            'suspicious' => $sus,
            'positives'  => $pos,
            'last_scan'  => isset($attrs['last_analysis_date']) ? date('Y-m-d H:i:s', (int)$attrs['last_analysis_date']) : 'N/A',
        ];

        $positives_total += $pos;
        $malicious_total += $mal;

        log_status("✅ $domain positives=$pos malicious=$mal (fresh scan)");
        sleep(15);
    }

    $duration_s = time() - $start_ts;
    log_status("📊 Scan complete: positives_total=$positives_total malicious_total=$malicious_total errors_total=$errors_total duration={$duration_s}s");

    // Build HTML email body
    $html_body = '<h2>VirusTotal Domain Scan Results</h2>';
    $html_body .= '<p><strong>Summary:</strong> ' . count($domains) . ' domains scanned | ' . $positives_total . ' positives | ' . $malicious_total . ' malicious | ' . $duration_s . 's</p>';
    $html_body .= '<table border="1" cellpadding="6" style="border-collapse:collapse;">';
    $html_body .= '<tr><th>Domain</th><th>VT</th><th>Rep</th><th>Mal</th><th>Susp</th><th>Pos</th><th>Last Scan</th></tr>';
    
    foreach ($results as $dom => $res) {
        if (isset($res['error'])) {
            $html_body .= '<tr><td colspan="7" style="color:red">' . html($dom) . ': ' . html($res['error']) . '</td></tr>';
            continue;
        }
        $bg = ((int)$res['positives'] > 0) ? ' style="background:#ffeeee"' : '';
        $vt_link = 'https://www.virustotal.com/gui/domain/' . urlencode($dom);
        $html_body .= "<tr$bg>
            <td><a href='https://" . html($dom) . "' target='_blank'>" . html($dom) . "</a></td>
            <td><a href='$vt_link' target='_blank'>VT</a></td>
            <td>" . html((string)$res['reputation']) . "</td>
            <td>" . (int)$res['malicious'] . "</td>
            <td>" . (int)$res['suspicious'] . "</td>
            <td><b>" . (int)$res['positives'] . "</b></td>
            <td>" . html((string)$res['last_scan']) . "</td>
        </tr>";
    }
    $html_body .= '</table>';

    // Send email
    log_status("🔄 Sending email...");
    
    $mail = new PHPMailer(true);
    try {
        $mail->isSMTP();
        $mail->Host       = $smtp_host;
        $mail->SMTPAuth   = true;
        $mail->Username   = $smtp_user;
        $mail->Password   = $smtp_pass;
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
        $mail->Port       = $smtp_port;

        $mail->setFrom($from_email, 'VT Scanner');
        $mail->addAddress($to_email);
        $mail->CharSet    = 'UTF-8';
        $mail->isHTML(true);
        $mail->Subject    = 'VirusTotal Scan Results (' . date('Y-m-d H:i') . ')' . ($positives_total > 0 ? ' ⚠️ ALERT' : '');
        $mail->Body       = $html_body;
        $mail->AltBody    = strip_tags($html_body);
        
        $mail->send();
        log_status("✅ Email sent successfully");
    } catch (Exception $e) {
        log_status("❌ Email failed: " . $e->getMessage());
    }

    // Save results
    log_status("💾 Saving JSON results...");
    $last = [
        'finished_time'   => time(),
        'domain_count'    => count($domains),
        'positives_total' => $positives_total,
        'malicious_total' => $malicious_total,
        'errors_total'    => $errors_total,
        'duration_s'      => $duration_s,
        'results'         => $results,
    ];
    file_put_contents($LAST_JSON, json_encode($last, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX);

    log_status("🎉 Scan complete!");
    echo "OK\n";
    exit;
}

// =====================================================
// Main UI (Start Button + Live Preview)
// =====================================================
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>🔍 VirusTotal Domain Scanner</title>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body {
            font-family:'Roboto', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background:linear-gradient(135deg,#0a0a0a 0%,#1a1a2e 50%,#16213e 100%);
            color:#e0e0e0;
            min-height:100vh;
            padding:30px 20px;
        }
        .container { max-width:1000px; margin:0 auto; }
        .header { text-align:center; margin-bottom:40px; }
        .header h1 {
            font-size:3em;
            background:linear-gradient(45deg,#00ff88,#00ccff);
            -webkit-background-clip:text;
            -webkit-text-fill-color:transparent;
            margin-bottom:15px;
        }
        #controls { text-align:center; margin-bottom:30px; }
        button {
            padding:20px 50px;
            font-size:1.4em;
            background:linear-gradient(45deg,#00ff88,#00ccff);
            color:#000;
            border:none;
            border-radius:50px;
            cursor:pointer;
            font-weight:bold;
            box-shadow:0 15px 40px rgba(0,255,136,0.3);
            transition:all 0.3s ease;
        }
        button:hover:not(:disabled) {
            transform:translateY(-5px);
            box-shadow:0 20px 50px rgba(0,255,136,0.4);
        }
        button:disabled {
            background:#444;
            box-shadow:none;
            cursor:not-allowed;
            opacity:0.6;
        }
        #log {
            background:rgba(17,17,17,0.95);
            border:2px solid #00ff88;
            border-radius:25px;
            padding:30px;
            min-height:500px;
            overflow:auto;
            font-family:'Roboto Mono','Courier New',monospace;
            font-size:15px;
            line-height:1.6;
            backdrop-filter:blur(20px);
            box-shadow:inset 0 0 30px rgba(0,0,0,0.5);
        }
        .status-link { text-align:center; margin-top:20px; }
        .status-link a {
            color:#00ccff;
            text-decoration:none;
            font-weight:bold;
            font-size:1.1em;
        }
        .status-link a:hover { text-decoration:underline; }
        code {color:#00ff88}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>🔍 VirusTotal Scanner</h1>
        <p>Scans multiple domains via VirusTotal API with live logging and email alerts.</p>
    </div>

    <div id="controls">
        <button id="startBtn" onclick="startScan()">🔥 START SCAN</button>
    </div>

    <div id="log">🟢 Ready! Click "START SCAN" for live status...</div>

    <div class="status-link">
        <a href="?status=1">📋 Full Log Viewer</a>
    </div>
</div>

<script>
let running = false;

function startScan() {
    if (running) return;
    running = true;
    document.getElementById('startBtn').disabled  = true;
    document.getElementById('startBtn').innerHTML = '⏳ Scanning...';
    document.getElementById('log').innerHTML      = '🚀 Starting scan worker...';
    fetch('?start=1').then(() => updateStatus());
}

function updateStatus() {
    fetch('?status=1')
        .then(r => r.text())
        .then(data => {
            const logElement = document.getElementById('log');
            const lines = data.split('<br>');
            logElement.innerHTML = lines.slice(-25).join('<br>');
            logElement.scrollTop = logElement.scrollHeight;

            if (data.includes('🎉 Scan complete!') && running) {
                running = false;
                document.getElementById('startBtn').disabled  = false;
                document.getElementById('startBtn').innerHTML = '✅ COMPLETE! Restart?';
            } else if (running) {
                setTimeout(updateStatus, 2000);
            }
        }).catch(() => {});
}

setInterval(updateStatus, 5000);
updateStatus();
</script>
</body>
</html>
