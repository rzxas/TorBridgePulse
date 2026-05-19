// main.go
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"math/big"

	_ "github.com/lib/pq"
)

const DefaultTorrcTemplate = `
# Minimal torrc template for bridge checking
ClientOnly 1
AutomapHostsOnResolve 1
BandwidthBurst 1GB
BandwidthRate 1GB
DormantCanceledByStartup 1
DormantTimeoutDisabledByIdleStreams 1
UseEntryGuards 1
NumEntryGuards 1
NumPrimaryGuards 1
CircuitPadding 1
CircuitBuildTimeout 0 seconds
CircuitsAvailableTimeout 0 seconds
CircuitStreamTimeout 0 seconds
SocksPort 0
TokenBucketRefillInterval 75

StrictNodes 1
Log notice stdout
# CookieAuthentication will be set per-check (default 0 for temporary instances)
# ControlPort and DataDirectory will be set per-check
`

type BridgeRow struct {
	ID          int64
	RawLine     sql.NullString
	Host        sql.NullString
	Port        sql.NullInt64
	Fingerprint sql.NullString
	URL         sql.NullString
	SNI         sql.NullString
	Params      sql.NullString
	Ver         sql.NullString
}

type CheckResult struct {
	Success   bool
	Progress  int
	Summary   string
	Notes     string
	ElapsedMs int
	BridgeName string
}

var (
	// flags
	dsn             = flag.String("dsn", "", "Postgres DSN")
	envFile         = flag.String("env", "/etc/tor/bridge-db-connect.env", "Environment file with DATABASE_URL and API_TOKEN")
	torPath         = flag.String("tor", "tor", "Path to tor binary")
	lyrebirdPlugin  = flag.String("lyrebird", "obfs4,webtunnel exec /usr/bin/lyrebird", "ClientTransportPlugin line or path to lyrebird")
	baseTmpDir      = flag.String("tmpdir", "", "Base tmp dir for DataDirectory and torrc (default os.TempDir())")
	controlPortBase = flag.Int("control-port-base", 9151, "Base ControlPort (if not using auto-pick)")
	timeout         = flag.Duration("timeout", 30*time.Second, "Timeout for Tor bootstrap check")
	quickTimeout    = flag.Duration("quick-timeout", 3*time.Second, "Timeout for quick TCP/TLS/HTTP check")
	workers         = flag.Int("workers", 3, "Number of parallel Tor workers")
	pollInterval    = flag.Duration("poll-interval", 1*time.Minute, "How often to poll DB for candidates")
	batchSize       = flag.Int("batch-size", 0, "How many candidates to fetch per poll (0 = all)")
	once            = flag.Bool("once", false, "Run once and exit")
	verbose         = flag.Bool("v", false, "Verbose logging")
	checkOlderThan  = flag.String("check-older-than", "5m", "Select rows not checked since this interval (e.g. 5m, 1h)")
	torrcPath       = flag.String("torrc", "", "Path to base torrc to use as template (optional)")
	reuseDataDir    = flag.Bool("reuse-data-dir", false, "Reuse DataDirectory between checks for each worker (faster)")
	autoPickPort    = flag.Bool("auto-pick-port", true, "Automatically pick a free ControlPort for each check")
	dataSrcDir        = flag.String("data-src", "", "Path to central tor data cache to copy cached-* files from (optional)")
	keepTempOnFailure = flag.Bool("keep-temp-on-failure", false, "Do not remove dataDir/log on failure (for debugging)")
	geoipPath 	  = flag.String("geoip-path", "/usr/share/tor", "Path to directory containing geoip and geoip6 files (default /usr/share/tor)")
	lockMethod     = flag.String("lock-method", "pg", "lock method: 'pg' or 'none' (default 'pg')")
	advisoryKey    = flag.Int64("advisory-key", 123456789, "numeric key for advisory lock (default 123456789)")
	waitForExisting = flag.Bool("wait-for-existing", false, "wait for existing instance (default false)")
	waitTimeout     = flag.Duration("wait-timeout", 0, "maximum wait time like 30m; 0 means wait forever (default 0)")
	checkStatus 	= flag.String("check", "all", "status to check: alive|dead|timeout|unknown|all")
	checkID     	= flag.Int("id", 0, "check single bridge by id (overrides -check)")

	// new flags
	checkTypeFlag   = flag.String("type", "all", "Type to check: obfs4|webtunnel|all")
)

func logf(format string, a ...interface{}) {
	if *verbose {
		fmt.Printf(format+"\n", a...)
	}
}

// ----------------- global running registries -----------------
//
// globalRunning: pid -> struct{} for tor processes started by checker
// globalRunningCanc: pid -> cancel func for the monitor context
//
var (
	globalRunning       = make(map[int]struct{})
	globalRunningMu     sync.Mutex
	globalRunningCanc   = make(map[int]context.CancelFunc)
	globalRunningCancMu sync.Mutex

	geoNetsV4CIDR []*net.IPNet
	geoNetsV6CIDR []*net.IPNet
	geoRangesV4   []ipv4Range
	geoRangesV6   []ipv6Range
	geoNetsCC     = make(map[string]string) // по-прежнему можно хранить CIDR->CC

	geoCache = make(map[string]geoCacheVal)
	geoCacheMu sync.RWMutex
	geoCacheTTL = 24 * time.Hour

	reLogName = regexp.MustCompile(`new bridge descriptor '([^']+)'`)
	reTilde   = regexp.MustCompile(`~([A-Za-z0-9_-]+)`)
)

// simple mapping ISO code -> country name (дополни по необходимости)
var countryNames = map[string]string{
	"AF": "Afghanistan",
	"AX": "Åland Islands",
	"AL": "Albania",
	"DZ": "Algeria",
	"AS": "American Samoa",
	"AD": "Andorra",
	"AO": "Angola",
	"AI": "Anguilla",
	"AQ": "Antarctica",
	"AG": "Antigua and Barbuda",
	"AR": "Argentina",
	"AM": "Armenia",
	"AW": "Aruba",
	"AU": "Australia",
	"AT": "Austria",
	"AZ": "Azerbaijan",
	"BS": "Bahamas",
	"BH": "Bahrain",
	"BD": "Bangladesh",
	"BB": "Barbados",
	"BY": "Belarus",
	"BE": "Belgium",
	"BZ": "Belize",
	"BJ": "Benin",
	"BM": "Bermuda",
	"BT": "Bhutan",
	"BO": "Bolivia",
	"BQ": "Bonaire, Sint Eustatius and Saba",
	"BA": "Bosnia and Herzegovina",
	"BW": "Botswana",
	"BV": "Bouvet Island",
	"BR": "Brazil",
	"IO": "British Indian Ocean Territory",
	"BN": "Brunei Darussalam",
	"BG": "Bulgaria",
	"BF": "Burkina Faso",
	"BI": "Burundi",
	"CV": "Cabo Verde",
	"KH": "Cambodia",
	"CM": "Cameroon",
	"CA": "Canada",
	"KY": "Cayman Islands",
	"CF": "Central African Republic",
	"TD": "Chad",
	"CL": "Chile",
	"CN": "China",
	"CX": "Christmas Island",
	"CC": "Cocos (Keeling) Islands",
	"CO": "Colombia",
	"KM": "Comoros",
	"CG": "Congo",
	"CD": "Congo (Democratic Republic of the)",
	"CK": "Cook Islands",
	"CR": "Costa Rica",
	"CI": "Côte d'Ivoire",
	"HR": "Croatia",
	"CU": "Cuba",
	"CW": "Curaçao",
	"CY": "Cyprus",
	"CZ": "Czechia",
	"DK": "Denmark",
	"DJ": "Djibouti",
	"DM": "Dominica",
	"DO": "Dominican Republic",
	"EC": "Ecuador",
	"EG": "Egypt",
	"SV": "El Salvador",
	"GQ": "Equatorial Guinea",
	"ER": "Eritrea",
	"EE": "Estonia",
	"SZ": "Eswatini",
	"ET": "Ethiopia",
	"FK": "Falkland Islands (Malvinas)",
	"FO": "Faroe Islands",
	"FJ": "Fiji",
	"FI": "Finland",
	"FR": "France",
	"GF": "French Guiana",
	"PF": "French Polynesia",
	"TF": "French Southern Territories",
	"GA": "Gabon",
	"GM": "Gambia",
	"GE": "Georgia",
	"DE": "Germany",
	"GH": "Ghana",
	"GI": "Gibraltar",
	"GR": "Greece",
	"GL": "Greenland",
	"GD": "Grenada",
	"GP": "Guadeloupe",
	"GU": "Guam",
	"GT": "Guatemala",
	"GG": "Guernsey",
	"GN": "Guinea",
	"GW": "Guinea-Bissau",
	"GY": "Guyana",
	"HT": "Haiti",
	"HM": "Heard Island and McDonald Islands",
	"VA": "Holy See",
	"HN": "Honduras",
	"HK": "Hong Kong",
	"HU": "Hungary",
	"IS": "Iceland",
	"IN": "India",
	"ID": "Indonesia",
	"IR": "Iran (Islamic Republic of)",
	"IQ": "Iraq",
	"IE": "Ireland",
	"IM": "Isle of Man",
	"IL": "Israel",
	"IT": "Italy",
	"JM": "Jamaica",
	"JP": "Japan",
	"JE": "Jersey",
	"JO": "Jordan",
	"KZ": "Kazakhstan",
	"KE": "Kenya",
	"KI": "Kiribati",
	"KP": "Korea (Democratic People's Republic of)",
	"KR": "Korea (Republic of)",
	"KW": "Kuwait",
	"KG": "Kyrgyzstan",
	"LA": "Lao People's Democratic Republic",
	"LV": "Latvia",
	"LB": "Lebanon",
	"LS": "Lesotho",
	"LR": "Liberia",
	"LY": "Libya",
	"LI": "Liechtenstein",
	"LT": "Lithuania",
	"LU": "Luxembourg",
	"MO": "Macao",
	"MG": "Madagascar",
	"MW": "Malawi",
	"MY": "Malaysia",
	"MV": "Maldives",
	"ML": "Mali",
	"MT": "Malta",
	"MH": "Marshall Islands",
	"MQ": "Martinique",
	"MR": "Mauritania",
	"MU": "Mauritius",
	"YT": "Mayotte",
	"MX": "Mexico",
	"FM": "Micronesia (Federated States of)",
	"MD": "Moldova (Republic of)",
	"MC": "Monaco",
	"MN": "Mongolia",
	"ME": "Montenegro",
	"MS": "Montserrat",
	"MA": "Morocco",
	"MZ": "Mozambique",
	"MM": "Myanmar",
	"NA": "Namibia",
	"NR": "Nauru",
	"NP": "Nepal",
	"NL": "Netherlands",
	"NC": "New Caledonia",
	"NZ": "New Zealand",
	"NI": "Nicaragua",
	"NE": "Niger",
	"NG": "Nigeria",
	"NU": "Niue",
	"NF": "Norfolk Island",
	"MK": "North Macedonia",
	"MP": "Northern Mariana Islands",
	"NO": "Norway",
	"OM": "Oman",
	"PK": "Pakistan",
	"PW": "Palau",
	"PS": "Palestine, State of",
	"PA": "Panama",
	"PG": "Papua New Guinea",
	"PY": "Paraguay",
	"PE": "Peru",
	"PH": "Philippines",
	"PN": "Pitcairn",
	"PL": "Poland",
	"PT": "Portugal",
	"PR": "Puerto Rico",
	"QA": "Qatar",
	"RE": "Réunion",
	"RO": "Romania",
	"RU": "Russian Federation",
	"RW": "Rwanda",
	"BL": "Saint Barthélemy",
	"SH": "Saint Helena, Ascension and Tristan da Cunha",
	"KN": "Saint Kitts and Nevis",
	"LC": "Saint Lucia",
	"MF": "Saint Martin (French part)",
	"PM": "Saint Pierre and Miquelon",
	"VC": "Saint Vincent and the Grenadines",
	"WS": "Samoa",
	"SM": "San Marino",
	"ST": "Sao Tome and Principe",
	"SA": "Saudi Arabia",
	"SN": "Senegal",
	"RS": "Serbia",
	"SC": "Seychelles",
	"SL": "Sierra Leone",
	"SG": "Singapore",
	"SX": "Sint Maarten (Dutch part)",
	"SK": "Slovakia",
	"SI": "Slovenia",
	"SB": "Solomon Islands",
	"SO": "Somalia",
	"ZA": "South Africa",
	"GS": "South Georgia and the South Sandwich Islands",
	"SS": "South Sudan",
	"ES": "Spain",
	"LK": "Sri Lanka",
	"SD": "Sudan",
	"SR": "Suriname",
	"SJ": "Svalbard and Jan Mayen",
	"SE": "Sweden",
	"CH": "Switzerland",
	"SY": "Syrian Arab Republic",
	"TW": "Taiwan, Province of China",
	"TJ": "Tajikistan",
	"TZ": "Tanzania, United Republic of",
	"TH": "Thailand",
	"TL": "Timor-Leste",
	"TG": "Togo",
	"TK": "Tokelau",
	"TO": "Tonga",
	"TT": "Trinidad and Tobago",
	"TN": "Tunisia",
	"TR": "Turkey",
	"TM": "Turkmenistan",
	"TC": "Turks and Caicos Islands",
	"TV": "Tuvalu",
	"UG": "Uganda",
	"UA": "Ukraine",
	"AE": "United Arab Emirates",
	"GB": "United Kingdom of Great Britain and Northern Ireland",
	"US": "United States of America",
	"UM": "United States Minor Outlying Islands",
	"UY": "Uruguay",
	"UZ": "Uzbekistan",
	"VU": "Vanuatu",
	"VE": "Venezuela (Bolivarian Republic of)",
	"VN": "Viet Nam",
	"VG": "Virgin Islands (British)",
	"VI": "Virgin Islands (U.S.)",
	"WF": "Wallis and Futuna",
	"EH": "Western Sahara",
	"YE": "Yemen",
	"ZM": "Zambia",
	"ZW": "Zimbabwe",
	"ZZ": "Unknown",
}

// ----------------- utils for torrc writing -----------------

// normalizeLyrebirdArg: if user passed only path, add transport names
func normalizeLyrebirdArg(a string) string {
	a = strings.TrimSpace(a)
	if a == "" {
		return ""
	}
	// if contains exec or comma, assume full form
	if strings.Contains(a, "exec") || strings.Contains(a, ",") {
		return a
	}
	// user passed only path
	return fmt.Sprintf("obfs4,webtunnel exec %s", a)
}

// writeClientTransportPlugin writes a single ClientTransportPlugin line with comma-separated transports.
func writeClientTransportPlugin(w *bufio.Writer, clientTransportPluginArg string) error {
	s := strings.TrimSpace(clientTransportPluginArg)
	if s == "" {
		return nil
	}
	// normalize CR/LF and BOM
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.TrimPrefix(s, "\uFEFF")

	// if user passed only path, normalize to default transports
	if !strings.Contains(s, "exec") {
		s = fmt.Sprintf("obfs4,webtunnel exec %s", s)
	}

	// ensure exactly one space before "exec"
	parts := strings.SplitN(s, " exec ", 2)
	if len(parts) != 2 {
		// fallback: write whole argument as-is on one line
		_, err := w.WriteString("ClientTransportPlugin " + s + "\n")
		return err
	}

	names := strings.TrimSpace(parts[0])
	execPart := strings.TrimSpace(parts[1])
	// write single line with comma-separated names and exec part
	line := fmt.Sprintf("ClientTransportPlugin %s exec %s\n", names, execPart)
	if _, err := w.WriteString(line); err != nil {
		return err
	}
	return nil
}

// templateHasClientTransportPlugin returns true if template already contains ClientTransportPlugin
func templateHasClientTransportPlugin(baseTemplate string) bool {
	re := regexp.MustCompile(`(?mi)^\s*ClientTransportPlugin\b`)
	return re.MatchString(baseTemplate)
}

// safeWriteBridge writes Bridge line starting with "Bridge " (no extra quotes)
func safeWriteBridge(w *bufio.Writer, bridgeLine string) error {
	bridgeLine = strings.TrimSpace(bridgeLine)
	if bridgeLine == "" {
		return nil
	}
	bridgeLine = strings.TrimPrefix(bridgeLine, "\uFEFF")
	bridgeLine = strings.ReplaceAll(bridgeLine, "\r", "")

	// if user already included leading "Bridge ", remove it to avoid duplication
	lower := strings.ToLower(bridgeLine)
	if strings.HasPrefix(lower, "bridge ") {
		bridgeLine = strings.TrimSpace(bridgeLine[len("Bridge "):])
	}

	// write single line starting with Bridge and the rest exactly as provided (no added quotes)
	_, err := w.WriteString("Bridge " + bridgeLine + "\n")
	return err
}

// templateHasCookieAuth detects CookieAuthentication in base template
func templateHasCookieAuth(baseTemplate string) (bool, bool) {
	re := regexp.MustCompile(`(?mi)^\s*CookieAuthentication\s+([01])\s*$`)
	m := re.FindStringSubmatch(baseTemplate)
	if len(m) >= 2 {
		return true, m[1] == "1"
	}
	return false, false
}

// ----------------- control port / auth helpers -----------------

// pickFreePort returns a free TCP port on localhost
func pickFreePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// waitForControlPort waits until controlAddr is accepting connections or timeout
func waitForControlPort(controlAddr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", controlAddr, 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("control port %s not available after %s", controlAddr, timeout)
}

// readControlCookie reads control_auth_cookie from dataDir and returns hex string
func readControlCookie(dataDir string) (string, error) {
	cookiePath := filepath.Join(dataDir, "control_auth_cookie")
	b, err := os.ReadFile(cookiePath)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

// sendControlCommand sends a command and reads response block.
// It sets short deadlines to avoid blocking indefinitely during shutdown.
func sendControlCommand(conn net.Conn, cmd string) (string, error) {
	// set write deadline
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err := conn.Write([]byte(cmd + "\r\n"))
	if err != nil {
		return "", err
	}
	// set read deadline
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var lines []string
	r := bufio.NewReader(conn)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return "", err
		}
		line = strings.TrimRight(line, "\r\n")
		lines = append(lines, line)
		if strings.HasPrefix(line, "250 ") || strings.HasPrefix(line, "552 ") || strings.HasPrefix(line, "650 ") {
			break
		}
		// refresh read deadline for long responses
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	}
	// clear deadlines
	_ = conn.SetReadDeadline(time.Time{})
	_ = conn.SetWriteDeadline(time.Time{})
	return strings.Join(lines, "\n"), nil
}

var progressRe = regexp.MustCompile(`PROGRESS=(\d+)`)
var summaryRe = regexp.MustCompile(`SUMMARY="([^"]*)"`)

func parseBootstrapInfo(resp string) (int, string) {
	m := progressRe.FindStringSubmatch(resp)
	progress := -1
	if len(m) >= 2 {
		if v, err := strconv.Atoi(m[1]); err == nil {
			progress = v
		}
	}
	summary := ""
	if sm := summaryRe.FindStringSubmatch(resp); len(sm) >= 2 {
		summary = sm[1]
	}
	return progress, summary
}

// monitorBootstrap connects to ControlPort, authenticates (prefer cookie), polls GETINFO status/bootstrap-phase
// It waits until Tor reaches PROGRESS 100 or until ctx is done.
func monitorBootstrap(ctx context.Context, controlAddr, dataDir string, pollInterval time.Duration) (int, string, error) {
	// Wait for control port to be listening
	if err := waitForControlPort(controlAddr, 20*time.Second); err != nil {
		return 0, "", fmt.Errorf("control port not available: %w", err)
	}
	logf("control port %s is open", controlAddr)

	// Wait for control_auth_cookie to appear and be non-empty (prefer cookie auth)
	cookiePath := filepath.Join(dataDir, "control_auth_cookie")
	cookieWaitUntil := time.Now().Add(30 * time.Second)
	cookieReady := false
	for {
		select {
			case <-ctx.Done():
				return 0, "", ctx.Err()
			default:
		}
		fi, err := os.Stat(cookiePath)
		if err == nil && fi.Size() > 0 {
			cookieReady = true
			logf("control_auth_cookie present and non-empty (size=%d)", fi.Size())
			break
		}
		if time.Now().After(cookieWaitUntil) {
			logf("control_auth_cookie not ready after %s; will attempt empty AUTHENTICATE as fallback", time.Until(cookieWaitUntil))
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	// Connect once and authenticate (prefer cookie if available and non-empty)
	conn, err := net.Dial("tcp", controlAddr)
	if err != nil {
		return 0, "", fmt.Errorf("control connect: %w", err)
	}
	defer conn.Close()
	logf("connected to control %s", controlAddr)

	// Try cookie auth if available
	if cookieReady {
		b, rerr := os.ReadFile(cookiePath)
		if rerr == nil && len(b) > 0 {
			cookieHex := fmt.Sprintf("%x", b)
			resp, err := sendControlCommand(conn, fmt.Sprintf("AUTHENTICATE %s", cookieHex))
			if err != nil {
				return 0, "", fmt.Errorf("authenticate with cookie failed: %w", err)
			}
			if !strings.HasPrefix(resp, "250") {
				return 0, "", fmt.Errorf("authenticate with cookie rejected: %s", resp)
			}
			logf("authenticated with cookie")
		} else {
			// cookie read failed unexpectedly; try empty auth below
			logf("cookie file read error or empty despite earlier check: %v", rerr)
			resp, err := sendControlCommand(conn, `AUTHENTICATE ""`)
			if err != nil || !strings.HasPrefix(resp, "250") {
				return 0, "", fmt.Errorf("authenticate empty failed after cookie read error: %v; resp: %v", err, resp)
			}
			logf("authenticated with empty cookie fallback")
		}
	} else {
		// cookie not available — try empty authenticate once
		resp, err := sendControlCommand(conn, `AUTHENTICATE ""`)
		if err != nil || !strings.HasPrefix(resp, "250") {
			return 0, "", fmt.Errorf("authenticate empty failed and cookie not available: %v; resp: %v", err, resp)
		}
		logf("authenticated with empty cookie (no cookie file present)")
	}

	// Poll bootstrap status until PROGRESS == 100 or ctx timeout
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	lastProgress := -1
	for {
		select {
			case <-ctx.Done():
				return lastProgress, "", ctx.Err()
			case <-ticker.C:
				resp, err := sendControlCommand(conn, "GETINFO status/bootstrap-phase")
				if err != nil {
					// transient error — log and continue until ctx timeout
					logf("GETINFO transient error: %v", err)
					continue
				}
				progress, summary := parseBootstrapInfo(resp)
				if progress >= 0 {
					// log progress updates
					if progress != lastProgress {
						logf("bootstrap progress %d summary=%s", progress, summary)
						lastProgress = progress
					}
					// only return when bootstrap finished
					if progress >= 100 {
						return progress, summary, nil
					}
				}
				// otherwise continue polling
		}
	}
}

// ----------------- tor start/stop and logging -----------------

// startTorWithTorrc starts tor with -f torrcPath and redirects stdout/stderr to logFile.
// It sets process group so we can kill the whole group later.
func startTorWithTorrc(torPath, torrcPath, logFile string) (*exec.Cmd, *os.File, error) {
	cmd := exec.Command(torPath, "-f", torrcPath)
	// start in new process group
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, nil, fmt.Errorf("open tor log: %w", err)
	}
	cmd.Stdout = f
	cmd.Stderr = f
	if err := cmd.Start(); err != nil {
		_ = f.Close()
		return nil, nil, fmt.Errorf("start tor: %w", err)
	}
	return cmd, f, nil
}

// killProcessGroup sends SIGTERM to process group of pid, then SIGKILL if still alive after timeout.
func killProcessGroup(pid int, grace time.Duration) {
	pgid, err := syscall.Getpgid(pid)
	if err != nil {
		_ = syscall.Kill(pid, syscall.SIGTERM)
		time.Sleep(200 * time.Millisecond)
		_ = syscall.Kill(pid, syscall.SIGKILL)
		return
	}
	_ = syscall.Kill(-pgid, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		time.Sleep(grace)
		done <- struct{}{}
	}()
	<-done
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
}

type ipv4Range struct {
	start uint32
	end   uint32
	cc    string
}
type ipv6Range struct {
	start *big.Int
	end   *big.Int
	cc    string
}

// helper: convert uint32 to net.IP (big-endian)
func uint32ToIP(n uint32) net.IP {
	b := make([]byte, 4)
	b[0] = byte(n >> 24)
	b[1] = byte(n >> 16)
	b[2] = byte(n >> 8)
	b[3] = byte(n)
	return net.IP(b)
}

// helper: parse decimal IPv4 number string to uint32
func parseIPv4Decimal(s string) (uint32, error) {
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(v), nil
}

// helper: parse IPv6 text to big.Int
func ipToBigInt(ip net.IP) *big.Int {
	ip = ip.To16()
	if ip == nil {
		return nil
	}
	return new(big.Int).SetBytes(ip)
}

// loadGeoFlexible parses a Tor-style geoip/geoip6 file supporting:
// - CIDR lines: "1.2.3.0/24\tCC" or "2001:db8::/32 CC"
// - IPv4 decimal ranges: "16777216,16777471,AU"
// - IPv6 ranges: "2001:2::,2001:2:0:ffff:...,US"
func loadGeoFlexible(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// split by comma or whitespace/tab
		// prefer comma if present (your files use commas)
		var parts []string
		if strings.Contains(line, ",") {
			parts = strings.Split(line, ",")
			for i := range parts {
				parts[i] = strings.TrimSpace(parts[i])
			}
		} else {
			parts = strings.Fields(line)
		}
		if len(parts) < 2 {
			continue
		}
		// last part is country code
		cc := parts[len(parts)-1]

		// Case A: CIDR (first part contains '/')
		first := parts[0]
		if strings.Contains(first, "/") {
			if _, ipnet, err := net.ParseCIDR(first); err == nil {
				if ipnet.IP.To4() != nil {
					geoNetsV4CIDR = append(geoNetsV4CIDR, ipnet)
				} else {
					geoNetsV6CIDR = append(geoNetsV6CIDR, ipnet)
				}
				geoNetsCC[ipnet.String()] = cc
				continue
			}
			// if ParseCIDR failed, fallthrough to other parsers
		}

		// Case B: IPv4 decimal range: startDecimal,endDecimal,CC
		// detect by numeric first token without ':' and not containing letters
		if _, err := strconv.ParseUint(first, 10, 64); err == nil && !strings.Contains(first, ":") {
			// expect at least 3 parts: start,end,CC
			if len(parts) >= 3 {
				startStr := parts[0]
				endStr := parts[1]
				s, err1 := parseIPv4Decimal(startStr)
				e, err2 := parseIPv4Decimal(endStr)
				if err1 == nil && err2 == nil {
					// store range
					geoRangesV4 = append(geoRangesV4, ipv4Range{start: s, end: e, cc: cc})
					continue
				}
			}
		}

		// Case C: IPv6 textual range: startIP,endIP,CC
		// detect by presence of ':' in first token
		if strings.Contains(first, ":") {
			if len(parts) >= 3 {
				startIP := net.ParseIP(parts[0])
				endIP := net.ParseIP(parts[1])
				if startIP != nil && endIP != nil {
					s := ipToBigInt(startIP)
					e := ipToBigInt(endIP)
					if s != nil && e != nil {
						geoRangesV6 = append(geoRangesV6, ipv6Range{start: s, end: e, cc: cc})
						continue
					}
				}
			}
		}

		// fallback: try parse first as CIDR again (robustness)
		if _, ipnet, err := net.ParseCIDR(first); err == nil {
			if ipnet.IP.To4() != nil {
				geoNetsV4CIDR = append(geoNetsV4CIDR, ipnet)
			} else {
				geoNetsV6CIDR = append(geoNetsV6CIDR, ipnet)
			}
			geoNetsCC[ipnet.String()] = cc
			continue
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

// lookupCountryFlexible: check CIDR lists first, then ranges
func lookupCountryFlexible(ip net.IP) string {
	if ip == nil {
		return "ZZ"
	}
	if ip.To4() != nil {
		// CIDR check
		for _, n := range geoNetsV4CIDR {
			if n.Contains(ip) {
				if cc, ok := geoNetsCC[n.String()]; ok {
					return cc
				}
				return "ZZ"
			}
		}
		// range check (convert ip to uint32)
		b := ip.To4()
		if b == nil {
			return "ZZ"
		}
		val := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		for _, r := range geoRangesV4 {
			if val >= r.start && val <= r.end {
				return r.cc
			}
		}
		return "ZZ"
	} else {
		// IPv6: CIDR check
		for _, n := range geoNetsV6CIDR {
			if n.Contains(ip) {
				if cc, ok := geoNetsCC[n.String()]; ok {
					return cc
				}
				return "ZZ"
			}
		}
		// range check using big.Int
		ipInt := ipToBigInt(ip)
		if ipInt == nil {
			return "ZZ"
		}
		for _, r := range geoRangesV6 {
			if ipInt.Cmp(r.start) >= 0 && ipInt.Cmp(r.end) <= 0 {
				return r.cc
			}
		}
		return "ZZ"
	}
}

type geoCacheVal struct {
	cc string
	ts time.Time
}

func lookupCountryCached(ip net.IP) string {
	key := ip.String()
	geoCacheMu.RLock()
	if v, ok := geoCache[key]; ok {
		if time.Since(v.ts) < geoCacheTTL {
			geoCacheMu.RUnlock()
			return v.cc
		}
	}
	geoCacheMu.RUnlock()

	// do actual lookup (cidranger or simple)
	cc := lookupCountryFlexible(ip) // or lookupCountryCIDR(ip)
	geoCacheMu.Lock()
	geoCache[key] = geoCacheVal{cc: cc, ts: time.Now()}
	geoCacheMu.Unlock()
	return cc
}

func countryNameFromCode(cc string) string {
	if cc == "" {
		return ""
	}
	if n, ok := countryNames[cc]; ok {
		return n
	}
	return cc
}

func resolveHostToIP(host string, timeout time.Duration) net.IP {
	if host == "" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip
		}
	}
	return ips[0]
}

// readLogSnippet reads up to n bytes from beginning of file (for notes)
func readLogSnippet(path string, n int) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("log read err: %v", err)
	}
	if len(b) > n {
		return string(b[:n])
	}
	return string(b)
}

func extractBridgeNameFromText(s string) string {
	if m := reLogName.FindStringSubmatch(s); len(m) >= 2 {
		return strings.TrimSpace(m[1])
	}
	if m := reTilde.FindStringSubmatch(s); len(m) >= 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// ----------------- data cache population utilities -----------------

// copyFile copies file from src to dst preserving mode.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	fi, err := in.Stat()
	if err != nil {
		return err
	}
	// ensure parent dir exists
	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, fi.Mode())
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

// copyDirIfNotExists copies directory entries from srcDir to dstDir only if they don't exist in dst.
func copyDirIfNotExists(srcDir, dstDir string) error {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		srcPath := filepath.Join(srcDir, e.Name())
		dstPath := filepath.Join(dstDir, e.Name())
		if e.IsDir() {
			// ensure dst dir exists
			if _, err := os.Stat(dstPath); os.IsNotExist(err) {
				if err := os.MkdirAll(dstPath, 0700); err != nil {
					return err
				}
			}
			// copy files inside directory (one level)
			subEntries, err := os.ReadDir(srcPath)
			if err != nil {
				return err
			}
			for _, se := range subEntries {
				ssrc := filepath.Join(srcPath, se.Name())
				sdst := filepath.Join(dstPath, se.Name())
				if _, serr := os.Stat(sdst); serr == nil {
					continue
				}
				if err := copyFile(ssrc, sdst); err != nil {
					logf("populate: copy %s -> %s: %v", ssrc, sdst, err)
				}
			}
			continue
		}
		// file
		if di, derr := os.Stat(dstPath); derr == nil && di.Size() > 0 {
			continue // already present and non-empty
		}
		if err := copyFile(srcPath, dstPath); err != nil {
			logf("populate: copy %s -> %s: %v", srcPath, dstPath, err)
		} else {
			logf("populate: copied %s -> %s", srcPath, dstPath)
		}
	}
	return nil
}

// populateDataDirFromCache copies a set of cached files into dataDir if missing.
func populateDataDirFromCache(cacheDir, dataDir string) error {
	if cacheDir == "" {
		return nil
	}
	// list of files/dirs to copy
	items := []string{
		"cached-certs",
		"cached-descriptors",
		"cached-descriptors.new",
		"cached-microdesc-consensus",
		"cached-microdescs",
		"cached-microdescs.new",
		"keys",
		"pt_state",
		"torrc",
	}
	for _, it := range items {
		src := filepath.Join(cacheDir, it)
		dst := filepath.Join(dataDir, it)
		if _, err := os.Stat(src); err != nil {
			// source missing — skip silently
			continue
		}
		si, _ := os.Stat(src)
		if si.IsDir() {
			if err := copyDirIfNotExists(src, dst); err != nil {
				logf("populateDataDirFromCache dir %s -> %s: %v", src, dst, err)
			}
		} else {
			if err := copyFile(src, dst); err != nil {
				logf("populateDataDirFromCache file %s -> %s: %v", src, dst, err)
			} else {
				logf("populateDataDirFromCache copied %s -> %s", src, dst)
			}
		}
	}
	// ensure permissions
	_ = os.Chmod(dataDir, 0700)
	return nil
}

// ----------------- torrc creation -----------------

// writeTempTorrc creates a temporary torrc file with strict permissions and returns its path.
func writeTempTorrc(baseDir, baseTemplate, clientTransportPlugin, dataDir string, controlPort int, bridgeLine string, cookieAuth bool) (string, error) {
	tmpDir := baseDir
	if tmpDir == "" {
		tmpDir = os.TempDir()
	}
	ts := time.Now().UnixNano()
	torrcPath := filepath.Join(tmpDir, fmt.Sprintf("torrc-check-%d", ts))
	f, err := os.OpenFile(torrcPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return "", fmt.Errorf("open torrc: %w", err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)

	// clean template
	baseTemplate = strings.ReplaceAll(baseTemplate, "\r", "")
	baseTemplate = strings.TrimPrefix(baseTemplate, "\uFEFF")

	// detect cookie auth in template (foundCookie==true means template already contains CookieAuthentication)
	foundCookie, cookieVal := templateHasCookieAuth(baseTemplate)
	hasSocks := strings.Contains(strings.ToLower(baseTemplate), "socksport")

	// write base template as-is
	if _, err := w.WriteString(baseTemplate + "\n"); err != nil {
		return "", fmt.Errorf("write template: %w", err)
	}

	// If template does not specify SocksPort, explicitly disable it to avoid conflicts.
	if !hasSocks {
		if _, err := w.WriteString("SocksPort 0\n"); err != nil {
			return "", fmt.Errorf("write SocksPort: %w", err)
		}
	}

	// DataDirectory and ControlPort
	if _, err := w.WriteString(fmt.Sprintf("DataDirectory %s\n", dataDir)); err != nil {
		return "", fmt.Errorf("write DataDirectory: %w", err)
	}
	if _, err := w.WriteString(fmt.Sprintf("ControlPort %d\n", controlPort)); err != nil {
		return "", fmt.Errorf("write ControlPort: %w", err)
	}

	// CookieAuthentication: if template already contains directive, do NOT add another one.
	if !foundCookie {
		if _, err := w.WriteString("CookieAuthentication 1\n"); err != nil {
			return "", fmt.Errorf("write CookieAuthentication: %w", err)
		}
	} else {
		_ = cookieVal
	}

	// ClientTransportPlugin: write only if template doesn't already contain it
	if templateHasClientTransportPlugin(baseTemplate) {
		logf("template already contains ClientTransportPlugin; skipping additional write")
	} else {
		if err := writeClientTransportPlugin(w, clientTransportPlugin); err != nil {
			return "", fmt.Errorf("write ClientTransportPlugin: %w", err)
		}
	}

	// Bridge (safe, no added quotes)
	if err := safeWriteBridge(w, bridgeLine); err != nil {
		return "", fmt.Errorf("write Bridge: %w", err)
	}

	if err := w.Flush(); err != nil {
		return "", fmt.Errorf("flush torrc: %w", err)
	}
	if err := os.Chmod(torrcPath, 0600); err != nil {
		return "", fmt.Errorf("chmod torrc: %w", err)
	}
	logf("wrote torrc %s (DataDirectory=%s ControlPort=%d)", torrcPath, dataDir, controlPort)
	return torrcPath, nil
}

// ----------------- Network check ---------------

func isNetworkUp(timeout time.Duration) bool {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.Dial("tcp", "9.9.9.9:53")
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// ----------------- quick check -----------------

// quickCheck performs a light-weight connectivity test.
// returns status ("alive"/"timeout"), latencyMs, notes, isTimeout
func quickCheck(typ, host string, port int, urlStr, sni string, timeout time.Duration) (string, int, string, bool) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	start := time.Now()
	if typ == "webtunnel" && urlStr != "" {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{ServerName: sni, InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}
		req, _ := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
		resp, err := client.Do(req)
		if err != nil {
			return "timeout", 0, err.Error(), ctx.Err() == context.DeadlineExceeded
		}
		defer resp.Body.Close()
		lat := int(time.Since(start).Milliseconds())
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return "alive", lat, fmt.Sprintf("http %d", resp.StatusCode), false
		}
		return "timeout", lat, fmt.Sprintf("http %d", resp.StatusCode), false
	}
	d := net.Dialer{Timeout: timeout}
	if typ == "webtunnel" {
		conn, err := tls.DialWithDialer(&d, "tcp", addr, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return "timeout", 0, err.Error(), true
			}
			return "timeout", 0, err.Error(), false
		}
		conn.Close()
		return "alive", int(time.Since(start).Milliseconds()), "tls ok", false
	}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return "timeout", 0, err.Error(), true
		}
		return "timeout", 0, err.Error(), false
	}
	conn.Close()
	return "alive", int(time.Since(start).Milliseconds()), "tcp ok", false
}

// ----------------- run tor check -----------------

// runTorCheckWithTorrc runs a single tor instance with generated torrc and monitors bootstrap.
// parentCtx is used as parent for per-check context so global shutdown can cancel all checks.
func runTorCheckWithTorrc(parentCtx context.Context, torPath, baseTemplate, lyrebirdPlugin, bridgeLine, baseTmpDir string, controlPortBase int, timeout time.Duration, reuse bool, autoPick bool, running map[int]struct{}, runningMu *sync.Mutex) CheckResult {
	start := time.Now()
	ts := time.Now().UnixNano()

	// dataDir per-run (or per-worker if reuse)
	dataDir := filepath.Join(baseTmpDir, fmt.Sprintf("tor-check-data-%d", ts))
	// pick control port
	var controlPort int
	var err error
	if autoPick {
		controlPort, err = pickFreePort()
		if err != nil {
			return CheckResult{Success: false, Progress: 0, Summary: "", Notes: fmt.Sprintf("pick port: %v", err)}
		}
	} else {
		controlPort = controlPortBase + int(ts%1000)
	}
	controlAddr := fmt.Sprintf("127.0.0.1:%d", controlPort)

	// create data dir
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return CheckResult{Success: false, Progress: 0, Summary: "", Notes: fmt.Sprintf("mkdir dataDir: %v", err)}
	}

	// populate from cache if requested
	if *dataSrcDir != "" {
		if err := populateDataDirFromCache(*dataSrcDir, dataDir); err != nil {
			logf("populateDataDirFromCache err: %v", err)
		} else {
			logf("populated dataDir %s from cache %s", dataDir, *dataSrcDir)
		}
	}

	// torrc path and log path
	torrcPath, err := writeTempTorrc(baseTmpDir, baseTemplate, lyrebirdPlugin, dataDir, controlPort, bridgeLine, false)
	if err != nil {
		if !*keepTempOnFailure {
			_ = os.RemoveAll(dataDir)
		}
		return CheckResult{Success: false, Progress: 0, Summary: "", Notes: fmt.Sprintf("write torrc: %v", err)}
	}
	logPath := filepath.Join(baseTmpDir, fmt.Sprintf("tor-check-log-%d.log", ts))

	// start tor
	cmd, logFile, err := startTorWithTorrc(torPath, torrcPath, logPath)
	if err != nil {
		if !*keepTempOnFailure {
			_ = os.RemoveAll(dataDir)
			_ = os.Remove(torrcPath)
		}
		return CheckResult{Success: false, Progress: 0, Summary: "", Notes: fmt.Sprintf("start tor: %v", err)}
	}

	// register running pid for global shutdown
	if running != nil && runningMu != nil {
		runningMu.Lock()
		running[cmd.Process.Pid] = struct{}{}
		runningMu.Unlock()
	}
	// register global running
	globalRunningMu.Lock()
	globalRunning[cmd.Process.Pid] = struct{}{}
	globalRunningMu.Unlock()

	// create per-check context and register cancel globally so shutdown can cancel monitors
	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	globalRunningCancMu.Lock()
	globalRunningCanc[cmd.Process.Pid] = cancel
	globalRunningCancMu.Unlock()

	// ensure we remove cancel registration at the end
	defer func(pid int) {
		globalRunningCancMu.Lock()
		delete(globalRunningCanc, pid)
		globalRunningCancMu.Unlock()
	}(cmd.Process.Pid)

	// wait for control port to open
	if err := waitForControlPort(controlAddr, 12*time.Second); err != nil {
		// read some log bytes for notes
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = logFile.Close()
		logSnippet := readLogSnippet(logPath, 4096)
		bridgeName := extractBridgeNameFromText(logSnippet)
		// cleanup
		if !reuse && !*keepTempOnFailure {
			_ = os.RemoveAll(dataDir)
			_ = os.Remove(torrcPath)
		}
		// unregister
		if running != nil && runningMu != nil {
			runningMu.Lock()
			delete(running, cmd.Process.Pid)
			runningMu.Unlock()
		}
		globalRunningMu.Lock()
		delete(globalRunning, cmd.Process.Pid)
		globalRunningMu.Unlock()
		// remove cancel registration and cancel
		globalRunningCancMu.Lock()
		if c, ok := globalRunningCanc[cmd.Process.Pid]; ok {
			c()
			delete(globalRunningCanc, cmd.Process.Pid)
		}
		globalRunningCancMu.Unlock()
		return CheckResult{
			Success: false,
			Progress: 0,
			Summary: "",
			Notes: fmt.Sprintf("control connect: %v; torlog: %s", err, logSnippet),
			BridgeName: bridgeName,
		}
	}

	// monitor bootstrap with context (ctx will be canceled on global shutdown)
	progress, summary, monErr := monitorBootstrap(ctx, controlAddr, dataDir, 1*time.Second)
	elapsed := time.Since(start)

	// cleanup cancel registration and call cancel to free resources
	globalRunningCancMu.Lock()
	if c, ok := globalRunningCanc[cmd.Process.Pid]; ok {
		c()
		delete(globalRunningCanc, cmd.Process.Pid)
	}
	globalRunningCancMu.Unlock()
	cancel()

	// if monitor returned error, wait a bit for diagnostics before killing
	if monErr != nil {
		logf("monitorBootstrap error: %v — sleeping 12s for diagnostics before killing tor", monErr)
		time.Sleep(12 * time.Second)
	}

	// stop tor: send SIGTERM to group, wait, then SIGKILL
	killProcessGroup(cmd.Process.Pid, 2*time.Second)
	_ = cmd.Wait()
	_ = logFile.Close()

	// read log snippet for notes
	logSnippet := readLogSnippet(logPath, 4096)

	// cleanup if not reusing and not requested to keep temp on failure
	if !reuse {
		if !*keepTempOnFailure {
			_ = os.RemoveAll(dataDir)
			_ = os.Remove(torrcPath)
			_ = os.Remove(logPath)
		} else {
			logf("keeping temp artifacts: %s %s %s", dataDir, torrcPath, logPath)
		}
	}

	// unregister
	if running != nil && runningMu != nil {
		runningMu.Lock()
		delete(running, cmd.Process.Pid)
		runningMu.Unlock()
	}
	globalRunningMu.Lock()
	delete(globalRunning, cmd.Process.Pid)
	globalRunningMu.Unlock()

	res := CheckResult{
		Success:   false,
		Progress:  progress,
		Summary:   summary,
		Notes:     logSnippet,
		ElapsedMs: int(elapsed.Milliseconds()),
	}
	res.BridgeName = extractBridgeNameFromText(logSnippet)

	if monErr != nil {
		res.Notes = strings.TrimSpace(res.Notes + " " + monErr.Error())
		return res
	}
	if progress >= 100 {
		res.Success = true
		return res
	}
	return res
}

// ----------------- DB and worker logic -----------------
func checkBridgeRow(ctx context.Context, db *sql.DB, br BridgeRow, baseTemplate, lyrebird, baseTmp, persistentDataDir, torPath string, controlPortBase int, timeout time.Duration, reuseDataDir bool, autoPickPort bool, running map[int]struct{}, runningMu *sync.Mutex) error {
	// build bridgeLine
	raw := ""
	if br.RawLine.Valid {
		raw = br.RawLine.String
	}
	bridgeLine := raw
	if bridgeLine == "" {
		if br.Fingerprint.Valid && br.Host.Valid && br.Port.Valid {
			params := ""
			if br.Params.Valid {
				params = br.Params.String
			}
			if strings.Contains(params, "cert=") || strings.Contains(params, "iat-mode=") {
				bridgeLine = fmt.Sprintf("obfs4 %s:%d %s %s", br.Host.String, br.Port.Int64, br.Fingerprint.String, params)
			} else {
				bridgeLine = fmt.Sprintf("webtunnel %s:%d %s %s", br.Host.String, br.Port.Int64, br.Fingerprint.String, params)
			}
		} else {
			return fmt.Errorf("skip id=%d: no raw_line and insufficient fields", br.ID)
		}
	}

	// quick check
	typ := "webtunnel"
	lower := strings.ToLower(bridgeLine)
	if strings.HasPrefix(lower, "obfs4") || strings.Contains(lower, "cert=") || strings.Contains(lower, "iat-mode=") {
		typ = "obfs4"
	}

	host := ""
	port := 0
	if br.Host.Valid && br.Port.Valid {
		host = br.Host.String
		port = int(br.Port.Int64)
	} else {
		parts := strings.Fields(bridgeLine)
		if len(parts) >= 2 {
			hp := parts[1]
			if strings.HasPrefix(hp, "[") && strings.Contains(hp, "]:") {
				inside := strings.TrimPrefix(hp, "[")
				parts2 := strings.SplitN(inside, "]:", 2)
				host = parts2[0]
				p, _ := strconv.Atoi(parts2[1])
				port = p
			} else {
				parts2 := strings.SplitN(hp, ":", 2)
				if len(parts2) == 2 {
					host = parts2[0]
					p, _ := strconv.Atoi(parts2[1])
					port = p
				}
			}
		}
	}

	urlStr := ""
	if br.URL.Valid {
		urlStr = br.URL.String
	}
	sni := ""
	if br.SNI.Valid {
		sni = br.SNI.String
	}

	quickStatus := "unknown"
	latMs := 0
	notes := ""
	isTimeout := false
	if host != "" && port != 0 {
		qs, lat, qnotes, qto := quickCheck(typ, host, port, urlStr, sni, *quickTimeout)
		quickStatus = qs
		latMs = lat
		notes = qnotes
		isTimeout = qto
	}

	if quickStatus == "timeout" {
		latNull := sql.NullInt64{Int64: int64(latMs), Valid: latMs > 0}
		var cc, cname, provider string
		ip := resolveHostToIP(host, 2*time.Second)
		if ip != nil {
			cc = lookupCountryCached(ip)
			cname = countryNameFromCode(cc)
			provider = "tor-geoip"
		}
		logf("quick timeout for id=%d host=%s ip=%v cc=%s; proceeding to full Tor check", br.ID, host, ip, cc)
		if err := applyResult(db, br.ID, "timeout", latNull, "quick:"+notes, isTimeout, cc, cname, provider, ""); err != nil {
			logf("applyResult quick err id=%d: %v", br.ID, err)
		}
	}

	// run Tor bootstrap check
	runTmp := baseTmp
	if reuseDataDir && persistentDataDir != "" {
		runTmp = persistentDataDir
	}
	bl := strings.TrimSpace(bridgeLine)
	if strings.HasPrefix(strings.ToLower(bl), "bridge ") {
		bl = strings.TrimSpace(bl[len("Bridge "):])
	}

	res := runTorCheckWithTorrc(ctx, torPath, baseTemplate, lyrebird, bl, runTmp, controlPortBase, timeout, reuseDataDir, autoPickPort, running, runningMu)
	status := "timeout"
	if res.Success {
		status = "alive"
	}
	latNull := sql.NullInt64{Int64: int64(res.ElapsedMs), Valid: res.ElapsedMs > 0}
	note := strings.TrimSpace(res.Summary + " " + res.Notes)
	var cc, cname, provider string
	ip := resolveHostToIP(host, 2*time.Second)
	if ip != nil {
		cc = lookupCountryCached(ip)
		cname = countryNameFromCode(cc)
		provider = "tor-geoip"
	}

	bridgeName := strings.TrimSpace(res.BridgeName)
	if err := applyResult(db, br.ID, status, latNull, note, res.Progress < 100, cc, cname, provider, bridgeName); err != nil {
		return fmt.Errorf("applyResult tor err id=%d: %w", br.ID, err)
	}

	logf("checked id=%d status=%s progress=%d elapsed=%dms cc=%s", br.ID, status, res.Progress, res.ElapsedMs, cc)
	return nil
}

func checkBridgeByID(ctx context.Context, db *sql.DB, id int64, baseTemplate, lyrebird, baseTmp, persistentDataDir, torPath string, controlPortBase int, timeout time.Duration, reuseDataDir bool, autoPickPort bool, running map[int]struct{}, runningMu *sync.Mutex) error {
	var got bool
	if err := db.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", id).Scan(&got); err != nil {
		return fmt.Errorf("advisory lock error: %w", err)
	}
	if !got {
		return fmt.Errorf("bridge %d is already being checked", id)
	}
	defer func() {
		_, _ = db.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", id)
	}()

	var br BridgeRow
	row := db.QueryRowContext(ctx, `
	SELECT id, raw_line, host, port, fingerprint, url, sni_imitation, params, ver
	FROM bridges.bridges WHERE id = $1
	`, id)
	if err := row.Scan(&br.ID, &br.RawLine, &br.Host, &br.Port, &br.Fingerprint, &br.URL, &br.SNI, &br.Params, &br.Ver); err != nil {
		return fmt.Errorf("select bridge id=%d: %w", id, err)
	}

	return checkBridgeRow(ctx, db, br, baseTemplate, lyrebird, baseTmp, persistentDataDir, torPath, controlPortBase, timeout, reuseDataDir, autoPickPort, running, runningMu)
}

// fetchCandidates selects rows to check
func fetchCandidates(ctx context.Context, db *sql.DB, olderThan string, limit int, checkStatus string, checkType string, checkID int) ([]BridgeRow, error) {
	// validate checkStatus
	allowedStatus := map[string]bool{"alive": true, "dead": true, "timeout": true, "unknown": true, "all": true}
	if !allowedStatus[checkStatus] {
		return nil, fmt.Errorf("invalid check status: %s", checkStatus)
	}
	// validate checkType
	allowedType := map[string]bool{"obfs4": true, "webtunnel": true, "all": true}
	if !allowedType[checkType] {
		return nil, fmt.Errorf("invalid check type: %s", checkType)
	}

	var rows *sql.Rows
	var err error

	// build SQL depending on status/type
	if checkStatus == "all" && checkType == "all" {
		if limit <= 0 {
			rows, err = db.QueryContext(ctx, `
			SELECT id, raw_line, host, port, fingerprint, url, sni_imitation, params, ver
			FROM bridges.bridges
			WHERE last_checked_at IS NULL OR last_checked_at < now() - $1::interval
			ORDER BY last_checked_at NULLS FIRST
			`, olderThan)
		} else {
			rows, err = db.QueryContext(ctx, `
			SELECT id, raw_line, host, port, fingerprint, url, sni_imitation, params, ver
			FROM bridges.bridges
			WHERE last_checked_at IS NULL OR last_checked_at < now() - $1::interval
			ORDER BY last_checked_at NULLS FIRST
			LIMIT $2
			`, olderThan, limit)
		}
	} else if checkStatus == "all" && checkType != "all" {
		if limit <= 0 {
			rows, err = db.QueryContext(ctx, `
			SELECT id, raw_line, host, port, fingerprint, url, sni_imitation, params, ver
			FROM bridges.bridges
			WHERE (last_checked_at IS NULL OR last_checked_at < now() - $1::interval)
			AND type::text = $2
			ORDER BY last_checked_at NULLS FIRST
			`, olderThan, checkType)
		} else {
			rows, err = db.QueryContext(ctx, `
			SELECT id, raw_line, host, port, fingerprint, url, sni_imitation, params, ver
			FROM bridges.bridges
			WHERE (last_checked_at IS NULL OR last_checked_at < now() - $1::interval)
			AND type::text = $2
			ORDER BY last_checked_at NULLS FIRST
			LIMIT $3
			`, olderThan, checkType, limit)
		}
	} else if checkStatus != "all" && checkType == "all" {
		if limit <= 0 {
			rows, err = db.QueryContext(ctx, `
			SELECT id, raw_line, host, port, fingerprint, url, sni_imitation, params, ver
			FROM bridges.bridges
			WHERE (last_checked_at IS NULL OR last_checked_at < now() - $1::interval)
			AND status::text = $2
			ORDER BY last_checked_at NULLS FIRST
			`, olderThan, checkStatus)
		} else {
			rows, err = db.QueryContext(ctx, `
			SELECT id, raw_line, host, port, fingerprint, url, sni_imitation, params, ver
			FROM bridges.bridges
			WHERE (last_checked_at IS NULL OR last_checked_at < now() - $1::interval)
			AND status::text = $2
			ORDER BY last_checked_at NULLS FIRST
			LIMIT $3
			`, olderThan, checkStatus, limit)
		}
	} else {
		// both status and type specified
		if limit <= 0 {
			rows, err = db.QueryContext(ctx, `
			SELECT id, raw_line, host, port, fingerprint, url, sni_imitation, params, ver
			FROM bridges.bridges
			WHERE (last_checked_at IS NULL OR last_checked_at < now() - $1::interval)
			AND status::text = $2
			AND type::text = $3
			ORDER BY last_checked_at NULLS FIRST
			`, olderThan, checkStatus, checkType)
		} else {
			rows, err = db.QueryContext(ctx, `
			SELECT id, raw_line, host, port, fingerprint, url, sni_imitation, params, ver
			FROM bridges.bridges
			WHERE (last_checked_at IS NULL OR last_checked_at < now() - $1::interval)
			AND status::text = $2
			AND type::text = $3
			ORDER BY last_checked_at NULLS FIRST
			LIMIT $4
			`, olderThan, checkStatus, checkType, limit)
		}
	}

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []BridgeRow
	for rows.Next() {
		var r BridgeRow
		if err := rows.Scan(&r.ID, &r.RawLine, &r.Host, &r.Port, &r.Fingerprint, &r.URL, &r.SNI, &r.Params, &r.Ver); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// applyResult updates DB atomically
func applyResult(db *sql.DB, id int64, status string, latencyMs sql.NullInt64, notes string, isTimeout bool, countryCode, countryName, geoProvider, bridgeName string) error {
	// convert optional geo fields to sql.NullString
	cc := sql.NullString{String: countryCode, Valid: strings.TrimSpace(countryCode) != ""}
	cn := sql.NullString{String: countryName, Valid: strings.TrimSpace(countryName) != ""}
	gp := sql.NullString{String: geoProvider, Valid: strings.TrimSpace(geoProvider) != ""}
	bn := sql.NullString{String: bridgeName, Valid: strings.TrimSpace(bridgeName) != ""}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// main update: status, last_checked_at, latency_ms, notes, check_count, consecutive_timeouts, geo fields
	_, err = tx.Exec(`
	UPDATE bridges.bridges
	SET status = $1,
	last_checked_at = now(),
			 latency_ms = $2,
			 notes = $3,
			 check_count = COALESCE(check_count,0) + 1,
			 consecutive_timeouts = CASE WHEN $4 THEN COALESCE(consecutive_timeouts,0) + 1 ELSE 0 END,
			 country_code = $5,
			 country_name = $6,
			 geo_provider = $7,
			 bridge_name = $8
			 WHERE id = $9
			 `, status, latencyMs, notes, isTimeout, cc, cn, gp, bn, id)
	if err != nil {
		return err
	}

	// mark dead if too many consecutive timeouts (same transaction)
	_, err = tx.Exec(`
	UPDATE bridges.bridges
	SET status = 'dead'
	WHERE id = $1 AND COALESCE(consecutive_timeouts,0) >= 3
	`, id)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// backward-compatible wrapper: calls new applyResult with empty geo fields
func applyResultSimple(db *sql.DB, id int64, status string, latencyMs sql.NullInt64, notes string, isTimeout bool) error {
	return applyResult(db, id, status, latencyMs, notes, isTimeout, "", "", "", "")
}

// worker processes jobs from the jobs channel. It checks appCtx before starting each job and exits early if cancelled.
func worker(appCtx context.Context, id int, db *sql.DB, jobs <-chan BridgeRow, wg *sync.WaitGroup, baseTemplate, lyrebird, baseTmp string, running map[int]struct{}, runningMu *sync.Mutex) {
	defer wg.Done()
	// per-worker persistent dataDir if reuse enabled
	var persistentDataDir string
	if *reuseDataDir {
		ts := time.Now().UnixNano()
		persistentDataDir = filepath.Join(baseTmp, fmt.Sprintf("tor-worker-data-%d-%d", id, ts))
		_ = os.MkdirAll(persistentDataDir, 0700)
		// populate persistent dir from cache if requested
		if *dataSrcDir != "" {
			if err := populateDataDirFromCache(*dataSrcDir, persistentDataDir); err != nil {
				logf("worker %d populate persistent dataDir err: %v", id, err)
			} else {
				logf("worker %d populated persistent dataDir %s from cache %s", id, persistentDataDir, *dataSrcDir)
			}
		}
		logf("worker %d persistent dataDir %s", id, persistentDataDir)
	}
	for {
		select {
			case <-appCtx.Done():
				logf("worker %d received appCtx cancel, exiting", id)
				return
			case br, ok := <-jobs:
				if !ok {
					logf("worker %d jobs channel closed, exiting", id)
					return
				}
				logf("worker %d processing id=%d", id, br.ID)

				if err := checkBridgeByID(appCtx, db, br.ID, baseTemplate, *lyrebirdPlugin, baseTmp, persistentDataDir, *torPath, *controlPortBase, *timeout, *reuseDataDir, *autoPickPort, running, runningMu); err != nil {
					logf("worker %d: check id=%d error: %v", id, br.ID, err)
				}
		}
	}
}

// tryAdvisoryLock tries to acquire advisory lock and returns true if acquired.
func tryAdvisoryLock(db *sql.DB, key int64) (bool, error) {
	var got bool
	err := db.QueryRow("SELECT pg_try_advisory_lock($1)", key).Scan(&got)
	if err != nil {
		return false, err
	}
	return got, nil
}

// waitForAdvisoryLock waits until lock acquired or timeout reached.
// If timeout == 0, it blocks indefinitely using pg_advisory_lock.
func waitForAdvisoryLock(db *sql.DB, key int64, timeout time.Duration) (bool, error) {
	if timeout == 0 {
		_, err := db.Exec("SELECT pg_advisory_lock($1)", key)
		if err != nil {
			return false, err
		}
		return true, nil
	}

	deadline := time.Now().Add(timeout)
	backoff := 500 * time.Millisecond
	for {
		got, err := tryAdvisoryLock(db, key)
		if err != nil {
			return false, err
		}
		if got {
			return true, nil
		}
		if time.Now().After(deadline) {
			return false, nil // timeout
		}
		time.Sleep(backoff)
		if backoff < 5*time.Second {
			backoff *= 2
		}
	}
}


// releaseAdvisoryLock releases the lock.
func releaseAdvisoryLock(db *sql.DB, key int64) error {
	_, err := db.Exec("SELECT pg_advisory_unlock($1)", key)
	return err
}

// ----------------- main -----------------

func main() {
	flag.Parse()
	allowed := map[string]bool{"alive":true,"dead":true,"timeout":true,"unknown":true,"all":true}
	if !allowed[*checkStatus] {
		fmt.Printf("invalid -check value: %s\n", *checkStatus)
		os.Exit(1)
	}
	// Load env from file if needed (simple loader)
	// Expect DATABASE_URL and API_TOKEN in env
	if strings.TrimSpace(*dsn) == "" {
		if strings.TrimSpace(*envFile) != "" {
			if _, err := os.Stat(*envFile); err == nil {
				if err := loadEnvFile(*envFile); err != nil {
					log.Fatalf("failed to load env file %s: %v", *envFile, err)
				}
			} else {
				log.Printf("env file %q not found, will rely on -dsn or DATABASE_URL env", *envFile)
			}
		}
	}

	// priority: flag -dsn, then env DATABASE_URL
	dsn := strings.TrimSpace(*dsn)
	if dsn == "" {
		dsn = strings.TrimSpace(os.Getenv("DATABASE_URL"))
	}
	if dsn == "" {
		log.Fatal("DATABASE_URL not set and -dsn not provided")
	}
	if *baseTmpDir == "" {
		*baseTmpDir = os.TempDir()
	}

	// normalize lyrebird
	*lyrebirdPlugin = normalizeLyrebirdArg(*lyrebirdPlugin)

	// load torrc template if provided
	baseTemplate := DefaultTorrcTemplate
	if *torrcPath != "" {
		b, err := os.ReadFile(*torrcPath)
		if err != nil {
			fmt.Printf("read torrc %s: %v\n", *torrcPath, err)
			os.Exit(1)
		}
		baseTemplate = string(b)
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("db open: %v", err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		log.Fatalf("db ping: %v", err)
	}

	// application context that can be cancelled on shutdown
	appCtx, appCancel := context.WithCancel(context.Background())

	if *lockMethod == "pg" {
		if *waitForExisting {
			ok, err := waitForAdvisoryLock(db, *advisoryKey, *waitTimeout)
			if err != nil {
				fmt.Printf("advisory lock error: %v\n", err)
				os.Exit(1)
			}
			if !ok {
				fmt.Printf("could not acquire advisory lock within %v, exiting\n", *waitTimeout)
				os.Exit(2)
			}
			logf("acquired advisory lock key=%d", *advisoryKey)
		} else {
			got, err := tryAdvisoryLock(db, *advisoryKey)
			if err != nil {
				fmt.Printf("advisory lock try error: %v\n", err)
				os.Exit(1)
			}
			if !got {
				logf("another instance holds advisory lock key=%d, exiting", *advisoryKey)
				os.Exit(2)
			}
			logf("acquired advisory lock key=%d", *advisoryKey)
		}

		// ensure release on exit
		defer func() {
			if err := releaseAdvisoryLock(db, *advisoryKey); err != nil {
				logf("warning: failed to release advisory lock: %v", err)
			} else {
				logf("released advisory lock key=%d", *advisoryKey)
			}
		}()
	}

	// Load geoip files (if present)
	geoPath := *geoipPath
	geoFile := filepath.Join(geoPath, "geoip")
	geoFile6 := filepath.Join(geoPath, "geoip6")

	// reset structures before loading (CIDR lists + ranges)
	geoNetsV4CIDR = nil
	geoNetsV6CIDR = nil
	geoRangesV4 = nil
	geoRangesV6 = nil
	geoNetsCC = make(map[string]string)

	loaded := false
	if _, err := os.Stat(geoFile); err == nil {
		if err := loadGeoFlexible(geoFile); err != nil {
			logf("loadGeoFlexible %s: %v", geoFile, err)
		} else {
			v4Count := len(geoNetsV4CIDR) + len(geoRangesV4)
			v6Count := len(geoNetsV6CIDR) + len(geoRangesV6)
			logf("loaded geoip %s entries v4=%d v6=%d", geoFile, v4Count, v6Count)
			loaded = true
		}
	}
	if _, err := os.Stat(geoFile6); err == nil {
		if err := loadGeoFlexible(geoFile6); err != nil {
			logf("loadGeoFlexible %s: %v", geoFile6, err)
		} else {
			v4Count := len(geoNetsV4CIDR) + len(geoRangesV4)
			v6Count := len(geoNetsV6CIDR) + len(geoRangesV6)
			logf("loaded geoip6 %s entries v4=%d v6=%d", geoFile6, v4Count, v6Count)
			loaded = true
		}
	}
	if !loaded {
		logf("no geoip files found in %s; geo lookups will return ZZ", geoPath)
	}

	if *once && *checkID > 0 {
		log.Printf("single-run mode: checking id=%d", *checkID)

		persistentDataDir := ""
		createdPersistent := false
		if *reuseDataDir {
			ts := time.Now().UnixNano()
			persistentDataDir = filepath.Join(*baseTmpDir, fmt.Sprintf("tor-single-data-%d-%d", *checkID, ts))
			if err := os.MkdirAll(persistentDataDir, 0700); err != nil {
				log.Fatalf("failed to create persistent data dir %s: %v", persistentDataDir, err)
			}
			createdPersistent = true

			// populate from cache if requested
			if *dataSrcDir != "" {
				if err := populateDataDirFromCache(*dataSrcDir, persistentDataDir); err != nil {
					logf("populate persistent dataDir err: %v", err)
				} else {
					logf("populated persistent dataDir %s from cache %s", persistentDataDir, *dataSrcDir)
				}
			}
			logf("single-run persistent dataDir %s", persistentDataDir)
		}

		if createdPersistent {
			defer func() {
				if err := os.RemoveAll(persistentDataDir); err != nil {
					logf("warning: failed to remove persistent dataDir %s: %v", persistentDataDir, err)
				} else {
					logf("removed persistent dataDir %s", persistentDataDir)
				}
			}()
		}

		if err := checkBridgeByID(
			context.Background(),
					  db,
			    int64(*checkID),
					  baseTemplate,
			    *lyrebirdPlugin,
			    *baseTmpDir,
			    persistentDataDir,
			    *torPath,
			    *controlPortBase,
			    *timeout,
			    *reuseDataDir,
			    *autoPickPort,
			    globalRunning,
			    &globalRunningMu,
		); err != nil {
			log.Fatalf("check id=%d failed: %v", *checkID, err)
		}

		log.Printf("single-run id=%d finished, exiting", *checkID)
		return
	}

	// worker pool
	jobs := make(chan BridgeRow, *batchSize*2)
	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go worker(appCtx, i+1, db, jobs, &wg, baseTemplate, *lyrebirdPlugin, *baseTmpDir, globalRunning, &globalRunningMu)
	}

	// signal handling and interactive "qq" to quit
	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, syscall.SIGINT, syscall.SIGTERM)

	// also watch stdin for "qq" to quit quickly
	stdinStop := make(chan struct{})
	go func() {
		r := bufio.NewReader(os.Stdin)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				close(stdinStop)
				return
			}
			if strings.TrimSpace(line) == "qq" {
				close(stdinStop)
				return
			}
		}
	}()

	runOnceFunc := func() {
		if !isNetworkUp(2*time.Second) {
			logf("network unreachable — skipping this poll")
			return
		}
		cands, err := fetchCandidates(appCtx, db, *checkOlderThan, *batchSize, *checkStatus, *checkTypeFlag, *checkID)
		if err != nil {
			logf("fetchCandidates err: %v", err)
			return
		}
		if len(cands) == 0 {
			logf("no candidates")
			return
		}
		for _, r := range cands {
			select {
				case <-appCtx.Done():
					return
				default:
					jobs <- r
			}
		}
	}

	// initial run
	runOnceFunc()
	if *once {
		close(jobs)
		wg.Wait()
		return
	}

	ticker := time.NewTicker(*pollInterval)
	defer ticker.Stop()

	loop:
	for {
		select {
				case <-ticker.C:
					runOnceFunc()
				case <-stopCh:
					fmt.Println("received signal, shutting down...")
					break loop
				case <-stdinStop:
					fmt.Println("received 'qq' on stdin, shutting down...")
					break loop
		}
	}

	// stop accepting new jobs and notify workers
	// 1) cancel application context so workers stop taking new jobs immediately
	appCancel()

	// 2) close jobs channel so workers that are waiting on jobs exit after current work
	close(jobs)

	// 3) cancel all active monitors so goroutines stop polling control sockets
	globalRunningCancMu.Lock()
	for pid, cancel := range globalRunningCanc {
		logf("cancelling monitor for pid %d", pid)
		cancel()
		// keep entry removal to the runTorCheckWithTorrc defer/cleanup
		_ = pid
	}
	globalRunningCancMu.Unlock()

	// give monitors a short grace to exit and close sockets
	time.Sleep(500 * time.Millisecond)

	// 4) kill running tor instances gracefully (kill process groups)
	globalRunningMu.Lock()
	for pid := range globalRunning {
		logf("killing tor pid %d", pid)
		killProcessGroup(pid, 2*time.Second)
	}
	globalRunningMu.Unlock()

	// wait workers
	wg.Wait()
	fmt.Println("checker stopped")
}

// loadEnvFile reads simple KEY=VALUE lines and sets them into os.Environ
func loadEnvFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		// strip surrounding quotes if present
		if len(val) >= 2 && ((val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'')) {
			val = val[1 : len(val)-1]
		}
		os.Setenv(key, val)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}
