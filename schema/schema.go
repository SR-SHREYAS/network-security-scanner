package schema

type PortState string

const (
	StateOpen     PortState = "open"
	StateClosed   PortState = "closed"
	StateFiltered PortState = "filtered"
	StateError    PortState = "error"
)

type RiskLevel string

const (
	RiskCritical RiskLevel = "critical"
	RiskHigh     RiskLevel = "high"
	RiskMedium   RiskLevel = "medium"
	RiskLow      RiskLevel = "low"
	RiskInfo     RiskLevel = "info"
)

// ScanResult holds the findings for a single port
type ScanResult struct {
	Port      int       `json:"port"`
	State     PortState `json:"state"`
	Service   string    `json:"service"`
	Banner    string    `json:"banner"`
	RiskLevel RiskLevel `json:"risk_level"`
	Reason    string    `json:"reason"`
}

type RiskSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

func (rs *RiskSummary) Add(level RiskLevel) {
	switch level {
	case RiskCritical:
		rs.Critical++
	case RiskHigh:
		rs.High++
	case RiskMedium:
		rs.Medium++
	case RiskLow:
		rs.Low++
	case RiskInfo:
		rs.Info++
	}
}

type Exposure string

const (
	ExposureLoopback Exposure = "loopback"
	ExposurePrivate  Exposure = "private"
	ExposurePublic   Exposure = "public"
)

type ScanReport struct {
	Target        string       `json:"target"`
	ResolvedIP    string       `json:"resolved_ip"`
	Exposure      Exposure     `json:"exposure"`
	ScanTime      string       `json:"scan_time"`
	Duration      string       `json:"duration"`
	TotalPorts    int          `json:"total_ports"`
	OpenPorts     int          `json:"open_ports"`
	ClosedPorts   int          `json:"closed_ports"`
	FilteredPorts int          `json:"filtered_ports"`
	ErrorPorts    int          `json:"error_ports"`
	HostStatus    Host         `json:"host_status"`
	RiskSummary   RiskSummary  `json:"risk_summary"`
	Results       []ScanResult `json:"results"`
}

// Common ports
var CommonPorts = []int{
	21, 22, 23, 25, 80, 110, 135, 139,
	443, 445, 993, 995, 1433, 3306,
	3389, 5432, 6379, 8080, 8443,
}

// Maps port numbers to their known service names
var ServiceMap = map[int]string{
	21:   "FTP",
	22:   "SSH",
	23:   "Telnet",
	25:   "SMTP",
	80:   "HTTP",
	110:  "POP3",
	135:  "MS RPC",
	139:  "NetBIOS",
	443:  "HTTPS",
	445:  "SMB",
	993:  "IMAPS",
	995:  "POP3S",
	1433: "MSSQL",
	3306: "MySQL",
	3389: "RDP",
	5432: "PostgreSQL",
	6379: "Redis",
	8080: "HTTP-Alt",
	8443: "HTTPS-Alt",
}

type Host string

const (
	HostUp         Host = "up"
	HostDown       Host = "down"
	HostNoResponse Host = "no_response"
)
