package schema

// ScanResult holds the findings for a single port
type ScanResult struct {
	Port    int    `json:"port"`
	State   string `json:"state"`
	Service string `json:"service"`
	Banner  string `json:"banner"`
}

// Common ports
var CommonPorts = []int{
	22, 23, 25, 80, 110, 135, 139,
	443, 445, 993, 995, 1433, 3306,
	3389, 5432, 8080, 8443,
}

// Maps port numbers to their known service names
var ServiceMap = map[int]string{
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
	8080: "HTTP-Alt",
	8443: "HTTPS-Alt",
}
