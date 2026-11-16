package risk

import "github.com/SR-SHREYAS/network-security-scanner.git/schema"

type Rule struct {
	Level  schema.RiskLevel
	Reason string
}

// rules is keyed by service name, so banner-based detection feeds the rating.
var rules = map[string]Rule{
	"Telnet":     {schema.RiskCritical, "Unencrypted remote shell; credentials travel in plaintext."},
	"FTP":        {schema.RiskCritical, "Unencrypted file transfer; credentials travel in plaintext."},
	"RDP":        {schema.RiskHigh, "Remote desktop is a frequent target of brute force and exploits when exposed."},
	"SMB":        {schema.RiskHigh, "File sharing protocol with a history of wormable vulnerabilities."},
	"Redis":      {schema.RiskHigh, "Often runs without authentication; exposure can mean data theft or code execution."},
	"POP3":       {schema.RiskHigh, "Unencrypted mail retrieval; credentials travel in plaintext."},
	"HTTP":       {schema.RiskHigh, "Unencrypted web traffic; verify whether it should be reachable."},
	"HTTP-Alt":   {schema.RiskHigh, "Unencrypted web traffic on a non-standard port; often admin or dev tooling."},
	"PostgreSQL": {schema.RiskMedium, "Database should not be directly reachable from untrusted networks."},
	"MySQL":      {schema.RiskMedium, "Database should not be directly reachable from untrusted networks."},
	"MSSQL":      {schema.RiskMedium, "Database should not be directly reachable from untrusted networks."},
	"MS RPC":     {schema.RiskMedium, "Windows RPC endpoint; should not be exposed beyond the local network."},
	"NetBIOS":    {schema.RiskMedium, "Legacy Windows networking; leaks host information."},
	"SMTP":       {schema.RiskMedium, "Mail server; check it is not an open relay."},
	"SSH":        {schema.RiskLow, "Encrypted remote access; ensure key-based auth and no weak passwords."},
	"HTTPS":      {schema.RiskLow, "Encrypted web traffic."},
	"HTTPS-Alt":  {schema.RiskLow, "Encrypted web traffic on a non-standard port."},
	"IMAPS":      {schema.RiskLow, "Encrypted mail access."},
	"POP3S":      {schema.RiskLow, "Encrypted mail retrieval."},
}

// Classify returns the risk level and the reason for a service name.
func Classify(service string) (schema.RiskLevel, string) {
	if r, ok := rules[service]; ok {
		return r.Level, r.Reason
	}
	return schema.RiskInfo, "No rule for this service; review manually."
}

// Has reports whether an explicit rule exists for the service.
func Has(service string) bool {
	_, ok := rules[service]
	return ok
}
