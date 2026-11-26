package webapi

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net/http"
	"net/url"
	"os/exec"
	"time"
)

func certificateStatus(path string) map[string]any {
	block, _ := pem.Decode(readRegularTail(path, 256*1024, false))
	if block == nil || block.Type != "CERTIFICATE" {
		return map[string]any{}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return map[string]any{}
	}

	sans := [][2]string{}
	for _, name := range cert.DNSNames {
		sans = append(sans, [2]string{"DNS", name})
	}
	for _, ip := range cert.IPAddresses {
		sans = append(sans, [2]string{"IP Address", ip.String()})
	}
	for _, address := range cert.EmailAddresses {
		sans = append(sans, [2]string{"email", address})
	}
	for _, uri := range cert.URIs {
		sans = append(sans, [2]string{"URI", uri.String()})
	}
	return map[string]any{
		"subject": certificateName(cert.Subject), "issuer": certificateName(cert.Issuer),
		"notAfter": cert.NotAfter.UTC(), "sans": sans,
	}
}

func certificateName(name pkix.Name) map[string]string {
	fields := map[string]string{
		"2.5.4.3": "commonName", "2.5.4.5": "serialNumber", "2.5.4.6": "countryName",
		"2.5.4.7": "localityName", "2.5.4.8": "stateOrProvinceName", "2.5.4.9": "streetAddress",
		"2.5.4.10": "organizationName", "2.5.4.11": "organizationalUnitName",
	}
	result := map[string]string{}
	for _, entry := range name.Names {
		field := fields[entry.Type.String()]
		if value, ok := entry.Value.(string); ok && field != "" {
			result[field] = value
		}
	}
	return result
}

func systemStatus(ctx context.Context, env map[string]string) map[string]any {
	commands := []struct {
		name, binary, arg string
	}{{"domainTrust", "wbinfo", "-t"}, {"sambaConfig", "testparm", "-s"}}
	checks := map[string]bool{}
	for _, command := range commands {
		check, cancel := context.WithTimeout(ctx, 10*time.Second)
		checks[command.name] = exec.CommandContext(check, command.binary, command.arg).Run() == nil
		cancel()
	}
	return map[string]any{
		"hostname": env["WEB_HOSTNAME"], "checks": checks,
		"tls": certificateStatus(env["WEB_TLS_CERT_FILE"]), "serverTime": time.Now().UTC().Truncate(time.Second),
	}
}

func (api AdminAPI) status(w http.ResponseWriter, r *http.Request, path string, params url.Values) {
	ctx := r.Context()
	switch path {
	case "groups":
		result, err := api.Access.Report(ctx)
		adminResult(w, result, err)
		return
	case "storage":
		writeJSON(w, http.StatusOK, api.Usage.snapshot(ctx))
		return
	}

	snapshot, err := api.Config.Snapshot(ctx)
	if err != nil {
		adminResult(w, nil, err)
		return
	}
	env, err := api.Config.Environment(snapshot, false)
	if err != nil {
		adminResult(w, nil, err)
		return
	}

	switch path {
	case "backup":
		writeJSON(w, http.StatusOK, backupStatus(snapshot, env, includeLog(params)))
	case "reconciliation":
		writeJSON(w, http.StatusOK, reconciliationStatus(env, includeLog(params)))
	case "overview":
		api.overview(w, ctx, snapshot, env)
	case "system":
		value := systemStatus(ctx, env)
		value["audit"], _ = api.Audit.Summary(ctx, env["STATE_DB_PATH"])
		value["usage"] = api.Usage.snapshot(ctx)
		writeJSON(w, http.StatusOK, value)
	case "report":
		groups, err := api.Access.Report(ctx)
		if err != nil {
			adminResult(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"generatedAt": time.Now().UTC().Truncate(time.Second), "groups": groups,
			"storage": api.Usage.snapshot(ctx), "backup": backupStatus(snapshot, env, false),
			"system": systemStatus(ctx, env),
		})
	}
}
