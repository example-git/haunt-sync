package service

import (
	"errors"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type Config struct {
	Issuer            string
	DatabaseURL       string
	Schema            string
	AllowLoopbackHTTP bool
	SMTPHost          string
	SMTPPort          string
	SMTPUsername      string
	SMTPPassword      string
	SMTPCAFile        string
	MailFrom          string
	TrustedProxies    string
	UpdatesDirectory  string
	proxies           []netip.Prefix
}

func Origin(raw string, loopback bool) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || u.RawPath != "" {
		return "", errors.New("use an HTTPS origin without a path, credentials, query or fragment")
	}
	if u.Scheme != "https" && !(loopback && u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1")) {
		return "", errors.New("HTTPS is required; explicit loopback HTTP is for local verification only")
	}
	if strings.ToLower(u.Host) != u.Host || u.Opaque != "" || strings.ContainsAny(u.Host, "\\\r\n\x00") {
		return "", errors.New("invalid or noncanonical origin")
	}
	if u.Port() == "443" && u.Scheme == "https" {
		return "", errors.New("omit the default HTTPS port")
	}
	if port := u.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 || strconv.Itoa(value) != port {
			return "", errors.New("invalid origin port")
		}
	}
	return u.Scheme + "://" + u.Host, nil
}

func (c *Config) Validate() error {
	var err error
	if c.Issuer, err = Origin(c.Issuer, c.AllowLoopbackHTTP); err != nil {
		return err
	}
	if c.DatabaseURL == "" {
		return errors.New("HAUNT_SYNC_DATABASE_URL is required")
	}
	if c.UpdatesDirectory != "" {
		root, err := os.OpenRoot(c.UpdatesDirectory)
		if err != nil {
			return errors.New("HAUNT_SYNC_UPDATES_DIR must name a readable release directory")
		}
		root.Close()
	}
	if c.Schema == "" {
		c.Schema = "haunt_sync"
	}
	if !regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`).MatchString(c.Schema) {
		return errors.New("invalid database schema")
	}
	if c.SMTPHost != "" {
		if c.SMTPPort == "" {
			c.SMTPPort = "587"
		}
		value, err := strconv.Atoi(c.SMTPPort)
		if err != nil || value < 1 || value > 65535 || strconv.Itoa(value) != c.SMTPPort {
			return errors.New("invalid SMTP port")
		}
		if _, err := emailAddress(c.MailFrom); err != nil {
			return errors.New("a valid HAUNT_SYNC_MAIL_FROM is required for SMTP")
		}
		if strings.ContainsAny(c.SMTPHost+c.SMTPPort+c.SMTPUsername, "\r\n\x00") {
			return errors.New("invalid SMTP configuration")
		}
	}
	c.proxies = nil
	for _, value := range strings.Split(c.TrustedProxies, ",") {
		if value == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			return errors.New("invalid trusted proxy CIDR")
		}
		c.proxies = append(c.proxies, prefix)
	}
	return nil
}
