package toolbroker

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

const maxNetworkRedirects = 10

// IPResolver permits deterministic DNS tests while keeping resolution and
// dialing in the same security boundary.
type IPResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// ContextDialer is the minimum dialing capability required by NetworkBoundary.
type ContextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// NetworkBoundary validates URL targets, resolves every hostname before use,
// and dials only the validated address. It intentionally exposes HTTP rather
// than raw network access to network tool executors.
type NetworkBoundary struct {
	resolver IPResolver
	dialer   ContextDialer
}

func NewNetworkBoundary(resolver IPResolver, dialer ContextDialer) *NetworkBoundary {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	return &NetworkBoundary{resolver: resolver, dialer: dialer}
}

// Client returns an HTTP client constrained to the URL in parameters and its
// allowed origins. Every redirect is independently authorized, and DNS results
// are used directly for dialing so a later DNS rebinding cannot change the peer.
func (b *NetworkBoundary) Client(ctx context.Context, parameters []byte, allowedTargets []string) (*http.Client, error) {
	requested, err := networkURLFromParameters(parameters)
	if err != nil {
		return nil, err
	}
	allowed, err := parseAllowedTargets(allowedTargets)
	if err != nil {
		return nil, ErrNetworkDenied
	}
	binding := &networkBinding{boundary: b, allowed: allowed, endpoints: make(map[string][]netip.Addr)}
	if err := binding.authorize(ctx, requested); err != nil {
		return nil, err
	}
	transport := &http.Transport{
		Proxy:       nil,
		DialContext: binding.dialContext,
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= maxNetworkRedirects {
				return ErrNetworkDenied
			}
			return binding.authorize(request.Context(), request.URL)
		},
	}, nil
}

type networkBinding struct {
	boundary  *NetworkBoundary
	allowed   map[string]struct{}
	mu        sync.RWMutex
	endpoints map[string][]netip.Addr
}

func (b *networkBinding) authorize(ctx context.Context, target *url.URL) error {
	if target == nil || !allowedURL(target) {
		return ErrNetworkDenied
	}
	key := originKey(target)
	if _, ok := b.allowed[key]; !ok {
		return ErrNetworkDenied
	}
	addresses, err := b.resolve(ctx, target.Hostname())
	if err != nil {
		return ErrNetworkDenied
	}
	b.mu.Lock()
	b.endpoints[endpointKey(target.Hostname(), effectivePort(target))] = addresses
	b.mu.Unlock()
	return nil
}

func (b *networkBinding) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if forbiddenHostname(host) || ambiguousIPAddress(host) {
		return nil, ErrNetworkDenied
	}
	if address, err := netip.ParseAddr(host); err == nil {
		if address.String() != strings.ToLower(host) || forbiddenAddress(address) {
			return nil, ErrNetworkDenied
		}
		return []netip.Addr{address}, nil
	}
	addresses, err := b.boundary.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addresses) == 0 {
		return nil, ErrNetworkDenied
	}
	result := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		if !address.IsValid() || forbiddenAddress(address) {
			return nil, ErrNetworkDenied
		}
		result = append(result, address.Unmap())
	}
	return result, nil
}

func (b *networkBinding) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, ErrNetworkDenied
	}
	key := endpointKey(host, port)
	b.mu.RLock()
	addresses := append([]netip.Addr(nil), b.endpoints[key]...)
	b.mu.RUnlock()
	if len(addresses) == 0 {
		return nil, ErrNetworkDenied
	}
	var lastErr error
	for _, resolved := range addresses {
		connection, dialErr := b.boundary.dialer.DialContext(ctx, network, net.JoinHostPort(resolved.String(), port))
		if dialErr == nil {
			return connection, nil
		}
		lastErr = dialErr
	}
	if lastErr == nil {
		lastErr = ErrNetworkDenied
	}
	return nil, lastErr
}

func networkURLFromParameters(parameters []byte) (*url.URL, error) {
	var value struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(parameters, &value); err != nil || value.URL == "" {
		return nil, ErrNetworkDenied
	}
	parsed, err := url.Parse(value.URL)
	if err != nil || !allowedURL(parsed) {
		return nil, ErrNetworkDenied
	}
	return parsed, nil
}

func parseAllowedTargets(targets []string) (map[string]struct{}, error) {
	if len(targets) == 0 {
		return nil, errors.New("empty network target allowlist")
	}
	allowed := make(map[string]struct{}, len(targets))
	for _, rawTarget := range targets {
		parsed, err := url.Parse(rawTarget)
		if err != nil || !allowedURL(parsed) || parsed.Path != "" && parsed.Path != "/" || parsed.RawQuery != "" || parsed.Fragment != "" {
			return nil, ErrNetworkDenied
		}
		if forbiddenHostname(parsed.Hostname()) || ambiguousIPAddress(parsed.Hostname()) {
			return nil, ErrNetworkDenied
		}
		if address, parseErr := netip.ParseAddr(parsed.Hostname()); parseErr == nil && forbiddenAddress(address) {
			return nil, ErrNetworkDenied
		}
		if _, exists := allowed[originKey(parsed)]; exists {
			return nil, ErrNetworkDenied
		}
		allowed[originKey(parsed)] = struct{}{}
	}
	return allowed, nil
}

func validateNetworkTarget(target string) error {
	_, err := parseAllowedTargets([]string{target})
	return err
}

func allowedURL(value *url.URL) bool {
	if value == nil || value.User != nil || value.Hostname() == "" || value.Scheme != "http" && value.Scheme != "https" {
		return false
	}
	return value.Port() == "" || validPort(value.Port())
}

func validPort(port string) bool {
	value, err := strconv.ParseUint(port, 10, 16)
	return err == nil && value > 0
}

func originKey(value *url.URL) string {
	return originKeyForHostPort(value.Hostname(), effectivePort(value), value.Scheme)
}

func originKeyForHostPort(host, port, scheme string) string {
	host = strings.Trim(strings.ToLower(host), "[]")
	return scheme + "://" + endpointKey(host, port)
}

func endpointKey(host, port string) string {
	return net.JoinHostPort(strings.Trim(strings.ToLower(host), "[]"), port)
}

func effectivePort(value *url.URL) string {
	if port := value.Port(); port != "" {
		return port
	}
	if value.Scheme == "https" {
		return "443"
	}
	return "80"
}

func forbiddenHostname(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	switch host {
	case "metadata", "metadata.google.internal", "instance-data", "instance-data.ec2.internal":
		return true
	default:
		return false
	}
}

func ambiguousIPAddress(host string) bool {
	if host == "" || strings.Contains(host, ":") || host[0] < '0' || host[0] > '9' {
		return false
	}
	for _, character := range host {
		if character == '.' || character >= '0' && character <= '9' || character == 'x' || character == 'X' || character >= 'a' && character <= 'f' || character >= 'A' && character <= 'F' {
			continue
		}
		if character != '.' {
			return false
		}
	}
	return net.ParseIP(host) == nil
}

func forbiddenAddress(address netip.Addr) bool {
	address = address.Unmap()
	if address.Is4() {
		for _, prefix := range blockedIPv4Prefixes {
			if prefix.Contains(address) {
				return true
			}
		}
		return false
	}
	for _, prefix := range blockedIPv6Prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

var blockedIPv4Prefixes = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
	"192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
	"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
)

var blockedIPv6Prefixes = mustPrefixes(
	"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32",
)

func mustPrefixes(values ...string) []netip.Prefix {
	result := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		result = append(result, netip.MustParsePrefix(value))
	}
	return result
}
