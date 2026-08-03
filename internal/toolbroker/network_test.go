package toolbroker

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type fakeResolver struct {
	mu        sync.Mutex
	answers   map[string][]netip.Addr
	lookups   []string
	lookupErr error
}

func (r *fakeResolver) LookupNetIP(_ context.Context, _ string, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lookups = append(r.lookups, host)
	if r.lookupErr != nil {
		return nil, r.lookupErr
	}
	return append([]netip.Addr(nil), r.answers[host]...), nil
}

type fakeDialer struct {
	mu        sync.Mutex
	addresses []string
}

func (d *fakeDialer) DialContext(_ context.Context, _ string, address string) (net.Conn, error) {
	d.mu.Lock()
	d.addresses = append(d.addresses, address)
	d.mu.Unlock()
	return nil, errors.New("dial stopped")
}

func TestNetworkBoundaryRejectsPrivateLoopbackMetadataAndAmbiguousIPs(t *testing.T) {
	resolver := &fakeResolver{answers: map[string][]netip.Addr{"public.test": {netip.MustParseAddr("93.184.216.34")}}}
	boundary := NewNetworkBoundary(resolver, &fakeDialer{})
	targets := []string{"http://public.test"}

	for _, rawURL := range []string{
		"http://127.0.0.1/",
		"http://10.0.0.1/",
		"http://[::1]/",
		"http://[::ffff:127.0.0.1]/",
		"http://169.254.169.254/latest/meta-data/",
		"http://100.100.100.200/latest/meta-data/",
		"http://metadata.google.internal/computeMetadata/v1/",
		"http://instance-data.ec2.internal/latest/",
		"http://2130706433/",
		"http://0177.0.0.1/",
		"http://0x7f000001/",
	} {
		parameters := []byte(`{"url":"` + rawURL + `"}`)
		if _, err := boundary.Client(context.Background(), parameters, targets); !errors.Is(err, ErrNetworkDenied) {
			t.Fatalf("Client(%q) error = %v, want ErrNetworkDenied", rawURL, err)
		}
	}
}

func TestNetworkToolDescriptorRejectsUnsafeOrUnboundedDestinations(t *testing.T) {
	for _, target := range []string{
		"http://127.0.0.1",
		"http://metadata.google.internal",
		"http://2130706433",
		"http://public.test/path",
		"https://public.test?query=value",
	} {
		d := descriptor()
		d.NetworkAccess = NetworkAllowlist
		d.AllowedNetworkTargets = []string{target}
		if err := d.Validate(); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("Validate(%q) error = %v, want ErrInvalidRequest", target, err)
		}
	}
	d := descriptor()
	d.NetworkAccess = NetworkOpen
	if err := d.Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("NetworkOpen descriptor error = %v, want ErrInvalidRequest", err)
	}
}

func TestNetworkBoundaryRejectsPrivateDNSAndBindsValidatedAddress(t *testing.T) {
	resolver := &fakeResolver{answers: map[string][]netip.Addr{
		"rebind.test":  {netip.MustParseAddr("93.184.216.34")},
		"private.test": {netip.MustParseAddr("127.0.0.1")},
	}}
	dialer := &fakeDialer{}
	boundary := NewNetworkBoundary(resolver, dialer)

	if _, err := boundary.Client(context.Background(), []byte(`{"url":"http://private.test/"}`), []string{"http://private.test"}); !errors.Is(err, ErrNetworkDenied) {
		t.Fatalf("private DNS error = %v, want ErrNetworkDenied", err)
	}
	client, err := boundary.Client(context.Background(), []byte(`{"url":"http://rebind.test/"}`), []string{"http://rebind.test"})
	if err != nil {
		t.Fatal(err)
	}
	resolver.answers["rebind.test"] = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	transport := client.Transport.(*http.Transport)
	if _, err := transport.DialContext(context.Background(), "tcp", "rebind.test:80"); err == nil {
		t.Fatal("DialContext unexpectedly succeeded")
	}
	if len(dialer.addresses) != 1 || dialer.addresses[0] != "93.184.216.34:80" {
		t.Fatalf("dial addresses = %#v, want the address resolved before rebinding", dialer.addresses)
	}
}

func TestNetworkBoundaryValidatesEveryRedirect(t *testing.T) {
	resolver := &fakeResolver{answers: map[string][]netip.Addr{
		"public.test":   {netip.MustParseAddr("93.184.216.34")},
		"redirect.test": {netip.MustParseAddr("93.184.216.35")},
	}}
	boundary := NewNetworkBoundary(resolver, &fakeDialer{})
	client, err := boundary.Client(context.Background(), []byte(`{"url":"https://public.test/"}`), []string{"https://public.test", "https://redirect.test"})
	if err != nil {
		t.Fatal(err)
	}
	blocked, err := http.NewRequest(http.MethodGet, "http://127.0.0.1/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CheckRedirect(blocked, nil); !errors.Is(err, ErrNetworkDenied) {
		t.Fatalf("private redirect error = %v, want ErrNetworkDenied", err)
	}
	notAllowed, err := http.NewRequest(http.MethodGet, "https://other.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CheckRedirect(notAllowed, nil); !errors.Is(err, ErrNetworkDenied) {
		t.Fatalf("unallowlisted redirect error = %v, want ErrNetworkDenied", err)
	}
	allowed, err := http.NewRequest(http.MethodGet, "https://redirect.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CheckRedirect(allowed, nil); err != nil {
		t.Fatalf("allowlisted redirect error = %v", err)
	}
}

type networkExecutor struct {
	standardCalls int
	networkCalls  int
}

func (e *networkExecutor) Execute(context.Context, ToolDescriptor, []byte) ([]byte, error) {
	e.standardCalls++
	return nil, errors.New("network tool used the unrestricted executor")
}

func (e *networkExecutor) ExecuteNetwork(_ context.Context, _ ToolDescriptor, _ []byte, client *http.Client) ([]byte, error) {
	if client == nil || client.Transport == nil {
		return nil, errors.New("missing constrained client")
	}
	e.networkCalls++
	return []byte(`{"ok":true}`), nil
}

func TestBrokerRequiresBoundNetworkExecutor(t *testing.T) {
	d := descriptor()
	d.ToolID = "web.fetch"
	d.NetworkAccess = NetworkAllowlist
	d.AllowedNetworkTargets = []string{"https://public.test"}
	resolver := &fakeResolver{answers: map[string][]netip.Addr{"public.test": {netip.MustParseAddr("93.184.216.34")}}}
	executor := &networkExecutor{}
	broker := NewWithNetworkBoundary(&testLease{}, testPolicy{}, executor, nil, &testRecorder{}, nil, NewNetworkBoundary(resolver, &fakeDialer{}), func() time.Time { return brokerTestNow })
	if err := broker.Register(d); err != nil {
		t.Fatal(err)
	}
	call := request()
	call.ToolID = d.ToolID
	call.Parameters = []byte(`{"url":"https://public.test/"}`)
	result, err := broker.Invoke(context.Background(), call)
	if err != nil || string(result.Output) != `{"ok":true}` || executor.networkCalls != 1 || executor.standardCalls != 0 {
		t.Fatalf("result=%#v err=%v networkCalls=%d standardCalls=%d", result, err, executor.networkCalls, executor.standardCalls)
	}

	unbound := NewWithNetworkBoundary(&testLease{}, testPolicy{}, &testExecutor{}, nil, &testRecorder{}, nil, NewNetworkBoundary(resolver, &fakeDialer{}), func() time.Time { return brokerTestNow })
	if err := unbound.Register(d); err != nil {
		t.Fatal(err)
	}
	if _, err := unbound.Invoke(context.Background(), call); !errors.Is(err, ErrNetworkDenied) {
		t.Fatalf("unbound executor error = %v, want ErrNetworkDenied", err)
	}
}
