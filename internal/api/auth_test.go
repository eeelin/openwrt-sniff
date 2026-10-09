package api

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/eeelin/openwrt-sniff/internal/capture"
	"github.com/eeelin/openwrt-sniff/internal/flow"
)

const testAuthToken = "0123456789abcdef0123456789abcdef0123456789abcdef"

func TestTokenLoginProtectsAPI(t *testing.T) {
	store := flow.NewStore(16, time.Minute)
	manager := capture.NewManager(nil, []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, 1024, store, nil)
	handler := New(store, manager, "test", testAuthToken)

	request := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status code = %d", response.Code)
	}
	if response.Header().Get("Content-Security-Policy") == "" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("security headers were not added")
	}

	cookie := login(t, handler, testAuthToken)
	request = httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	request.AddCookie(cookie)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("authenticated status code = %d: %s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodDelete, "/api/v1/flows", nil)
	request.AddCookie(cookie)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("cross-site protection code = %d", response.Code)
	}

	request = httptest.NewRequest(http.MethodDelete, "/api/v1/flows", nil)
	request.Host = "router.lan:8088"
	request.Header.Set("Origin", "http://router.lan:8088")
	request.AddCookie(cookie)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("same-origin request code = %d: %s", response.Code, response.Body.String())
	}
}

func TestLoginRejectsInvalidTokenAndOrigin(t *testing.T) {
	handler := New(flow.NewStore(4, time.Minute), capture.NewManager(nil, nil, 1024, flow.NewStore(4, time.Minute), nil), "test", testAuthToken)

	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"token":"wrong"}`))
	request.Host = "router.lan"
	request.Header.Set("Origin", "http://router.lan")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("invalid token code = %d", response.Code)
	}

	request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"token":"`+testAuthToken+`"}`))
	request.Host = "router.lan"
	request.Header.Set("Origin", "http://attacker.invalid")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("cross-origin login code = %d", response.Code)
	}
}

func TestTamperedSessionIsRejected(t *testing.T) {
	store := flow.NewStore(4, time.Minute)
	handler := New(store, capture.NewManager(nil, nil, 1024, store, nil), "test", testAuthToken)
	cookie := login(t, handler, testAuthToken)
	cookie.Value += "x"
	request := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("tampered session code = %d", response.Code)
	}
}

func login(t *testing.T, handler http.Handler, token string) *http.Cookie {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"token":"`+token+`"}`))
	request.Host = "router.lan:8088"
	request.Header.Set("Origin", "http://router.lan:8088")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("login code = %d: %s", response.Code, response.Body.String())
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("unexpected session cookie: %+v", cookies)
	}
	return cookies[0]
}
