package adminauth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"portico-gateway/internal/session"
	"portico-gateway/internal/vault"
	"testing"
)

func TestPortalCookiesGroupsAndServerSideAccess(t *testing.T) {
	admin, p, c := setup(t)
	portal := *admin
	portal.basePath = "/portal"
	portal.groups = map[string]bool{"users": true}
	p.roles = []string{"users"}
	r := httptest.NewRequest("GET", portal.public+"/portal/", nil)
	r.AddCookie(&http.Cookie{Name: portal.sessionCookie(), Value: c})
	id, token, err := portal.Access(r)
	if err != nil || id.Subject != "user" || token != "secret" {
		t.Fatalf("access: %v %q %v", id, token, err)
	}
	_, csrfToken, err := portal.Authenticate(r)
	if err != nil || csrfToken == token || csrfToken == csrf(c) {
		t.Fatal("CSRF not isolated from admin/token", err)
	}
	if _, _, err = admin.Access(r); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("portal cookie accepted by admin", err)
	}
	if _, _, err = portal.Access(request(c)); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("admin cookie accepted by portal", err)
	}
	p.roles = []string{"admins", "users-other", "org/users"}
	if _, _, err = portal.Access(r); !errors.Is(err, ErrForbidden) {
		t.Fatal("portal role match not exact", err)
	}
}

func TestPortalFlowAADAndBindingSeparated(t *testing.T) {
	admin, _, _ := setup(t)
	portal := *admin
	portal.basePath = "/portal"
	v, _ := vault.New(make([]byte, 32))
	state := session.NewCredential()
	encrypted, err := v.Seal([]byte("flow"), admin.flowAAD(state))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = v.Open(encrypted, portal.flowAAD(state)); err == nil {
		t.Fatal("cross-purpose login flow decrypted")
	}
	binding := session.NewCredential()
	f := flow{Cookie: session.Hash(binding)}
	r := httptest.NewRequest("GET", portal.public+"/portal/callback", nil)
	r.AddCookie(&http.Cookie{Name: flowCookieName, Value: binding})
	if portal.bound(r, f) {
		t.Fatal("admin login cookie bound portal flow")
	}
	r = httptest.NewRequest("GET", portal.public+"/portal/callback", nil)
	r.AddCookie(&http.Cookie{Name: portal.loginCookie(), Value: binding})
	if !portal.bound(r, f) || admin.bound(r, f) {
		t.Fatal("portal login cookie isolation failed")
	}
}

func TestPortalLogoutUsesIsolatedCSRFAndRedirect(t *testing.T) {
	s, _, c := setup(t)
	s.basePath = "/portal"
	r := httptest.NewRequest("POST", s.public+"/portal/logout", nil)
	r.AddCookie(&http.Cookie{Name: s.sessionCookie(), Value: c})
	r.Header.Set("Origin", s.public)
	r.Header.Set("X-CSRF-Token", csrf(c))
	if s.CheckCSRF(r) {
		t.Fatal("admin CSRF accepted")
	}
	r.Header.Set("X-CSRF-Token", s.csrf(c))
	w := httptest.NewRecorder()
	s.Logout(w, r)
	if w.Code != 303 || w.Header().Get("Location") != "/portal/login" {
		t.Fatalf("logout %d %s", w.Code, w.Header().Get("Location"))
	}
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name != s.sessionCookie() && cookie.Name != s.loginCookie() {
			t.Fatal("cleared another session cookie")
		}
	}
}
