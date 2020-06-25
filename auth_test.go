package auth

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"golang.org/x/net/context"
)

func TestUpdateHeaders(t *testing.T) {
	tt := []struct {
		name string
		i    *Info
		h    http.Header
		r    http.Header
	}{
		{
			"nil",
			nil,
			nil,
			nil,
		},
		{
			"simple",
			&Info{
				false,
				"test",
				http.Header{
					"Key": {"value"},
				},
			},
			http.Header{
				"A_key": {"a_value"},
			},
			http.Header{
				"Key":   {"value"},
				"A_key": {"a_value"},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			tc.i.UpdateHeaders(tc.h)
			if !reflect.DeepEqual(tc.r, tc.h) {
				t.Fatalf("expected %+v, got %+v", tc.r, tc.h)
			}
		})
	}
}

func TestFromContext(t *testing.T) {
	tt := []struct {
		name string
		i    context.Context
		r    *Info
	}{
		{
			"nil",
			context.TODO(),
			nil,
		},
		{
			"Unauthenticated",
			context.Background(),
			nil,
		},
		{
			"Authenticated",
			context.WithValue(context.Background(), infoKey, &Info{
				Authenticated:   true,
				Username:        "test",
				ResponseHeaders: http.Header{},
			}),
			&Info{
				Authenticated:   true,
				Username:        "test",
				ResponseHeaders: http.Header{},
			},
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			r := FromContext(tc.i)
			if !reflect.DeepEqual(tc.r, r) {
				t.Fatalf("expected %+v, got %+v", tc.r, r)
			}
		})
	}
}

func secret(user, realm string) string {
	if user == "john" {
		// password is "hello"
		return "$apr1$Xfu5Jqwg$DYvBqzdcW84tnuq5SbnZE/"
	}
	return ""
}

func regularHandler(w http.ResponseWriter, r *http.Request) {}

func TestJustCheck(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer ts.Close()
	tt := []struct {
		name string
		a    AuthenticatorInterface
		w    http.HandlerFunc
		u    string
		p    string
		r    int
	}{
		{
			"Denied",
			NewBasicAuthenticator("test.com", secret),
			regularHandler,
			"",
			"",
			401,
		},
		{
			"Good",
			NewBasicAuthenticator("test.com", secret),
			regularHandler,
			"john",
			"hello",
			200,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(JustCheck(tc.a, tc.w)))
			defer ts.Close()
			req, _ := http.NewRequest("GET", ts.URL, nil)
			req.SetBasicAuth(tc.u, tc.p)
			c := &http.Client{}
			r, err := c.Do(req)
			if err != nil {
				t.Fatalf("Err, %v", err)
			}
			defer r.Body.Close()

			if !reflect.DeepEqual(tc.r, r.StatusCode) {
				t.Fatalf("expected %+v, got %+v", tc.r, r)
			}
		})
	}
}
