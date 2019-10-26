// +build ignore
// (C) Modifications copyright 2019, Tom Andrade <wolvie@gmail.com>

/*
 Example application using NewContext/FromContext

 Build with:

 go build context.go
*/

package main

import (
	"fmt"
	"net/http"

	auth ".."
	"golang.org/x/net/context"
)

func secret(user, realm string) string {
	if user == "john" {
		// password is "hello"
		return "$apr1$Xfu5Jqwg$DYvBqzdcW84tnuq5SbnZE/"
	}
	return ""
}

type contextHandler interface {
	ServeHTTP(ctx context.Context, w http.ResponseWriter, r *http.Request)
}

type contextHandlerFunc func(ctx context.Context, w http.ResponseWriter, r *http.Request)

func (f contextHandlerFunc) ServeHTTP(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	f(ctx, w, r)
}

func handle(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	authInfo := auth.FromContext(ctx)
	authInfo.UpdateHeaders(w.Header())
	if authInfo == nil || !authInfo.Authenticated {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	fmt.Fprintf(w, "<html><body><h1>Hello, %s!</h1></body></html>", authInfo.Username)
}

func authenticatedHandler(a auth.AuthenticatorInterface, h contextHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := a.NewContext(context.Background(), r)
		h.ServeHTTP(ctx, w, r)
	})
}

func main() {
	authenticator := auth.NewBasicAuthenticator("example.com", secret)
	http.Handle("/", authenticatedHandler(authenticator, contextHandlerFunc(handle)))
	http.ListenAndServe(":8080", nil)
}
