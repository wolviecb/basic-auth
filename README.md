HTTP Authentication implementation in Go
========================================

This is an implementation of HTTP Basic in Go language. Which is basically a mash-up of [abbot/go-http-auth](https://github.com/abbot/go-http-auth) and [GehirnInc/crypt](https://github.com/GehirnInc/crypt)

Features
--------

* Supports HTTP Basic
* Supports htpasswd formatted files.
* Automatic reloading of password files.
* Pluggable interface for user/password storage.
* Supports MD5, SHA1 and BCrypt for Basic authentication password storage.
* Configurable Digest nonce cache size with expiration.
* Wrapper for legacy http handlers (http.HandlerFunc interface)

Example usage
-------------

This is a complete working example for Basic auth:

    package main

    import (
            "fmt"
            "net/http"

            auth "github.com/woliecb/basic-auth"
    )

    func Secret(user, realm string) string {
            if user == "john" {
                    // password is "hello"
                    return "$apr1$Xfu5Jqwg$DYvBqzdcW84tnuq5SbnZE/"
            }
            return ""
    }

    func handle(w http.ResponseWriter, r *auth.AuthenticatedRequest) {
            fmt.Fprintf(w, "<html><body><h1>Hello, %s!</h1></body></html>", r.Username)
    }

    func main() {
            authenticator := auth.NewBasicAuthenticator("example.com", Secret)
            http.HandleFunc("/", authenticator.Wrap(handle))
            http.ListenAndServe(":8080", nil)
    }

See more examples in the "examples" directory.
