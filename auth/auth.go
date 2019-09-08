package whitelister

import (
	"net/http"
)

type WhiteLister interface {
	// Check is used to determine if a client is to be authorized by the WhiteLister.
	// The interface is sent by an authentication method, it may contain a password or
	//  a message encrypted for the server and signed with a private key.
	// The string is a base64 string to whitelist if the authentication passes.
	// The first string it returns should be the base64 of the client to be whitelisted.
	// The second interface may be used to pass information from the whitelister to another
	//  routine but is optional
	// The final bool should be true if the client is to be whitelisted, false if it is
	//  not authorized.
	Check(interface{}) (string, interface{}, bool)
	// Whitelist returns the stored client whitelist
	Whitelist() []string
	// ServeHTTP implements an HTTP handler that does the login stuff
	ServeHTTP(http.ResponseWriter, *http.Request)
    // String returns a string to be used for identifying the auth method in use
    // to the server so it can expose it to the admin
    String() string
}
