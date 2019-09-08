package whitelister

type Credentials struct {
	Password string `json:"password"`
	Username string `json:"username"`
	Base64   string `json:"base64"`
}

type AdminCredentials struct {
	Password string `json:"password"`
	Username string `json:"username"`
	NewUser  string `json:"newusername"`
	NewPass  string `json:"newpassword"`
}
