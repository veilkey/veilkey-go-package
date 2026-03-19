package agentapi

// localvault API path constants.
// Used by both localvault (route registration) and vaultcenter (agent HTTP client).
const (
	PathSecrets      = "/api/secrets"
	PathSecretMeta   = "/api/secrets/meta"
	PathSecretFields = "/api/secrets/fields"
	PathCipher       = "/api/cipher"
	PathResolve      = "/api/resolve"
	PathRekey        = "/api/rekey"
	PathConfigs      = "/api/configs"
	PathConfigsBulk  = "/api/configs/bulk"
	PathNodeInfo     = "/api/node-info"

	// DefaultPort is the default TCP port for localvault agent HTTP listeners.
	DefaultPort = 10180
)

// vaultcenter API path constants.
// Used by both vaultcenter (route registration) and localvault (client calls).
const (
	PathRegistrationTokenValidate = "/api/registration-tokens/"
)
