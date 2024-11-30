package jasminauth

type Provider string

type User struct {
	Id         string                 `json:"id"`
	Provider   Provider               `json:"provider"`
	ProviderId Provider               `json:"providerId"`
	Domain     string                 `json:"domain"`
	Username   string                 `json:"username"`
	CreatedAt  int64                  `json:"createdAt"` // unix epoch time
	Contents   map[string]interface{} `json:"contents"`
}
