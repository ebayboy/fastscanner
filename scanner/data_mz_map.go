package scanner

//map[data_key][zones]string
//zonse := zones.([]string)
var DataZoneMap map[string]interface{} = map[string]interface{}{
	"request_uri":     []string{"$request_uri", "$u_request_uri"},
	"http_referer":    []string{"$http_referer"},
	"http_user_agent": []string{"$http_user_agent"},
	"request_body":    []string{"$request_body"},
	"request_method":  []string{"$request_method"},
	"request":         []string{"$request"},
	"args":            []string{"$args"},
}
