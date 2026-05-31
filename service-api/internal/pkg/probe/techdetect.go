package probe

import (
	"regexp"
	"sort"
	"strings"
)

type techRule struct {
	name      string
	role      string
	source    string
	header    string // canonical Go header key; empty means "body only"
	pattern   string // case-insensitive substring used as a fast pre-filter
	versionRE *regexp.Regexp
}

var techRules = []techRule{
	// HTTP server headers
	{name: "nginx", role: ComponentRoleWebServer, source: ComponentSourceHTTPServer, header: "Server", pattern: "nginx"},
	{name: "apache", role: ComponentRoleWebServer, source: ComponentSourceHTTPServer, header: "Server", pattern: "apache"},
	{name: "iis", role: ComponentRoleWebServer, source: ComponentSourceHTTPServer, header: "Server", pattern: "microsoft-iis"},
	{name: "cloudflare", role: ComponentRoleWebServer, source: ComponentSourceHTTPServer, header: "Server", pattern: "cloudflare"},
	{name: "lighttpd", role: ComponentRoleWebServer, source: ComponentSourceHTTPServer, header: "Server", pattern: "lighttpd"},
	{name: "caddy", role: ComponentRoleWebServer, source: ComponentSourceHTTPServer, header: "Server", pattern: "caddy"},
	{name: "openresty", role: ComponentRoleWebServer, source: ComponentSourceHTTPServer, header: "Server", pattern: "openresty"},

	// Powered-by
	{name: "php", role: ComponentRoleRuntime, source: ComponentSourcePoweredBy, header: "X-Powered-By", pattern: "php"},
	{name: "asp.net", role: ComponentRoleRuntime, source: ComponentSourcePoweredBy, header: "X-Powered-By", pattern: "asp.net"},

	// Cookie-based fingerprints
	{name: "php", role: ComponentRoleRuntime, source: ComponentSourceCookie, header: "Set-Cookie", pattern: "phpsessid"},
	{name: "asp.net", role: ComponentRoleRuntime, source: ComponentSourceCookie, header: "Set-Cookie", pattern: "asp.net_sessionid"},
	{name: "cloudflare", role: ComponentRoleWebServer, source: ComponentSourceCookie, header: "Set-Cookie", pattern: "__cfduid"},
	{name: "cloudflare", role: ComponentRoleWebServer, source: ComponentSourceCookie, header: "Set-Cookie", pattern: "cf_clearance"},

	// Generator meta tag — capture version when present.
	{name: "wordpress", role: ComponentRoleCMS, source: ComponentSourceMetaGenerator, pattern: `name="generator" content="wordpress`, versionRE: regexp.MustCompile(`(?i)name=["']generator["']\s+content=["']wordpress\s+([\d.]+)`)},
	{name: "drupal", role: ComponentRoleCMS, source: ComponentSourceMetaGenerator, pattern: `name="generator" content="drupal`, versionRE: regexp.MustCompile(`(?i)name=["']generator["']\s+content=["']drupal\s+([\d.]+)`)},
	{name: "joomla", role: ComponentRoleCMS, source: ComponentSourceMetaGenerator, pattern: `name="generator" content="joomla`, versionRE: regexp.MustCompile(`(?i)name=["']generator["']\s+content=["']joomla!?\s*-?\s*([\d.]+)`)},
	{name: "wix", role: ComponentRoleCMS, source: ComponentSourceMetaGenerator, pattern: `name="generator" content="wix`},
	{name: "squarespace", role: ComponentRoleCMS, source: ComponentSourceBodyPattern, pattern: "squarespace"},
	{name: "shopify", role: ComponentRoleCMS, source: ComponentSourceBodyPattern, pattern: `cdn.shopify.com`},

	// Body JS patterns — version captured from filenames or ?ver= queries
	// when the asset URL exposes one (wordpress-style "?ver=6.4.2",
	// jquery-3.6.0.min.js, bootstrap-5.3.0.min.css).
	{name: "react", role: ComponentRoleJSLibrary, source: ComponentSourceBodyPattern, pattern: "react.development.js"},
	{name: "react", role: ComponentRoleJSLibrary, source: ComponentSourceBodyPattern, pattern: "react.production.min.js"},
	{name: "react", role: ComponentRoleJSLibrary, source: ComponentSourceBodyPattern, pattern: `"__reactfiber`},
	{name: "vue.js", role: ComponentRoleJSLibrary, source: ComponentSourceBodyPattern, pattern: "vue.min.js"},
	{name: "vue.js", role: ComponentRoleJSLibrary, source: ComponentSourceBodyPattern, pattern: "vue.global.js"},
	{name: "angular", role: ComponentRoleJSLibrary, source: ComponentSourceBodyPattern, pattern: "angular.min.js"},
	{name: "angular", role: ComponentRoleJSLibrary, source: ComponentSourceBodyPattern, pattern: "ng-version=", versionRE: regexp.MustCompile(`(?i)ng-version=["']([\d.]+)`)},
	{name: "jquery", role: ComponentRoleJSLibrary, source: ComponentSourceBodyPattern, pattern: "jquery.min.js"},
	{name: "jquery", role: ComponentRoleJSLibrary, source: ComponentSourceBodyPattern, pattern: "jquery-", versionRE: regexp.MustCompile(`(?i)jquery[-/]([\d.]+)(?:\.min)?\.js`)},
	{name: "bootstrap", role: ComponentRoleJSLibrary, source: ComponentSourceBodyPattern, pattern: "bootstrap.min.css", versionRE: regexp.MustCompile(`(?i)bootstrap[-@/]([\d.]+)(?:\.min)?\.(?:css|js)`)},
	{name: "bootstrap", role: ComponentRoleJSLibrary, source: ComponentSourceBodyPattern, pattern: "bootstrap.min.js"},
	{name: "next.js", role: ComponentRoleFramework, source: ComponentSourceBodyPattern, pattern: `"__next"`},
	{name: "next.js", role: ComponentRoleFramework, source: ComponentSourceBodyPattern, pattern: "/_next/static/"},
	{name: "nuxt", role: ComponentRoleFramework, source: ComponentSourceBodyPattern, pattern: "/_nuxt/"},
	{name: "wordpress", role: ComponentRoleCMS, source: ComponentSourceBodyPattern, pattern: "/wp-content/", versionRE: regexp.MustCompile(`(?i)/wp-(?:content|includes)/[^"'?]*\?ver=([\d.]+)`)},
	{name: "wordpress", role: ComponentRoleCMS, source: ComponentSourceBodyPattern, pattern: "/wp-includes/"},
	{name: "drupal", role: ComponentRoleCMS, source: ComponentSourceBodyPattern, pattern: "/sites/default/files/"},
	{name: "laravel", role: ComponentRoleFramework, source: ComponentSourceCookie, header: "Set-Cookie", pattern: `laravel_session`},
	{name: "django", role: ComponentRoleFramework, source: ComponentSourceBodyPattern, pattern: "csrfmiddlewaretoken"},
	{name: "rails", role: ComponentRoleFramework, source: ComponentSourceBodyPattern, pattern: "authenticity_token"},
}

type componentKey struct {
	product string
	source  string
}

// detectComponents returns the multi-layer technology stack visible in the
// given HTTP headers + body. Each rule that matches yields one
// TechComponent with role + source set; rules with a versionRE attempt to
// capture a version from the matched location.
func detectComponents(headers map[string]string, body string) []TechComponent {
	bodyLower := strings.ToLower(body)

	seen := make(map[componentKey]TechComponent)

	for _, rule := range techRules {
		matched := false
		searchSpace := bodyLower

		if rule.header != "" {
			val, ok := headers[rule.header]
			if !ok {
				continue
			}

			searchSpace = strings.ToLower(val)
		}

		if !strings.Contains(searchSpace, rule.pattern) {
			continue
		}

		matched = true
		version := ""

		if rule.versionRE != nil {
			if m := rule.versionRE.FindStringSubmatch(body); len(m) > 1 {
				version = m[1]
			}
		}

		if !matched {
			continue
		}

		key := componentKey{product: rule.name, source: rule.source}

		existing, alreadySeen := seen[key]
		if alreadySeen && existing.Version != "" {
			continue
		}

		seen[key] = TechComponent{
			Product: rule.name,
			Version: version,
			Source:  rule.source,
			Role:    rule.role,
		}
	}

	if len(seen) == 0 {
		return nil
	}

	components := make([]TechComponent, 0, len(seen))
	for _, comp := range seen {
		components = append(components, comp)
	}

	sort.Slice(components, func(i, j int) bool {
		if components[i].Product != components[j].Product {
			return components[i].Product < components[j].Product
		}

		return components[i].Source < components[j].Source
	})

	return components
}

// detectTechnologies returns a sorted, deduplicated list of technology
// names — kept for the uv_http_response.technologies[] column. Internally
// it delegates to detectComponents and projects out product names.
func detectTechnologies(headers map[string]string, body string) []string {
	components := detectComponents(headers, body)
	if len(components) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(components))

	for _, comp := range components {
		seen[comp.Product] = struct{}{}
	}

	result := make([]string, 0, len(seen))
	for name := range seen {
		result = append(result, name)
	}

	sort.Strings(result)

	return result
}
