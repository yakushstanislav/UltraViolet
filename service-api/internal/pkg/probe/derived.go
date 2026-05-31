// Package-internal helpers that derive a FingerprintResult from data that
// every probe already collects: HTTP response headers/body and the TLS leaf
// certificate. Targeted, non-network code — these run inside an existing
// probe pass and never issue extra requests.
//
// Why this exists: probes like probeHTTP capture rich data (Server header,
// HTML <meta generator>, TLS Subject) but until now only stashed it as
// strings, while cvematch needs FingerprintResult{Product, Version}. Wiring
// these one-step parsers more than doubles match coverage on the most
// common services (nginx, Apache, IIS, PHP, ASP.NET, Tomcat, WordPress,
// Drupal, Joomla, GitLab, Jenkins, Vault, Kubernetes API…) without growing
// the probe registry.

package probe

import (
	"regexp"
	"strings"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/cpemap"
)

// productAndVersionRE captures the canonical `<name>/<version>` form used by
// most HTTP servers in the Server header, e.g.
//
//	nginx/1.18.0 (Ubuntu)
//	Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f
//	Microsoft-IIS/10.0
//	gunicorn/21.2.0
//	GitLab/16.5.2
//
// It deliberately matches *the first* token only — composite Server values
// (Apache + PHP + OpenSSL on the same line) are split out by the explicit
// modCaptureRE pass below.
var productAndVersionRE = regexp.MustCompile(`(?i)([A-Za-z][\w.+\-]*)\s*/\s*v?([0-9][\w.+\-]*)`)

// metaGeneratorRE picks the <meta name="generator" content="…"> tag out of
// HTML. Quotes can be single or double, attribute order is fixed in the
// generator-tag spec, so a tight pattern is enough.
var metaGeneratorRE = regexp.MustCompile(`(?is)<meta\s+name=["']generator["']\s+content=["']([^"']+)["']`)

// poweredByRE: the few power-by headers ship a value in either of two
// shapes: bare token ("PHP/8.1.10") matched by productAndVersionRE above,
// or human-readable "<product> <version>" we handle separately.
var poweredByRE = regexp.MustCompile(`(?i)^\s*([A-Za-z][\w.+\-]+)[\s/]+v?([0-9][\w.+\-]*)`)

// wordpressHTMLCommentRE catches the legacy "<!-- WordPress 6.4 -->"
// version hint that the platform emits in <head>, separate from the
// <meta generator> tag. Captured even when the generator tag is absent.
var wordpressHTMLCommentRE = regexp.MustCompile(`(?i)<!--\s*WordPress\s+([\d.]+)\s*-->`)

// genericBannerVersionRE is a last-resort version extractor used when a
// specialized probe has identified the product but not its version. It
// matches the first dotted version-like token in a banner ("Postfix
// smtpd-3.4.13", "Exim 4.94", "Welcome to 5.7.44-log").
var genericBannerVersionRE = regexp.MustCompile(`\b(\d+\.\d+(?:\.\d+)?)\b`)

// productAliases collapses the long tail of vendor-specific Server tokens
// onto the cpemap.productMap key set. cpemap.Lookup will consult this map
// before falling back to the literal product name.
//
// Rules:
//   - keys are lowercased canonical product strings as seen on the wire,
//   - values are the cpemap.productMap key we want cvematch to hit.
var productAliases = map[string]string{
	"httpd":               "apache",
	"apache_http_server":  "apache",
	"apache-coyote":       "tomcat",
	"apache":              "apache",
	"microsoft-iis":       "iis",
	"microsoft-httpapi":   "iis",
	"phusion_passenger":   "passenger",
	"asp.net":             "asp_net",
	"asp-net":             "asp_net",
	"openssl":             "openssl",
	"libssh":              "libssh",
	"node.js":             "nodejs",
	"node":                "nodejs",
	"express":             "express",
	"werkzeug":            "werkzeug",
	"jboss-eap":           "jboss",
	"jboss-as":            "jboss",
	"wildfly":             "wildfly",
	"glassfish":           "glassfish",
	"caddyserver":         "caddy",
	"hiawatha":            "hiawatha",
	"litespeed":           "litespeed",
	"openresty":           "openresty",
	"haproxy":             "haproxy",
	"varnish":             "varnish",
	"squid-cache":         "squid",
	"squid":               "squid",
	"kong":                "kong",
	"uwsgi":               "uwsgi",
	"gunicorn":            "gunicorn",
	"sun-one":             "sun_one",
	"webrick":             "webrick",
	"puma":                "puma",
	"unicorn":             "unicorn",
	"thin":                "thin",
	"gitlab":              "gitlab",
	"jenkins":             "jenkins",
	"vault":               "vault",
	"consul":              "consul",
	"consul-connect":      "consul",
	"prometheus":          "prometheus",
	"grafana":             "grafana",
	"rabbitmq-management": "rabbitmq",
	"phpmyadmin":          "phpmyadmin",
	"wordpress":           "wordpress",
	"drupal":              "drupal",
	"joomla":              "joomla",
	"joomla!":             "joomla",
	"nextcloud":           "nextcloud",
	"owncloud":            "owncloud",
	"moodle":              "moodle",
	"magento":             "magento",
	"openshift":           "openshift",
	"kubernetes":          "kubernetes",
	"k8s":                 "kubernetes",
	"docker":              "docker",
	"containerd":          "containerd",
	"etcd":                "etcd",
	"nats-server":         "nats",
	"natsd":               "nats",

	// Smart-home / IoT — what each gateway puts into Server: /
	// X-Powered-By: / <meta generator> on its embedded web UI.
	"tasmota":        "tasmota",
	"sonoff-tasmota": "tasmota",
	"esphome":        "esphome",
	"wled":           "wled",
	"shelly":         "shelly",
	"allterco":       "shelly",
	"home-assistant": "home_assistant",
	"homeassistant":  "home_assistant",
	"hass":           "home_assistant",
	"hue_bridge":     "hue_bridge",
	"philips_hue":    "hue_bridge",
	"signify_hue":    "hue_bridge",
	"openhab":        "openhab",

	// IP cameras / DVR — banner fragments seen on factory firmware.
	"hikvision-webs":    "hikvision_camera",
	"app-webs":          "hikvision_camera",
	"dahua-httpd":       "dahua_camera",
	"dahua":             "dahua_camera",
	"webs/dahua":        "dahua_camera",
	"axis":              "axis_camera",
	"axis-acap-runtime": "axis_camera",
	"foscam":            "foscam_camera",
	"netwave_ip_camera": "foscam_camera",
	"reolink":           "reolink_camera",
	"unifi-video":       "ubiquiti_camera",

	// Industrial / printers — banners frequently embedded in printer web
	// UIs and PLC HTTP frontends.
	"hp-laserjet":         "hp_printer",
	"hp_color_laserjet":   "hp_printer",
	"officejet":           "hp_printer",
	"deskjet":             "hp_printer",
	"kyocera-mita":        "kyocera_printer",
	"xerox-workcentre":    "xerox_printer",
	"epson-printer":       "epson_printer",
	"canon-printer":       "canon_printer",
	"lexmark-mfp":         "lexmark_printer",
	"siemens":             "siemens_simatic",
	"schneider-electric":  "schneider_electric_modicon",
	"rockwell-automation": "rockwell_logix",
	"omron-plc":           "omron_plc",
	"abb-plc":             "abb_plc",

	// Traffic-signal controllers. The Server line on NTCIP web UIs is
	// almost always the vendor's own product name, and the SNMP probe
	// rewrites sysDescr-derived banners into these aliases too.
	"econolite":   "econolite_asc3",
	"asc/3":       "econolite_asc3",
	"cobalt":      "econolite_cobalt",
	"mccain":      "mccain_atc",
	"atc-eX":      "mccain_atc",
	"trafficware": "trafficware_atc",
	"scout":       "trafficware_atc",
	"sitraffic":   "siemens_sitraffic",
	"swarco":      "swarco_traffic",
	"intelight":   "intelight_x1",
	"maxtime":     "intelight_x1",

	// Lighting / building-automation HTTP frontends — the web UIs all
	// brand their Server header with the gateway model.
	"lutron":           "lutron_homeworks",
	"homeworks":        "lutron_homeworks",
	"radiora":          "lutron_homeworks",
	"caseta":           "lutron_homeworks",
	"crestron":         "crestron_control",
	"toolbox":          "crestron_control",
	"netlinx":          "amx_netlinx",
	"amx":              "amx_netlinx",
	"helvar":           "helvar_imagine",
	"helvar-imagine":   "helvar_imagine",
	"tridonic":         "tridonic_dali",
	"dali":             "tridonic_dali",
	"dynalite":         "dynalite_dynet",
	"philips-dynalite": "dynalite_dynet",
	"casambi":          "casambi_gateway",
	"lunatone":         "dali2_iot",

	// Energy gateways.
	"sma":      "sma_inverter",
	"sunny":    "sma_inverter",
	"fronius":  "fronius_solar",
	"sel-rtac": "sel_rtac",

	// Network gear admin panels usually identify themselves with a
	// vendor-specific Server header.
	"cisco":              "cisco_ios",
	"cisco-ios":          "cisco_ios",
	"cisco_ios_xe":       "cisco_ios",
	"cisco-asa":          "cisco_asa",
	"cisco-nx-os":        "cisco_nxos",
	"mikrotik":           "mikrotik_routeros", //nolint:misspell // RouterOS is MikroTik's product name
	"routeros":           "mikrotik_routeros", //nolint:misspell // RouterOS is MikroTik's product name
	"mikrotik-routeros":  "mikrotik_routeros", //nolint:misspell // RouterOS is MikroTik's product name
	"webserver/routeros": "mikrotik_routeros", //nolint:misspell // RouterOS is MikroTik's product name
	"edgeos":             "ubiquiti_edgeos",
	"junos":              "juniper_junos",

	// VMS / access-control web consoles.
	"genetec":    "genetec_security_center",
	"milestone":  "milestone_xprotect",
	"xprotect":   "milestone_xprotect",
	"bvms":       "bosch_bvms",
	"bosch-bvms": "bosch_bvms",
	"pro-watch":  "honeywell_prowatch",
	"prowatch":   "honeywell_prowatch",
	"avigilon":   "avigilon_acc",

	// EV chargers.
	"terra-ac":  "abb_ev_charger",
	"terra-dc":  "abb_ev_charger",
	"evlink":    "schneider_evlink",
	"kecontact": "keba_charger",

	// OCPP central-station banner fragments. ocppUpgrade rewrites the
	// Product directly when it sees these in Server: ; the aliases are
	// the safety net for HTTP frontends that don't speak OCPP-WS but do
	// advertise the platform name in their admin UI.
	"steve":        "steve_ocpp",
	"steve-ocpp":   "steve_ocpp",
	"maeve":        "maeve_csms",
	"maeve-csms":   "maeve_csms",
	"mywallbox":    "wallbox_mywallbox",
	"wallbox":      "wallbox_mywallbox",
	"compleo":      "compleo_csms",
	"compleo-csms": "compleo_csms",
	"ev-manager":   "ev_manager",
	"ev_manager":   "ev_manager",

	// CUPS / IPP printing stacks.
	"cups":         "cups",
	"cups-ipp":     "cups",
	"cups-browsed": "cups",
	"openprinting": "cups",
	"ipp":          "ipp",

	// CODESYS field-controller branding seen on Wago / Bosch Rexroth /
	// Schneider M251 / ABB AC500 / Beckhoff embedded admin web UIs.
	"codesys":          "codesys_v3",
	"codesys-v3":       "codesys_v3",
	"codesys-control":  "codesys_v3",
	"codesys-gateway":  "codesys_v3",
	"3s-software":      "codesys_v3",
	"wago-pfc200":      "codesys_v3",
	"bosch-rexroth":    "codesys_v3",
	"beckhoff-twincat": "codesys_v3",
	"beckhoff":         "codesys_v3",

	// Physical access control & payment-and-pass HTTP frontends. The
	// banner usually carries the platform name; some send it through the
	// Server header (Lenel/S2/Genetec), others stash it in
	// X-Powered-By or <meta generator> on the web console.
	"lenel":              "lenel_onguard",
	"onguard":            "lenel_onguard",
	"c-cure":             "software_house_ccure",
	"ccure":              "software_house_ccure",
	"software-house":     "software_house_ccure",
	"istar":              "software_house_istar",
	"s2-netbox":          "s2_netbox",
	"s2_netbox":          "s2_netbox",
	"netbox":             "s2_netbox",
	"mercury-mr":         "hid_mercury",
	"mercury-lp":         "hid_mercury",
	"mercury_security":   "hid_mercury",
	"mercury-security":   "hid_mercury",
	"hid-edge":           "hid_edge",
	"hid-vertx":          "hid_vertx",
	"vertx":              "hid_vertx",
	"identiv":            "identiv_velocity",
	"velocity":           "identiv_velocity",
	"gallagher":          "gallagher_command",
	"command-centre":     "gallagher_command",
	"vanderbilt":         "vanderbilt_aliro",
	"aliro":              "vanderbilt_aliro",
	"suprema":            "suprema_biostar",
	"biostar":            "suprema_biostar",
	"zkteco":             "zkteco_biosecurity",
	"zkbiosecurity":      "zkteco_biosecurity",
	"paxton":             "paxton_net2",
	"net2":               "paxton_net2",
	"nedap":              "nedap_aeos",
	"aeos":               "nedap_aeos",
	"synergis":           "genetec_synergis",
	"axis-a1001":         "axis_a1001",
	"axis-entry-manager": "axis_entry_manager",
	"bolid":              "bolid_orion",
	"orion-pro":          "bolid_orion",
	"perco":              "perco_web",
	"perco-web":          "perco_web",
	"sigur":              "sigur_access",
	"skidata":            "skidata_parking",
	"scheidt-bachmann":   "scheidt_bachmann_entervo",
	"entervo":            "scheidt_bachmann_entervo",
	"cubic-nextfare":     "cubic_nextfare",
	"thales-revenue":     "thales_revenue",
	"indra-ticketing":    "indra_ticketing",

	// Fire-alarm / mass-notification panels.
	"notifier":        "notifier_onyx",
	"onyx":            "notifier_onyx",
	"onyxworks":       "notifier_onyx",
	"cerberus":        "siemens_cerberus",
	"cerberus-pro":    "siemens_cerberus",
	"avenar":          "bosch_avenar",
	"bosch-avenar":    "bosch_avenar",
	"est3":            "edwards_est3",
	"edwards-est3":    "edwards_est3",
	"simplex":         "simplex_4100es",
	"4100es":          "simplex_4100es",
	"truealert":       "simplex_4100es",
	"schrack-seconet": "schrack_seconet",
	"integral-ip":     "schrack_seconet",
	"apollo-fire":     "apollo_fire",
	"hochiki":         "hochiki_fire",
	"vigilon":         "gent_fire",
	"morley-zx":       "morley_facp",
	"autronica":       "autronica_fire",
	"autroprime":      "autronica_fire",

	// Water / wastewater + process historians.
	"melsec":          "mitsubishi_melsec",
	"mitsubishi":      "mitsubishi_melsec",
	"slmp":            "mitsubishi_melsec",
	"osisoft":         "osisoft_pi",
	"pi-web-api":      "osisoft_pi",
	"pi-server":       "osisoft_pi",
	"wonderware":      "wonderware_intouch",
	"intouch":         "wonderware_intouch",
	"aveva":           "wonderware_intouch",
	"system-platform": "wonderware_intouch",
	"iconics":         "iconics_genesis",
	"genesis64":       "iconics_genesis",
	"yokogawa":        "yokogawa_centum",
	"centum":          "yokogawa_centum",
	"deltav":          "emerson_deltav",
	"emerson-deltav":  "emerson_deltav",
	"ovation":         "emerson_ovation",
	"800xa":           "abb_800xa",
	"endress-hauser":  "endress_hauser",
	"fieldcare":       "endress_hauser",
	"sensus-flexnet":  "sensus_flexnet",
	"itron-openway":   "itron_openway",
	"hach":            "hach_wims",
	"hach-wims":       "hach_wims",
	"claros":          "hach_wims",
	"mueller-mi":      "mueller_mi",
	"badger-meter":    "badger_meter",
	"beacon-ama":      "badger_meter",

	// Smart irrigation gateways.
	"rain-bird":        "rain_bird_esp",
	"rainbird":         "rain_bird_esp",
	"esp-tm2":          "rain_bird_esp",
	"hunter-hydrawise": "hunter_hydrawise",
	"hydrawise":        "hunter_hydrawise",
	"toro-tempus":      "toro_tempus",
	"toro-irrigation":  "toro_tempus",
	"netafim":          "netafim_netbeat",
	"netbeat":          "netafim_netbeat",
	"galcon":           "galcon_irrigation",

	// Smart appliances — fridges, ovens, dishwashers, washing machines
	// that expose a vendor-branded admin/diagnostic web UI on the LAN
	// or whose self-signed TLS cert leaks the vendor cloud name into
	// the Server: header. The literal "smartthings" alias is already
	// claimed by the SmartThings Hub firmware further down the file —
	// the Family Hub fridge / cloud platform reuses
	// "samsungiot"/"familyhub" aliases instead.
	"samsungiot":      "samsung_smartthings",
	"samsung-iot":     "samsung_smartthings",
	"familyhub":       "samsung_smartthings",
	"thinq":           "lg_thinq",
	"lg-thinq":        "lg_thinq",
	"smartthinq":      "lg_thinq",
	"homeconnect":     "bsh_home_connect",
	"home-connect":    "bsh_home_connect",
	"bsh":             "bsh_home_connect",
	"bsh-group":       "bsh_home_connect",
	"bsh_hausgeraete": "bsh_home_connect",
	"whirlpool":       "whirlpool_smart",
	"6thsense":        "whirlpool_smart",
	"6th-sense":       "whirlpool_smart",
	"haier":           "haier_hon",
	"hon-cloud":       "haier_hon",
	"hon":             "haier_hon",
	"smartdevicebox":  "liebherr_smartdevicebox",
	"liebherr":        "liebherr_smartdevicebox",
	"miele":           "miele_xkm",
	"miele-xkm":       "miele_xkm",
	"miele@home":      "miele_xkm",
	"electrolux":      "electrolux_appliances",
	"aeg":             "electrolux_appliances",
	"myelectrolux":    "electrolux_appliances",
	"my-electrolux":   "electrolux_appliances",

	// Smart TVs / set-top boxes / cast receivers. Server header aliases
	// for the vendors whose firmware brands its embedded web stack. We
	// avoid the bare "google-cast" key — it's already claimed by the
	// audio-only Nest line — and route the Cast receiver flow through
	// the unhyphenated "chromecast" / "googlecast" tokens instead.
	"tizen":            "samsung_tizen_tv",
	"samsung-tizen":    "samsung_tizen_tv",
	"samsungtv":        "samsung_tizen_tv",
	"samsung-allshare": "samsung_tizen_tv",
	"webos":            "lg_webos_tv",
	"lg-webos":         "lg_webos_tv",
	"webos-tv":         "lg_webos_tv",
	"lgsmarttv":        "lg_webos_tv",
	"lg-allshare":      "lg_webos_tv",
	"eureka":           "google_chromecast",
	"chromecast":       "google_chromecast",
	"googlecast":       "google_chromecast",
	"google-home":      "google_chromecast",
	"android-tv":       "google_chromecast",
	"androidtv":        "google_chromecast",
	"roku":             "roku_tv",
	"roku-upnp":        "roku_tv",
	"rokuos":           "roku_tv",
	"airtunes":         "apple_tv",
	"airplay":          "apple_tv",
	"appletv":          "apple_tv",
	"tvos":             "apple_tv",
	"bravia":           "sony_bravia_tv",
	"sony-bravia":      "sony_bravia_tv",
	"bravia-android":   "sony_bravia_tv",
	"mi-tv":            "xiaomi_mi_tv",
	"xiaomi-tv":        "xiaomi_mi_tv",
	"mitv":             "xiaomi_mi_tv",
	"tcl-tv":           "tcl_android_tv",
	"tcl-android":      "tcl_android_tv",
	"tcl-googletv":     "tcl_android_tv",
	"vidaa":            "hisense_vidaa",
	"vidaa-os":         "hisense_vidaa",
	"hisense-tv":       "hisense_vidaa",
	"vizio":            "vizio_smartcast",
	"smartcast":        "vizio_smartcast",
	"vizio-smartcast":  "vizio_smartcast",

	// Broad IoT ecosystem — wire-form Server / X-Powered-By tokens
	// emitted by hubs, smart speakers, doorbells, locks and edge
	// gateways. Keys stay lower-case; values are canonical
	// cpemap.productMap keys.
	"sonos":               "sonos",
	"sonos,_inc.":         "sonos",
	"linuxupnp":           "sonos",
	"ewelink":             "sonoff_zbbridge",
	"sonoff":              "sonoff_zbbridge",
	"tuya":                "tuya_device",
	"tuya-smart":          "tuya_device",
	"smartlife":           "tuya_device",
	"smart-life":          "tuya_device",
	"belkin":              "belkin_wemo",
	"wemo":                "belkin_wemo",
	"belkin-wemo":         "belkin_wemo",
	"wemo-bridge":         "belkin_wemo",
	"hue/2.0":             "philips_hue_v2",
	"hue-bridge-v2":       "philips_hue_v2",
	"signify":             "philips_hue_v2",
	"signify-hue":         "philips_hue_v2",
	"magichome":           "tuya_device",
	"govee":               "tuya_device",
	"yeelight":            "yeelight",
	"aqara":               "aqara_hub",
	"lumi-gateway":        "aqara_hub",
	"samsung-smartthings": "samsung_smartthings_hub",
	"openhab-cloud":       "openhab",
	"zigbee2mqtt":         "zigbee2mqtt",
	"deconz":              "deconz_conbee",
	"conbee":              "deconz_conbee",
	"zwavejs":             "zwave_js_ui",
	"zwave-js":            "zwave_js_ui",
	"zwave-js-ui":         "zwave_js_ui",
	"homey":               "homey_pro",
	"homebridge":          "apple_homekit_bridge",
	"otbr":                "matter_otbr",
	"openthread":          "matter_otbr",
	"matter-server":       "matter_node",
	"alexa":               "amazon_echo",
	"echo":                "amazon_echo",
	"nest-audio":          "google_nest_audio",
	"soundtouch":          "bose_soundtouch",
	"heos":                "denon_heos",
	"musiccast":           "yamaha_musiccast",
	"yamaha-musiccast":    "yamaha_musiccast",
	"ring":                "ring_doorbell",
	"ring-cam":            "ring_doorbell",
	"nest-doorbell":       "nest_doorbell",
	"nest-cam":            "nest_doorbell",
	"arlo":                "arlo_pro",
	"netgear-arlo":        "arlo_pro",
	"eufy":                "eufy_security",
	"eufy-camera":         "eufy_security",
	"wyze":                "wyze_cam",
	"wyze-cam":            "wyze_cam",
	"amcrest":             "amcrest_camera",
	"swann":               "swann_dvr",
	"vivotek":             "vivotek_camera",
	"august":              "august_lock",
	"august-lock":         "august_lock",
	"yale-assure":         "yale_assure",
	"yale-real-living":    "yale_assure",
	"schlage":             "schlage_encode",
	"schlage-encode":      "schlage_encode",
	"kwikset":             "kwikset_halo",
	"kwikset-halo":        "kwikset_halo",
	"lockly":              "lockly_secure",
	"igloohome":           "igloohome",
	"lifx":                "lifx_bulb",
	"lifx-bulb":           "lifx_bulb",
	"nanoleaf":            "nanoleaf_aurora",
	"nanoleaf-aurora":     "nanoleaf_aurora",
	"ikea-dirigera":       "ikea_dirigera",
	"dirigera":            "ikea_dirigera",
	"tradfri":             "ikea_tradfri_gateway",
	"ikea-tradfri":        "ikea_tradfri_gateway",

	// Protocol-stack keys (raw Product values emitted by the new probes
	// land via cpemap.Lookup directly; these aliases catch the wire-form
	// strings that HTTP/SNMP-derived parsers see on the same hosts).
	"coap":            "coap",
	"libcoap":         "coap",
	"californium":     "coap",
	"leshan":          "lwm2m",
	"wakaama":         "lwm2m",
	"miio":            "xiaomi_miio_device",
	"mihome":          "xiaomi_miio_device",
	"edgex":           "edgex_foundry",
	"edgex-core":      "edgex_foundry",
	"edgex-core-data": "edgex_foundry",
	"edgex-foundry":   "edgex_foundry",

	// Industrial IoT / edge-gateway brands. Server tokens picked up off
	// vendor admin web UIs that host the same Linux runtime across
	// product lines.
	"moxa":            "moxa_iot",
	"moxaswitch":      "moxa_iot",
	"moxa-iologik":    "moxa_iot",
	"advantech":       "advantech_iot",
	"advantech-iot":   "advantech_iot",
	"wise-paas":       "advantech_iot",
	"phoenix-contact": "phoenix_contact_router",
	"mguard":          "phoenix_contact_router",
	"red-lion":        "red_lion_iot",
	"redlion":         "red_lion_iot",
	"flexedge":        "red_lion_iot",
	"dell-edge":       "dell_edge_gateway",
	"edge-gateway":    "dell_edge_gateway",
	"iot2050":         "siemens_iot2050",
	"simatic-iot":     "siemens_iot2050",

	// Precision-agriculture controllers / farm-management gateways.
	"john-deere":  "john_deere_jdlink",
	"johndeere":   "john_deere_jdlink",
	"jdlink":      "john_deere_jdlink",
	"ag-leader":   "agleader_incommand",
	"agleader":    "agleader_incommand",
	"incommand":   "agleader_incommand",
	"trimble-ag":  "trimble_ag",
	"tmx-2050":    "trimble_ag",
	"topcon-x35":  "topcon_x35",
	"raven-viper": "raven_viper",
	"viper4":      "raven_viper",
	"lely":        "lely_astronaut",
	"astronaut":   "lely_astronaut",
	"delaval":     "delaval_vms",
	"delpro":      "delaval_vms",
	"gea-dairy":   "gea_dairy",
	"dairyplan":   "gea_dairy",
	"cowcontrol":  "nedap_cowcontrol",
	"valley-icon": "valley_irrigation",
	"fieldnet":    "lindsay_fieldnet",

	// Broader EV-charger wallbox / DC-fast-charger Server-header tokens.
	// The ABB/Schneider/KEBA and OCPP-WS central-station aliases sit
	// further up; this block covers the rest of the market — most
	// wallboxes brand their embedded admin UI with the model or
	// vendor name in the Server header or in a self-signed TLS cert.
	"tesla-wall-connector": "tesla_wall_connector",
	"tesla":                "tesla_wall_connector",
	"wallbox-pulsar":       "wallbox_pulsar",
	"wallbox-quasar":       "wallbox_quasar",
	"easee":                "easee_home",
	"alfen":                "alfen_eve",
	"webasto":              "webasto_live",
	"evbox":                "evbox_elvi",
	"liviqo":               "evbox_elvi",
	"chargepoint":          "chargepoint_home_flex",
	"juicebox":             "enelx_juicebox",
	"juicepump":            "enelx_juicebox",
	"garo":                 "garo_gnm",
	"charx":                "phoenix_contact_charx",
	"keba-p40":             "keba_p40",
	"trydan":               "v2c_trydan",
	"raption":              "circontrol_raption",
	"ebox":                 "innogy_ebox",
	"smappee":              "smappee_ev_wall",
	"zappi":                "myenergi_zappi",
	"eddi":                 "myenergi_zappi",
	"andersen-ev":          "andersen_a2",
	"ohme":                 "ohme_home_pro",
	"tritium":              "tritium_pkm",
	"delta-dc":             "delta_dc",
	"signet":               "signet_dc",
	"efacec":               "efacec_qc",
	"touchenergy":          "touchenergy_ru",
	"parkline":             "parkline_ev_ru",
	"evolve-charge":        "evolve_charge",

	// Healthcare — DICOM PACS / HL7 EMR / OpenMRS / OpenEMR.
	"orthanc":           "orthanc_dicom",
	"orthanc-server":    "orthanc_dicom",
	"dcm4chee":          "dcm4chee",
	"dcm4che":           "dcm4chee",
	"dcm4chee-arc":      "dcm4chee",
	"dcm4chee-arc-cs":   "dcm4chee",
	"dcmtk":             "dcmtk",
	"pacscube":          "pacscube",
	"osirix":            "osirix",
	"osirix-md":         "osirix",
	"openmrs":           "openmrs",
	"openemr":           "openemr",
	"mirth-connect":     "mirth_connect",
	"mirth":             "mirth_connect",
	"nextgen-connect":   "mirth_connect",
	"epic-chronicles":   "epic_chronicles",
	"chronicles":        "epic_chronicles",
	"cerner-millennium": "cerner_millennium",
	"cerner":            "cerner_millennium",

	// Hypervisor / cloud management plane.
	"pve-api-daemon":     "proxmox_ve",
	"pveproxy":           "proxmox_ve",
	"proxmox":            "proxmox_ve",
	"ovirt":              "ovirt_engine",
	"ovirt-engine":       "ovirt_engine",
	"rhevm":              "ovirt_engine",
	"xapi":               "xenserver_xapi",
	"xenserver":          "xenserver_xapi",
	"xcp-ng":             "xcp_ng",
	"xcp_ng":             "xcp_ng",
	"keystone":           "openstack_keystone",
	"openstack-keystone": "openstack_keystone",
	"openstack_keystone": "openstack_keystone",
	"openstack-nova":     "openstack_nova",
	"openstack-neutron":  "openstack_neutron",

	// Backup software.
	"veeam":             "veeam_backup",
	"veeam-backup":      "veeam_backup",
	"veeambackup":       "veeam_backup",
	"vbr":               "veeam_backup",
	"commvault":         "commvault_backup",
	"commserve":         "commvault_backup",
	"cvwebservice":      "commvault_backup",
	"rubrik":            "rubrik_cdm",
	"rubrik-cdm":        "rubrik_cdm",
	"netbackup":         "netbackup",
	"veritas-netbackup": "netbackup",
	"cohesity":          "cohesity_dataplatform",
	"dataplatform":      "cohesity_dataplatform",
	"bareos":            "bareos",
	"bareos-dir":        "bareos",
	"bareos-fd":         "bareos",
	"bareos-sd":         "bareos",
	"bacula":            "bacula",
	"bacula-dir":        "bacula",
	"bacula-fd":         "bacula",
	"arcserve":          "arcserve_udp",
	"arcserve-udp":      "arcserve_udp",

	// APM / observability stacks.
	"splunkd":           "splunk",
	"splunk":            "splunk",
	"splunk-enterprise": "splunk",
	"splunk-web":        "splunk",
	"datadog":           "datadog_agent",
	"datadog-agent":     "datadog_agent",
	"trace-agent":       "datadog_agent",
	"dd-trace-agent":    "datadog_agent",
	"loki":              "grafana_loki",
	"grafana-loki":      "grafana_loki",
	"tempo":             "grafana_tempo",
	"grafana-tempo":     "grafana_tempo",
	"victoriametrics":   "victoria_metrics",
	"vmsingle":          "victoria_metrics",
	"vmstorage":         "victoria_metrics",
	"vmselect":          "victoria_metrics",
	"vminsert":          "victoria_metrics",
	"alertmanager":      "prometheus_alertmanager",
	"prom-alertmanager": "prometheus_alertmanager",
	"pushgateway":       "prometheus_pushgateway",
	"prom-pushgateway":  "prometheus_pushgateway",

	// Service mesh control planes.
	"istiod":          "istio_pilot",
	"istio-pilot":     "istio_pilot",
	"istio":           "istio_pilot",
	"linkerd":         "linkerd_proxy",
	"linkerd2":        "linkerd_proxy",
	"linkerd2-proxy":  "linkerd_proxy",
	"linkerd-proxy":   "linkerd_proxy",
	"cilium":          "cilium_agent",
	"cilium-agent":    "cilium_agent",
	"cilium-operator": "cilium_agent",
	"kuma":            "kuma_cp",
	"kuma-cp":         "kuma_cp",

	// Energy SCADA / metering.
	"dlms":          "dlms_cosem",
	"cosem":         "dlms_cosem",
	"dlms-cosem":    "dlms_cosem",
	"c37.118":       "synchrophasor_pmu",
	"synchrophasor": "synchrophasor_pmu",
	"pmu":           "synchrophasor_pmu",
	"sicam-pas":     "siemens_sicam_pas",
	"sicam_pas":     "siemens_sicam_pas",
	"sel-3373":      "sel_3373",
	"sel_3373":      "sel_3373",

	// Secure DNS.
	"dot":           "dns_over_tls",
	"dns-over-tls":  "dns_over_tls",
	"unbound":       "unbound",
	"knot-resolver": "knot_resolver",
	"kresd":         "knot_resolver",
	"cloudflared":   "cloudflared",
	"adguard-home":  "adguard_home",
	"adguardhome":   "adguard_home",
	"adguard":       "adguard_home",

	// CI/CD platforms.
	"teamcity":          "jetbrains_teamcity",
	"teamcity-pro":      "jetbrains_teamcity",
	"jetbrains-tc":      "jetbrains_teamcity",
	"go.cd":             "gocd",
	"gocd":              "gocd",
	"go-server":         "gocd",
	"drone":             "drone_ci",
	"drone-ci":          "drone_ci",
	"concourse":         "concourse_ci",
	"concourse-web":     "concourse_ci",
	"github-enterprise": "github_enterprise",
	"woodpecker":        "woodpecker_ci",
	"woodpecker-ci":     "woodpecker_ci",
	"argo":              "argo_workflows",
	"argo-workflows":    "argo_workflows",

	// Storage stacks.
	"iscsi":        "iscsi_target",
	"lio-target":   "iscsi_target",
	"tgtd":         "iscsi_target",
	"open-iscsi":   "iscsi_target",
	"nfs":          "nfs_server",
	"nfsd":         "nfs_server",
	"afp":          "apple_filing_protocol",
	"afpd":         "apple_filing_protocol",
	"netatalk":     "apple_filing_protocol",
	"lustre":       "lustre",
	"glusterfs":    "gluster_fs",
	"gluster":      "gluster_fs",
	"ceph-mon":     "ceph_mon",
	"ceph":         "ceph_mon",
	"minio":        "minio_server",
	"minio-server": "minio_server",
	"ontap":        "netapp_ontap",
	"netapp":       "netapp_ontap",
	"isilon":       "emc_isilon",
	"isilon-onefs": "emc_isilon",
	"powerscale":   "emc_isilon",
	"pure-storage": "pure_storage",
	"flasharray":   "pure_storage",
	"purity":       "pure_storage",

	// Robotics.
	"ros":                 "ros_master",
	"ros-master":          "ros_master",
	"roscore":             "ros_master",
	"ros2":                "ros2_dds",
	"fastdds":             "ros2_dds",
	"rmw":                 "ros2_dds",
	"kuka":                "kuka_krc",
	"krc4":                "kuka_krc",
	"krc5":                "kuka_krc",
	"abb-robotware":       "abb_robotware",
	"robotware":           "abb_robotware",
	"factorytalk-linx":    "rockwell_factorytalk",
	"factorytalk-gateway": "rockwell_factorytalk",
	"fanuc":               "fanuc_focas",
	"focas":               "fanuc_focas",
	"urcontrol":           "universal_robots",
	"polyscope":           "universal_robots",
	"ursoftware":          "universal_robots",
	"ur-control":          "universal_robots",
	"yaskawa":             "yaskawa_motoman",
	"motoman":             "yaskawa_motoman",
	"yrc1000":             "yaskawa_motoman",
	"staubli":             "staubli_cs9",
	"staubli-cs9":         "staubli_cs9",
	"denso":               "denso_robotics",
	"denso-robotics":      "denso_robotics",

	// Marine / aviation receivers.
	"nmea":          "nmea0183",
	"nmea0183":      "nmea0183",
	"nmea-0183":     "nmea0183",
	"aishub":        "ais_receiver",
	"aisdispatcher": "ais_receiver",
	"dump1090":      "dump1090",
	"dump1090-fa":   "dump1090",
	"readsb":        "dump1090",
	"piaware":       "dump1090",
	"fr24feed":      "dump1090",
	"gnuradio":      "gnu_radio",
	"gnu-radio":     "gnu_radio",
	"acarsdec":      "acarsdec",

	// Crypto / game.
	"satoshi":          "bitcoin_core",
	"bitcoin":          "bitcoin_core",
	"bitcoin-core":     "bitcoin_core",
	"bitcoin_knots":    "bitcoin_knots",
	"knots":            "bitcoin_knots",
	"bcoin":            "bcoin_node",
	"btcd":             "btcd_node",
	"litecoin":         "litecoin_core",
	"geth":             "ethereum_geth",
	"go-ethereum":      "ethereum_geth",
	"erigon":           "ethereum_erigon",
	"openethereum":     "ethereum_openethereum",
	"parity":           "ethereum_openethereum",
	"besu":             "hyperledger_besu",
	"nethermind":       "ethereum_nethermind",
	"lighthouse":       "ethereum_lighthouse",
	"prysm":            "ethereum_prysm",
	"monero":           "monero_node",
	"monerod":          "monero_node",
	"lnd":              "lightning_network_daemon",
	"lightning":        "lightning_network_daemon",
	"minecraft":        "minecraft_server",
	"minecraft-server": "minecraft_server",
	"mc-server":        "minecraft_server",
	"mojang":           "minecraft_server",
	"steam":            "steam_dedicated_server",
	"steam-server":     "steam_dedicated_server",
	"srcds":            "steam_dedicated_server",
}

// canonicalProduct returns the cpemap key for product, applying aliases.
// The input is lower-cased and space-trimmed.
func canonicalProduct(product string) string {
	key := strings.ToLower(strings.TrimSpace(product))
	if key == "" {
		return ""
	}

	if alias, ok := productAliases[key]; ok {
		return alias
	}

	return key
}

// specializedHTTPDetectors is the ordered list of body/header detectors that
// fingerprintFromHTTP falls back to when generic header parsing fails. Kept
// as a slice so componentsFromHTTP can iterate over them and emit one
// component per match instead of stopping at the first hit.
var specializedHTTPDetectors = []func(*HTTPResult) *FingerprintResult{
	detectPrometheusPushgateway,
	detectSplunkWebUI,
	detectDNSOverHTTPSResponse,
	detectHL7OverHTTP,
	detectDroneCI,
	detectConcourseCI,
	detectGitHubEnterprise,
	detectTeslaWallConnector,
}

// productRoles maps known product slugs to their default role label, so that
// when a generic detector (Server header, X-Powered-By, …) returns a
// product, the downstream component carries an accurate stack-layer tag.
var productRoles = map[string]string{
	"nginx":       ComponentRoleWebServer,
	"apache":      ComponentRoleWebServer,
	"iis":         ComponentRoleWebServer,
	"caddy":       ComponentRoleWebServer,
	"lighttpd":    ComponentRoleWebServer,
	"openresty":   ComponentRoleWebServer,
	"cloudflare":  ComponentRoleWebServer,
	"php":         ComponentRoleRuntime,
	"asp.net":     ComponentRoleRuntime,
	"python":      ComponentRoleRuntime,
	"nodejs":      ComponentRoleRuntime,
	"wordpress":   ComponentRoleCMS,
	"drupal":      ComponentRoleCMS,
	"joomla":      ComponentRoleCMS,
	"wix":         ComponentRoleCMS,
	"squarespace": ComponentRoleCMS,
	"shopify":     ComponentRoleCMS,
	"laravel":     ComponentRoleFramework,
	"django":      ComponentRoleFramework,
	"rails":       ComponentRoleFramework,
	"next.js":     ComponentRoleFramework,
	"nuxt":        ComponentRoleFramework,
	"react":       ComponentRoleJSLibrary,
	"vue.js":      ComponentRoleJSLibrary,
	"angular":     ComponentRoleJSLibrary,
	"jquery":      ComponentRoleJSLibrary,
	"bootstrap":   ComponentRoleJSLibrary,
}

// roleForProduct returns the configured role for product or fallback when
// the product is not in productRoles.
func roleForProduct(product, fallback string) string {
	if role, ok := productRoles[strings.ToLower(product)]; ok {
		return role
	}

	return fallback
}

// fingerprintToComponent copies the fields of a FingerprintResult into a
// TechComponent and tags it with the given source/role.
func fingerprintToComponent(fp *FingerprintResult, source, role string) TechComponent {
	return TechComponent{
		Product:      fp.Product,
		Version:      fp.Version,
		Edition:      fp.Edition,
		ClusterRole:  fp.ClusterRole,
		ClusterName:  fp.ClusterName,
		AuthRequired: fp.AuthRequired,
		TLSRequired:  fp.TLSRequired,
		Anonymous:    fp.Anonymous,
		RawJSON:      fp.RawJSON,
		Source:       source,
		Role:         role,
	}
}

// dedupComponents collapses (product, source) duplicates, keeping the row
// with a non-empty version when both variants exist.
func dedupComponents(in []TechComponent) []TechComponent {
	if len(in) == 0 {
		return nil
	}

	seen := make(map[string]int, len(in))
	out := make([]TechComponent, 0, len(in))

	for _, comp := range in {
		key := strings.ToLower(comp.Product) + "|" + comp.Source

		idx, exists := seen[key]
		if exists {
			if out[idx].Version == "" && comp.Version != "" {
				out[idx] = comp
			}

			continue
		}

		seen[key] = len(out)
		out = append(out, comp)
	}

	return out
}

// ExtractFromText is the generic product/version detector used as a
// fallback when a specialized probe has produced only a raw banner. It
// runs the canonical "<name>/<version>" extractor plus the "Name X.Y"
// shape over the input and returns at most one component, tagged
// banner_generic. Returns nil when no known product matches.
//
// Intended for probeBanner (the unknown-port fallback) and for
// specialized banners that don't carry their own version (SMTP "Postfix",
// MySQL welcome strings, RTSP OPTIONS replies, …).
func ExtractFromText(text string) []TechComponent {
	if text == "" {
		return nil
	}

	var components []TechComponent

	if fp := parseRsyncDaemonBanner(text); fp != nil {
		components = append(components, fingerprintToComponent(fp, ComponentSourceBannerGeneric, roleForProduct(fp.Product, ComponentRoleOther)))
	}

	if fp := matchProductRegex(text); fp != nil {
		components = append(components, fingerprintToComponent(fp, ComponentSourceBannerGeneric, roleForProduct(fp.Product, ComponentRoleOther)))
	}

	if fp := matchPoweredBy(text); fp != nil {
		alreadyKnown := false

		for _, comp := range components {
			if strings.EqualFold(comp.Product, fp.Product) {
				alreadyKnown = true

				break
			}
		}

		if !alreadyKnown {
			components = append(components, fingerprintToComponent(fp, ComponentSourceBannerGeneric, roleForProduct(fp.Product, ComponentRoleOther)))
		}
	}

	return components
}

// ExtractVersionFromBanner pulls the first dotted version-like token out
// of a banner. Used by specialized probes (SSH, SMTP, RTSP, MySQL,
// Postgres, Redis) when their structured parser identified the product
// but couldn't get a version through the protocol's version field.
func ExtractVersionFromBanner(banner string) string {
	if banner == "" {
		return ""
	}

	match := genericBannerVersionRE.FindStringSubmatch(banner)
	if len(match) < 2 {
		return ""
	}

	return match[1]
}

// componentsFromHTTP returns the full set of detected tech components from
// a HTTPResult — web_server + runtime + cms + JS libraries together —
// instead of collapsing to the single "primary" component that
// fingerprintFromHTTP yields.
func componentsFromHTTP(httpResult *HTTPResult) []TechComponent {
	if httpResult == nil {
		return nil
	}

	var components []TechComponent

	if fp := matchProductRegex(httpResult.Server); fp != nil {
		components = append(components, fingerprintToComponent(fp, ComponentSourceHTTPServer, roleForProduct(fp.Product, ComponentRoleWebServer)))
	}

	if powered := httpResult.Headers["X-Powered-By"]; powered != "" {
		if fp := matchPoweredBy(powered); fp != nil {
			components = append(components, fingerprintToComponent(fp, ComponentSourcePoweredBy, roleForProduct(fp.Product, ComponentRoleRuntime)))
		}
	}

	if gen := httpResult.Headers["X-Generator"]; gen != "" {
		if fp := matchPoweredBy(gen); fp != nil {
			components = append(components, fingerprintToComponent(fp, ComponentSourceMetaGenerator, roleForProduct(fp.Product, ComponentRoleCMS)))
		}
	}

	// X-AspNet-Version ships just the version ("4.0.30319"), no product
	// name — so map it to asp.net directly with the captured version.
	if aspver := strings.TrimSpace(httpResult.Headers["X-AspNet-Version"]); aspver != "" {
		components = append(components, TechComponent{
			Product: "asp.net",
			Version: aspver,
			Source:  ComponentSourcePoweredBy,
			Role:    ComponentRoleRuntime,
		})
	}

	// X-Drupal-Cache only proves the platform — no version, but enough for
	// version-less CVE matching against the drupal product.
	if _, drupalCache := httpResult.Headers["X-Drupal-Cache"]; drupalCache {
		components = append(components, TechComponent{
			Product: "drupal",
			Source:  ComponentSourceHTTPServer,
			Role:    ComponentRoleCMS,
		})
	}

	if httpResult.Body != "" {
		if fp := matchMetaGenerator(httpResult.Body); fp != nil {
			components = append(components, fingerprintToComponent(fp, ComponentSourceMetaGenerator, roleForProduct(fp.Product, ComponentRoleCMS)))
		}

		// Legacy "<!-- WordPress 6.4 -->" comment — captured even when the
		// site stripped the <meta generator> tag for cosmetic reasons.
		if m := wordpressHTMLCommentRE.FindStringSubmatch(httpResult.Body); len(m) > 1 {
			components = append(components, TechComponent{
				Product: "wordpress",
				Version: m[1],
				Source:  ComponentSourceBodyPattern,
				Role:    ComponentRoleCMS,
			})
		}
	}

	for _, detector := range specializedHTTPDetectors {
		if fp := detector(httpResult); fp != nil {
			components = append(components, fingerprintToComponent(fp, ComponentSourceProtocolProbe, roleForProduct(fp.Product, ComponentRoleOther)))
		}
	}

	components = append(components, detectComponents(httpResult.Headers, httpResult.Body)...)

	return dedupComponents(components)
}

// fingerprintFromHTTP derives a Product+Version pair from a HTTPResult.
// Priority: Server header → X-Powered-By → X-Generator → <meta generator>.
// Returns nil when nothing matched; callers should keep their existing
// fingerprint in that case.
func fingerprintFromHTTP(httpResult *HTTPResult) *FingerprintResult {
	if httpResult == nil {
		return nil
	}

	if fp := matchProductRegex(httpResult.Server); fp != nil {
		return fp
	}

	if powered := httpResult.Headers["X-Powered-By"]; powered != "" {
		if fp := matchPoweredBy(powered); fp != nil {
			return fp
		}
	}

	if gen := httpResult.Headers["X-Generator"]; gen != "" {
		if fp := matchPoweredBy(gen); fp != nil {
			return fp
		}
	}

	if httpResult.Body != "" {
		if fp := matchMetaGenerator(httpResult.Body); fp != nil {
			return fp
		}
	}

	if fp := detectPrometheusPushgateway(httpResult); fp != nil {
		return fp
	}

	if fp := detectSplunkWebUI(httpResult); fp != nil {
		return fp
	}

	if fp := detectDNSOverHTTPSResponse(httpResult); fp != nil {
		return fp
	}

	if fp := detectHL7OverHTTP(httpResult); fp != nil {
		return fp
	}

	if fp := detectDroneCI(httpResult); fp != nil {
		return fp
	}

	if fp := detectConcourseCI(httpResult); fp != nil {
		return fp
	}

	if fp := detectGitHubEnterprise(httpResult); fp != nil {
		return fp
	}

	if fp := detectTeslaWallConnector(httpResult); fp != nil {
		return fp
	}

	return nil
}

// detectPrometheusPushgateway matches the JSON body returned by
// `GET /api/v1/status/buildinfo` on the Prometheus pushgateway.
func detectPrometheusPushgateway(httpResult *HTTPResult) *FingerprintResult {
	body := strings.ToLower(httpResult.Body)

	if !strings.Contains(body, "pushgateway") || !strings.Contains(body, "version") {
		return nil
	}

	return &FingerprintResult{Product: "prometheus_pushgateway"}
}

// detectSplunkWebUI flags Splunk Web on plain HTTP port 8000 from the
// Splunkd Server header or HTML body markers.
func detectSplunkWebUI(httpResult *HTTPResult) *FingerprintResult {
	server := strings.ToLower(httpResult.Server)
	body := strings.ToLower(httpResult.Body)

	if !strings.Contains(server, "splunkd") && !strings.Contains(body, "splunk") {
		return nil
	}

	return &FingerprintResult{Product: "splunk"}
}

// detectDNSOverHTTPSResponse recognises DoH gateways from the
// `application/dns-message` content type on HTTPS responses.
func detectDNSOverHTTPSResponse(httpResult *HTTPResult) *FingerprintResult {
	ct := strings.ToLower(httpResult.Headers["Content-Type"])
	if !strings.Contains(ct, "application/dns-message") {
		return nil
	}

	return &FingerprintResult{Product: "dns_over_https"}
}

// detectHL7OverHTTP catches misconfigured HL7 listeners that expose MLLP
// payloads over HTTP on shared ports such as 5000.
func detectHL7OverHTTP(httpResult *HTTPResult) *FingerprintResult {
	if !strings.Contains(httpResult.Body, "MSH|") {
		return nil
	}

	return &FingerprintResult{Product: "hl7_mllp"}
}

// detectDroneCI recognises the Drone CI web UI from Server / body.
func detectDroneCI(httpResult *HTTPResult) *FingerprintResult {
	hay := strings.ToLower(httpResult.Server + " " + httpResult.Body)

	if !strings.Contains(hay, "drone") {
		return nil
	}

	return &FingerprintResult{Product: "drone_ci"}
}

// detectConcourseCI recognises the Concourse CI ATC web UI.
func detectConcourseCI(httpResult *HTTPResult) *FingerprintResult {
	hay := strings.ToLower(httpResult.Server + " " + httpResult.Title + " " + httpResult.Body)

	if !strings.Contains(hay, "concourse") {
		return nil
	}

	return &FingerprintResult{Product: "concourse_ci"}
}

// detectGitHubEnterprise matches GitHub Enterprise Server banners.
func detectGitHubEnterprise(httpResult *HTTPResult) *FingerprintResult {
	if httpResult.Headers["X-GitHub-Request-Id"] == "" &&
		!strings.Contains(strings.ToLower(httpResult.Server), "github.com") {
		return nil
	}

	return &FingerprintResult{Product: "github_enterprise"}
}

// matchProductRegex hunts for the canonical "<name>/<version>" token in
// a Server-style string and returns a FingerprintResult on first hit.
func matchProductRegex(value string) *FingerprintResult {
	if value == "" {
		return nil
	}

	match := productAndVersionRE.FindStringSubmatch(value)
	if len(match) < 3 {
		return nil
	}

	product := canonicalProduct(match[1])
	if !acceptDerivedProduct(product) {
		return nil
	}

	return &FingerprintResult{
		Product: product,
		Version: match[2],
	}
}

// matchPoweredBy handles both "PHP/8.1.10" and "WordPress 6.4.2" shapes.
func matchPoweredBy(value string) *FingerprintResult {
	if value == "" {
		return nil
	}

	if fp := matchProductRegex(value); fp != nil {
		return fp
	}

	match := poweredByRE.FindStringSubmatch(value)
	if len(match) < 3 {
		return nil
	}

	product := canonicalProduct(match[1])
	if !acceptDerivedProduct(product) {
		return nil
	}

	return &FingerprintResult{
		Product: product,
		Version: match[2],
	}
}

func acceptDerivedProduct(product string) bool {
	if product == "" || product == "cloudflare" {
		return false
	}

	return cpemap.HasProduct(product)
}

// matchMetaGenerator parses the <meta name="generator" content="…"> tag
// from HTML and tries to extract product + version. Typical content
// strings:
//
//	WordPress 6.4.2
//	Drupal 9 (https://www.drupal.org)
//	Joomla! - Open Source Content Management
//	MediaWiki 1.39.1
//	Hugo 0.119.0
//
// The version is optional — Joomla famously ships the tag without one. In
// that case we still emit a Product so cvematch can pick up version-less
// applicability statements.
func matchMetaGenerator(body string) *FingerprintResult {
	match := metaGeneratorRE.FindStringSubmatch(body)
	if len(match) < 2 {
		return nil
	}

	content := strings.TrimSpace(match[1])
	if content == "" {
		return nil
	}

	if fp := matchProductRegex(content); fp != nil {
		return fp
	}

	// Pattern "<Product> <Version>" with no slash.
	parts := strings.Fields(content)
	if len(parts) == 0 {
		return nil
	}

	product := canonicalProduct(strings.TrimRight(parts[0], "!"))
	if product == "" {
		return nil
	}

	fp := &FingerprintResult{Product: product}

	if len(parts) > 1 {
		ver := strings.TrimPrefix(parts[1], "v")
		if len(ver) > 0 && ver[0] >= '0' && ver[0] <= '9' {
			fp.Version = ver
		}
	}

	return fp
}

// tlsSubjectHint scans a TLS leaf cert Subject + SAN list for distinctive
// product markers (no version — TLS certs almost never carry one). The
// result is a Product-only FingerprintResult that still gives cvematch a
// chance to look up version-independent CVEs (e.g. a CVE that affects all
// Kubernetes API server builds).
//
// We do not generate guesses for vendors absent from cpemap.productMap
// (e.g. Fortinet, Palo Alto) — they would produce dangling matches.
func tlsSubjectHint(tlsResult *TLSResult) *FingerprintResult {
	if tlsResult == nil {
		return nil
	}

	haystack := strings.ToLower(tlsResult.Subject + " " + tlsResult.Issuer + " " + strings.Join(tlsResult.SANs, " "))

	for _, h := range tlsSubjectHints {
		if strings.Contains(haystack, h.needle) {
			return &FingerprintResult{Product: h.product}
		}
	}

	return nil
}

type tlsSubjectMarker struct {
	needle  string
	product string
}

// tlsSubjectHints links substrings that appear in self-signed admin-panel
// certs to the cpemap.productMap key for the product behind them. The list
// is intentionally narrow — broader hints belong in HTTP-body parsers.
var tlsSubjectHints = []tlsSubjectMarker{
	{needle: "kube-apiserver", product: "kubernetes"},
	{needle: "kube apiserver", product: "kubernetes"},
	{needle: "kubernetes ingress controller fake certificate", product: "kubernetes"},
	{needle: "kubernetes-master", product: "kubernetes"},
	{needle: "kubelet", product: "kubernetes"},
	{needle: "vault-server", product: "vault"},
	{needle: "consul-server", product: "consul"},
	{needle: "consul agent ca", product: "consul"},
	{needle: "etcd-server", product: "etcd"},
	{needle: "etcd-client", product: "etcd"},
	{needle: "etcd-peer", product: "etcd"},
	{needle: "grafana", product: "grafana"},
	{needle: "prometheus", product: "prometheus"},
	{needle: "jenkins", product: "jenkins"},
	{needle: "gitlab", product: "gitlab"},
	{needle: "nextcloud", product: "nextcloud"},
	{needle: "owncloud", product: "owncloud"},
	{needle: "mailcow", product: "mailcow"},
	{needle: "rabbitmq", product: "rabbitmq"},

	// IP camera firmware almost universally ships a self-signed cert
	// whose CN or O leaks the brand.
	{needle: "hikvision", product: "hikvision_camera"},
	{needle: "dahua technology", product: "dahua_camera"},
	{needle: "axis communications", product: "axis_camera"},
	{needle: "foscam", product: "foscam_camera"},
	{needle: "reolink", product: "reolink_camera"},
	{needle: "ubiquiti", product: "ubiquiti_camera"},

	// Smart-home hubs.
	{needle: "home assistant", product: "home_assistant"},
	{needle: "philips hue", product: "hue_bridge"},
	{needle: "tasmota", product: "tasmota"},
	{needle: "esphome", product: "esphome"},

	// ICS HMIs and PLC web UIs.
	{needle: "siemens ag", product: "siemens_simatic"},
	{needle: "schneider electric", product: "schneider_electric_modicon"},
	{needle: "rockwell automation", product: "rockwell_logix"},
	{needle: "tridium", product: "tridium_niagara"},
	{needle: "niagara", product: "tridium_niagara"},
	{needle: "honeywell international", product: "honeywell_bacnet"},
	{needle: "johnson controls", product: "johnson_controls"},

	// Traffic / lighting / energy control panels.
	{needle: "econolite", product: "econolite_asc3"},
	{needle: "mccain", product: "mccain_atc"},
	{needle: "trafficware", product: "trafficware_atc"},
	{needle: "swarco", product: "swarco_traffic"},
	{needle: "intelight", product: "intelight_x1"},
	{needle: "sitraffic", product: "siemens_sitraffic"},
	{needle: "lutron electronics", product: "lutron_homeworks"},
	{needle: "crestron electronics", product: "crestron_control"},
	{needle: "helvar", product: "helvar_imagine"},
	{needle: "tridonic", product: "tridonic_dali"},
	{needle: "casambi", product: "casambi_gateway"},
	{needle: "lunatone", product: "dali2_iot"},
	{needle: "schweitzer engineering", product: "sel_rtac"},
	{needle: "sma solar", product: "sma_inverter"},
	{needle: "fronius international", product: "fronius_solar"},

	// Network kit (admin web UIs).
	{needle: "cisco systems", product: "cisco_ios"},
	{needle: "mikrotik", product: "mikrotik_routeros"}, //nolint:misspell // RouterOS is MikroTik's product name
	{needle: "ubiquiti networks", product: "ubiquiti_edgeos"},
	{needle: "juniper networks", product: "juniper_junos"},

	// VMS / access-control web certs.
	{needle: "genetec", product: "genetec_security_center"},
	{needle: "milestone systems", product: "milestone_xprotect"},
	{needle: "bosch security systems", product: "bosch_bvms"},
	{needle: "honeywell access", product: "honeywell_prowatch"},
	{needle: "avigilon", product: "avigilon_acc"},

	// Physical access / payment-and-pass control panels. Most are
	// self-signed certs whose CN/O leaks the platform name.
	{needle: "lenel", product: "lenel_onguard"},
	{needle: "software house", product: "software_house_ccure"},
	{needle: "c-cure 9000", product: "software_house_ccure"},
	{needle: "istar ultra", product: "software_house_istar"},
	{needle: "s2 security", product: "s2_netbox"},
	{needle: "s2 netbox", product: "s2_netbox"},
	{needle: "mercury security", product: "hid_mercury"},
	{needle: "hid global", product: "hid_mercury"},
	{needle: "identiv", product: "identiv_velocity"},
	{needle: "hirsch electronics", product: "identiv_velocity"},
	{needle: "gallagher group", product: "gallagher_command"},
	{needle: "vanderbilt industries", product: "vanderbilt_aliro"},
	{needle: "suprema inc", product: "suprema_biostar"},
	{needle: "zkteco", product: "zkteco_biosecurity"},
	{needle: "paxton access", product: "paxton_net2"},
	{needle: "nedap", product: "nedap_aeos"},
	{needle: "bolid", product: "bolid_orion"},
	{needle: "perco", product: "perco_web"},
	{needle: "sigur", product: "sigur_access"},
	{needle: "skidata", product: "skidata_parking"},
	{needle: "scheidt & bachmann", product: "scheidt_bachmann_entervo"},

	// Fire-alarm panel HTTPS UIs.
	{needle: "notifier", product: "notifier_onyx"},
	{needle: "onyxworks", product: "notifier_onyx"},
	{needle: "cerberus", product: "siemens_cerberus"},
	{needle: "bosch fire", product: "bosch_avenar"},
	{needle: "avenar", product: "bosch_avenar"},
	{needle: "edwards systems", product: "edwards_est3"},
	{needle: "kidde-fenwal", product: "edwards_est3"},
	{needle: "simplex grinnell", product: "simplex_4100es"},
	{needle: "truealert", product: "simplex_4100es"},
	{needle: "schrack-seconet", product: "schrack_seconet"},
	{needle: "autronica", product: "autronica_fire"},
	{needle: "morley-ias", product: "morley_facp"},
	{needle: "hochiki", product: "hochiki_fire"},

	// Water / wastewater historians and SCADA HMI bridges.
	{needle: "mitsubishi electric", product: "mitsubishi_melsec"},
	{needle: "osisoft", product: "osisoft_pi"},
	{needle: "aveva", product: "wonderware_intouch"},
	{needle: "wonderware", product: "wonderware_intouch"},
	{needle: "iconics", product: "iconics_genesis"},
	{needle: "yokogawa", product: "yokogawa_centum"},
	{needle: "emerson process management", product: "emerson_deltav"},
	{needle: "abb 800xa", product: "abb_800xa"},
	{needle: "endress+hauser", product: "endress_hauser"},
	{needle: "endress hauser", product: "endress_hauser"},
	{needle: "sensus metering", product: "sensus_flexnet"},
	{needle: "itron, inc", product: "itron_openway"},
	{needle: "hach company", product: "hach_wims"},
	{needle: "mueller water products", product: "mueller_mi"},
	{needle: "badger meter", product: "badger_meter"},

	// OCPP central-station / EV-charger self-signed certs.
	{needle: "steve charging station", product: "steve_ocpp"},
	{needle: "maeve csms", product: "maeve_csms"},
	{needle: "wallbox chargers", product: "wallbox_mywallbox"},
	{needle: "compleo charging solutions", product: "compleo_csms"},

	// CUPS scheduler / printer-server certs (Apple, OpenPrinting,
	// Synology / QNAP packaging).
	{needle: "cups", product: "cups"},
	{needle: "apple cups", product: "cups"},
	{needle: "openprinting", product: "cups"},

	// CODESYS V3/V4 Edge Gateway self-signed certificate (always issued
	// to "CODESYS Control" or "3S-Smart Software Solutions").
	{needle: "codesys control", product: "codesys_v3"},
	{needle: "3s-smart software solutions", product: "codesys_v3"},
	{needle: "wago kontakttechnik", product: "codesys_v3"},
	{needle: "bosch rexroth", product: "codesys_v3"},
	{needle: "beckhoff automation", product: "codesys_v3"},

	// Smart appliances — most are reached via vendor cloud, but the
	// thin LAN admin UI ships a self-signed cert whose CN/O reveals
	// the manufacturer.
	{needle: "samsung electronics", product: "samsung_tizen_tv"},
	{needle: "smartthings", product: "samsung_smartthings"},
	{needle: "samsung family hub", product: "samsung_smartthings"},
	{needle: "lg electronics", product: "lg_webos_tv"},
	{needle: "lgsmarttv", product: "lg_webos_tv"},
	{needle: "lg thinq", product: "lg_thinq"},
	{needle: "smartthinq", product: "lg_thinq"},
	{needle: "bsh hausger", product: "bsh_home_connect"},
	{needle: "bsh home appliances", product: "bsh_home_connect"},
	{needle: "home connect", product: "bsh_home_connect"},
	{needle: "bosch siemens", product: "bsh_home_connect"},
	{needle: "whirlpool corporation", product: "whirlpool_smart"},
	{needle: "haier group", product: "haier_hon"},
	{needle: "haier smart", product: "haier_hon"},
	{needle: "liebherr-hausger", product: "liebherr_smartdevicebox"},
	{needle: "liebherr", product: "liebherr_smartdevicebox"},
	{needle: "miele & cie", product: "miele_xkm"},
	{needle: "miele cie", product: "miele_xkm"},
	{needle: "miele", product: "miele_xkm"},
	{needle: "electrolux home products", product: "electrolux_appliances"},
	{needle: "electrolux appliances", product: "electrolux_appliances"},
	{needle: "aktiebolaget electrolux", product: "electrolux_appliances"},

	// Smart TVs, set-top boxes and cast receivers — self-signed certs
	// from receiver-side TLS endpoints (Samsung Tizen 8002, LG webOS
	// 3001, Cast 8009, Roku ECP, Vizio SmartCast).
	{needle: "roku, inc", product: "roku_tv"},
	{needle: "roku inc", product: "roku_tv"},
	{needle: "roku streaming", product: "roku_tv"},
	{needle: "apple inc", product: "apple_tv"},
	{needle: "google llc", product: "google_chromecast"},
	{needle: "google inc", product: "google_chromecast"},
	{needle: "chromecast ica", product: "google_chromecast"},
	{needle: "cast root ca", product: "google_chromecast"},
	{needle: "android tv", product: "google_chromecast"},
	{needle: "sony corporation", product: "sony_bravia_tv"},
	{needle: "sony interactive", product: "sony_bravia_tv"},
	{needle: "sony visual products", product: "sony_bravia_tv"},
	{needle: "xiaomi inc", product: "xiaomi_mi_tv"},
	{needle: "xiaomi communications", product: "xiaomi_mi_tv"},
	{needle: "mibox", product: "xiaomi_mi_tv"},
	{needle: "tcl king electrical", product: "tcl_android_tv"},
	{needle: "tcl multimedia", product: "tcl_android_tv"},
	{needle: "shenzhen tcl", product: "tcl_android_tv"},
	{needle: "hisense co", product: "hisense_vidaa"},
	{needle: "hisense electric", product: "hisense_vidaa"},
	{needle: "hisense visual", product: "hisense_vidaa"},
	{needle: "vidaa", product: "hisense_vidaa"},
	{needle: "vizio, inc", product: "vizio_smartcast"},
	{needle: "vizio inc", product: "vizio_smartcast"},
	{needle: "smartcast", product: "vizio_smartcast"},

	// Irrigation and precision-agriculture controllers.
	{needle: "rain bird", product: "rain_bird_esp"},
	{needle: "hunter industries", product: "hunter_hydrawise"},
	{needle: "the toro company", product: "toro_tempus"},
	{needle: "netafim", product: "netafim_netbeat"},
	{needle: "galcon", product: "galcon_irrigation"},
	{needle: "john deere", product: "john_deere_jdlink"},
	{needle: "ag leader", product: "agleader_incommand"},
	{needle: "trimble ag", product: "trimble_ag"},
	{needle: "topcon agriculture", product: "topcon_x35"},
	{needle: "raven industries", product: "raven_viper"},
	{needle: "lely industries", product: "lely_astronaut"},
	{needle: "delaval", product: "delaval_vms"},
	{needle: "gea farm", product: "gea_dairy"},
	{needle: "valley irrigation", product: "valley_irrigation"},
	{needle: "lindsay corporation", product: "lindsay_fieldnet"},

	// Broad IoT ecosystem — manufacturer Subject/Issuer strings on the
	// self-signed TLS certs that ship with consumer hubs, doorbells,
	// smart locks and prosumer cameras. Keep the parallel TV worker's
	// territory out of this list — no Samsung Electronics, no LG
	// Electronics, no Roku, no Apple AirPlay.
	{needle: "sonos, inc", product: "sonos"},
	{needle: "sonos inc", product: "sonos"},
	{needle: "belkin international", product: "belkin_wemo"},
	{needle: "belkin inc", product: "belkin_wemo"},
	{needle: "xiaomi communications", product: "xiaomi_miio_device"},
	{needle: "xiaomi inc", product: "xiaomi_miio_device"},
	{needle: "aqara inc", product: "aqara_hub"},
	{needle: "lumi united", product: "aqara_hub"},
	{needle: "tuya inc", product: "tuya_device"},
	{needle: "tuya smart", product: "tuya_device"},
	{needle: "signify netherlands", product: "philips_hue_v2"},
	{needle: "signify holding", product: "philips_hue_v2"},
	{needle: "ikea of sweden", product: "ikea_tradfri_gateway"},
	{needle: "inter ikea systems", product: "ikea_tradfri_gateway"},
	{needle: "bose corporation", product: "bose_soundtouch"},
	{needle: "denon, ", product: "denon_heos"},
	{needle: "d&m holdings", product: "denon_heos"},
	{needle: "yamaha corporation", product: "yamaha_musiccast"},
	{needle: "amazon technologies", product: "amazon_echo"},
	{needle: "ring llc", product: "ring_doorbell"},
	{needle: "ring inc", product: "ring_doorbell"},
	{needle: "arlo technologies", product: "arlo_pro"},
	{needle: "netgear, inc", product: "arlo_pro"},
	{needle: "eufy", product: "eufy_security"},
	{needle: "anker innovations", product: "eufy_security"},
	{needle: "wyze labs", product: "wyze_cam"},
	{needle: "wyze, inc", product: "wyze_cam"},
	{needle: "amcrest technologies", product: "amcrest_camera"},
	{needle: "vivotek", product: "vivotek_camera"},
	{needle: "swann communications", product: "swann_dvr"},
	{needle: "yale security", product: "yale_assure"},
	{needle: "assa abloy", product: "yale_assure"},
	{needle: "august home", product: "august_lock"},
	{needle: "schlage lock company", product: "schlage_encode"},
	{needle: "allegion", product: "schlage_encode"},
	{needle: "kwikset", product: "kwikset_halo"},
	{needle: "spectrum brands", product: "kwikset_halo"},
	{needle: "lockly", product: "lockly_secure"},
	{needle: "igloocompany", product: "igloohome"},
	{needle: "lifx", product: "lifx_bulb"},
	{needle: "nanoleaf", product: "nanoleaf_aurora"},
	{needle: "yeelink", product: "yeelight"},
	{needle: "athom", product: "homey_pro"},

	// Industrial IoT / edge gateway brands. Most ship self-signed certs
	// whose Subject leaks the vendor + product family.
	{needle: "moxa inc", product: "moxa_iot"},
	{needle: "moxa, inc", product: "moxa_iot"},
	{needle: "advantech", product: "advantech_iot"},
	{needle: "phoenix contact", product: "phoenix_contact_router"},
	{needle: "red lion controls", product: "red_lion_iot"},
	{needle: "dell edge", product: "dell_edge_gateway"},
	{needle: "dell inc", product: "dell_edge_gateway"},
	{needle: "iot2050", product: "siemens_iot2050"},
	{needle: "simatic iot2", product: "siemens_iot2050"},

	// Open-source IoT hubs and Matter / OpenThread border routers.
	{needle: "zigbee2mqtt", product: "zigbee2mqtt"},
	{needle: "dresden elektronik", product: "deconz_conbee"},
	{needle: "z-wave js", product: "zwave_js_ui"},
	{needle: "openthread", product: "matter_otbr"},
	{needle: "openthread border router", product: "matter_otbr"},
	{needle: "homebridge", product: "apple_homekit_bridge"},

	// EdgeX Foundry core services.
	{needle: "edgex-core-data", product: "edgex_foundry"},
	{needle: "edgex foundry", product: "edgex_foundry"},
	{needle: "linuxfoundation edgex", product: "edgex_foundry"},

	// EV-charger self-signed wallbox / DC-fast-charger certs. The ABB
	// Terra, Schneider EVlink, KEBA KeContact, Wallbox myWallbox,
	// Compleo, Steve and MaEVe hints sit further up; this block
	// fingerprints the rest of the consumer/commercial wallbox market
	// off the cert Subject (or, in a few cases, the SAN). Tesla covers
	// both the legal-entity CN ("Tesla, Inc") and the device-CN that
	// firmware 24.x writes into the leaf ("Tesla Wall Connector").
	{needle: "tesla wall connector", product: "tesla_wall_connector"},
	{needle: "tesla, inc", product: "tesla_wall_connector"},
	{needle: "easee as", product: "easee_home"},
	{needle: "alfen elkamo", product: "alfen_eve"},
	{needle: "alfen ", product: "alfen_eve"},
	{needle: "webasto thermo & comfort", product: "webasto_live"},
	{needle: "evbox bv", product: "evbox_elvi"},
	{needle: "chargepoint, inc", product: "chargepoint_home_flex"},
	{needle: "enel x", product: "enelx_juicebox"},
	{needle: "garo aktiebolag", product: "garo_gnm"},
	{needle: "phoenix contact ev", product: "phoenix_contact_charx"},
	{needle: "v2c", product: "v2c_trydan"},
	{needle: "circontrol", product: "circontrol_raption"},
	{needle: "innogy se", product: "innogy_ebox"},
	{needle: "smappee", product: "smappee_ev_wall"},
	{needle: "myenergi limited", product: "myenergi_zappi"},
	{needle: "andersen ev", product: "andersen_a2"},
	{needle: "ohme operations", product: "ohme_home_pro"},
	{needle: "tritium pty", product: "tritium_pkm"},
	{needle: "delta electronics", product: "delta_dc"},
	{needle: "signet systems", product: "signet_dc"},
	{needle: "efacec", product: "efacec_qc"},

	// Healthcare / EMR — DICOM PACS, HL7 brokers, hospital EMR portals.
	{needle: "orthanc", product: "orthanc_dicom"},
	{needle: "dcm4chee", product: "dcm4chee"},
	{needle: "dcm4che", product: "dcm4chee"},
	{needle: "dcmtk", product: "dcmtk"},
	{needle: "pacscube", product: "pacscube"},
	{needle: "osirix", product: "osirix"},
	{needle: "openmrs", product: "openmrs"},
	{needle: "openemr", product: "openemr"},
	{needle: "mirth connect", product: "mirth_connect"},
	{needle: "nextgen healthcare", product: "mirth_connect"},
	{needle: "epic systems", product: "epic_chronicles"},
	{needle: "cerner corporation", product: "cerner_millennium"},
	{needle: "oracle cerner", product: "cerner_millennium"},

	// Hypervisor / cloud-control plane certs.
	{needle: "proxmox", product: "proxmox_ve"},
	{needle: "pveproxy", product: "proxmox_ve"},
	{needle: "ovirt", product: "ovirt_engine"},
	{needle: "redhat enterprise virtualization", product: "ovirt_engine"},
	{needle: "ovirt engine", product: "ovirt_engine"},
	{needle: "ovirt", product: "ovirt_engine"},
	{needle: "citrix systems", product: "xenserver_xapi"},
	{needle: "xenserver", product: "xenserver_xapi"},
	{needle: "xapi", product: "xenserver_xapi"},
	{needle: "xcp-ng project", product: "xcp_ng"},
	{needle: "vates", product: "xcp_ng"},
	{needle: "openstack keystone", product: "openstack_keystone"},
	{needle: "openstack", product: "openstack_keystone"},

	// Backup software self-signed certs.
	{needle: "veeam software", product: "veeam_backup"},
	{needle: "veeam backup", product: "veeam_backup"},
	{needle: "commvault systems", product: "commvault_backup"},
	{needle: "commserve", product: "commvault_backup"},
	{needle: "rubrik, inc", product: "rubrik_cdm"},
	{needle: "veritas technologies", product: "netbackup"},
	{needle: "cohesity", product: "cohesity_dataplatform"},
	{needle: "bareos director", product: "bareos"},
	{needle: "bareos gmbh", product: "bareos"},
	{needle: "bacula systems", product: "bacula"},
	{needle: "arcserve", product: "arcserve_udp"},

	// APM / observability TLS subjects.
	{needle: "splunk inc", product: "splunk"},
	{needle: "splunkd", product: "splunk"},
	{needle: "datadog inc", product: "datadog_agent"},
	{needle: "datadog, inc", product: "datadog_agent"},
	{needle: "grafana labs", product: "grafana_loki"},
	{needle: "victoriametrics", product: "victoria_metrics"},

	// Service mesh control planes / sidecar certs.
	{needle: "istio.io", product: "istio_pilot"},
	{needle: "istiod", product: "istio_pilot"},
	{needle: "linkerd", product: "linkerd_proxy"},
	{needle: "cilium.io", product: "cilium_agent"},
	{needle: "isovalent", product: "cilium_agent"},

	// Energy SCADA / metering.
	{needle: "siemens sicam", product: "siemens_sicam_pas"},
	{needle: "sel-3373", product: "sel_3373"},
	{needle: "schweitzer-3373", product: "sel_3373"},

	// Secure DNS resolvers.
	{needle: "nlnetlabs", product: "unbound"},
	{needle: "nlnet labs", product: "unbound"},
	{needle: "knot resolver", product: "knot_resolver"},
	{needle: "cz.nic", product: "knot_resolver"},
	{needle: "cloudflare", product: "cloudflared"},
	{needle: "adguard software", product: "adguard_home"},

	// CI/CD platforms.
	{needle: "jetbrains s.r.o", product: "jetbrains_teamcity"},
	{needle: "jetbrains teamcity", product: "jetbrains_teamcity"},
	{needle: "thoughtworks", product: "gocd"},
	{needle: "drone.io", product: "drone_ci"},
	{needle: "concourse-ci", product: "concourse_ci"},
	{needle: "github.com", product: "github_enterprise"},
	{needle: "github enterprise", product: "github_enterprise"},
	{needle: "woodpecker-ci", product: "woodpecker_ci"},

	// Storage stacks.
	{needle: "netapp, inc", product: "netapp_ontap"},
	{needle: "netapp inc", product: "netapp_ontap"},
	{needle: "ontap", product: "netapp_ontap"},
	{needle: "isilon", product: "emc_isilon"},
	{needle: "dell isilon", product: "emc_isilon"},
	{needle: "powerscale", product: "emc_isilon"},
	{needle: "pure storage", product: "pure_storage"},
	{needle: "purestorage", product: "pure_storage"},
	{needle: "purity", product: "pure_storage"},
	{needle: "minio", product: "minio_server"},
	{needle: "red hat ceph", product: "ceph_mon"},
	{needle: "red hat gluster", product: "gluster_fs"},

	// Robotics / industrial robotics.
	{needle: "universal robots", product: "universal_robots"},
	{needle: "polyscope", product: "universal_robots"},
	{needle: "kuka roboter", product: "kuka_krc"},
	{needle: "kuka deutschland", product: "kuka_krc"},
	{needle: "abb robotics", product: "abb_robotware"},
	{needle: "robotware", product: "abb_robotware"},
	{needle: "fanuc corporation", product: "fanuc_focas"},
	{needle: "yaskawa electric", product: "yaskawa_motoman"},
	{needle: "stäubli", product: "staubli_cs9"},
	{needle: "staeubli", product: "staubli_cs9"},
	{needle: "denso wave", product: "denso_robotics"},

	// Marine / aviation.
	{needle: "aishub", product: "ais_receiver"},
	{needle: "flightaware", product: "dump1090"},
	{needle: "gnu radio", product: "gnu_radio"},

	// Crypto-currency nodes (typically don't ship TLS certs, but a few
	// front-ends do).
	{needle: "bitcoin core", product: "bitcoin_core"},
	{needle: "ethereum foundation", product: "ethereum_geth"},
	{needle: "ledgerwatch", product: "ethereum_erigon"},
	{needle: "consensys", product: "hyperledger_besu"},
	{needle: "nethermind", product: "ethereum_nethermind"},
	{needle: "sigma prime", product: "ethereum_lighthouse"},
	{needle: "prysmatic", product: "ethereum_prysm"},

	// Minecraft hosting fronts.
	{needle: "mojang", product: "minecraft_server"},
	{needle: "minecraft server", product: "minecraft_server"},
}
