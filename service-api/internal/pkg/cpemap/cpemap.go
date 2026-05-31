// Package cpemap normalizes scanner fingerprint products into CPE 2.3
// vendor/product coordinates used by the NVD catalog, and provides a
// version comparator that decides whether a captured version falls inside
// an NVD applicability range.
package cpemap

import (
	"regexp"
	"strings"
	"unicode"
)

// Coord is a (vendor, product) pair from CPE 2.3.
type Coord struct {
	Vendor  string
	Product string
}

// productMap is the static lookup from fingerprint.Product to one or more
// vendor/product CPE coordinates. A single fingerprint may legitimately map
// to several CPEs (e.g. nginx is published both as nginx/nginx and f5/nginx).
//
// All keys are lower-case fingerprint Product strings as emitted by the
// internal/pkg/probe/* implementations.
var productMap = map[string][]Coord{
	"redis":         {{Vendor: "redis", Product: "redis"}},
	"postgresql":    {{Vendor: "postgresql", Product: "postgresql"}},
	"mysql":         {{Vendor: "mysql", Product: "mysql"}, {Vendor: "oracle", Product: "mysql"}},
	"mongodb":       {{Vendor: "mongodb", Product: "mongodb"}},
	"memcached":     {{Vendor: "memcached", Product: "memcached"}},
	"elasticsearch": {{Vendor: "elastic", Product: "elasticsearch"}, {Vendor: "elasticsearch", Product: "elasticsearch"}},
	"kafka":         {{Vendor: "apache", Product: "kafka"}},
	"amqp":          {{Vendor: "pivotal_software", Product: "rabbitmq"}, {Vendor: "rabbitmq", Product: "rabbitmq"}},
	"mssql":         {{Vendor: "microsoft", Product: "sql_server"}},
	"smb":           {{Vendor: "samba", Product: "samba"}},
	"rdp":           {{Vendor: "microsoft", Product: "remote_desktop"}},
	"telnet":        {{Vendor: "gnu", Product: "inetutils"}},
	"ftp":           {{Vendor: "proftpd", Product: "proftpd"}, {Vendor: "vsftpd", Product: "vsftpd"}},
	"pop3":          {{Vendor: "dovecot", Product: "dovecot"}},
	"imap":          {{Vendor: "dovecot", Product: "dovecot"}},
	"vnc":           {{Vendor: "realvnc", Product: "vnc"}, {Vendor: "tightvnc", Product: "tightvnc"}},
	"mqtt":          {{Vendor: "eclipse", Product: "mosquitto"}}, //nolint:misspell // CPE product name
	"ldap":          {{Vendor: "openldap", Product: "openldap"}},
	"ipmi":          {{Vendor: "intel", Product: "ipmi"}},
	"snmp":          {{Vendor: "net-snmp", Product: "net-snmp"}},
	"ntp":           {{Vendor: "ntp", Product: "ntp"}},
	"dns":           {{Vendor: "isc", Product: "bind"}},
	"ssh":           {{Vendor: "openbsd", Product: "openssh"}, {Vendor: "openssh", Product: "openssh"}},
	"openssh":       {{Vendor: "openbsd", Product: "openssh"}, {Vendor: "openssh", Product: "openssh"}},
	"nginx":         {{Vendor: "nginx", Product: "nginx"}, {Vendor: "f5", Product: "nginx"}},
	"apache":        {{Vendor: "apache", Product: "http_server"}},
	"apache-httpd":  {{Vendor: "apache", Product: "http_server"}},
	"lighttpd":      {{Vendor: "lighttpd", Product: "lighttpd"}},
	"iis":           {{Vendor: "microsoft", Product: "internet_information_services"}, {Vendor: "microsoft", Product: "internet_information_server"}},
	"caddy":         {{Vendor: "caddyserver", Product: "caddy"}},
	"tomcat":        {{Vendor: "apache", Product: "tomcat"}},
	"jetty":         {{Vendor: "eclipse", Product: "jetty"}, {Vendor: "mortbay", Product: "jetty"}},
	"haproxy":       {{Vendor: "haproxy", Product: "haproxy"}},
	"envoy":         {{Vendor: "envoyproxy", Product: "envoy"}, {Vendor: "cncf", Product: "envoy"}},
	"traefik":       {{Vendor: "traefik", Product: "traefik"}, {Vendor: "containous", Product: "traefik"}},
	"openssl":       {{Vendor: "openssl", Product: "openssl"}},

	// Runtimes / language platforms.
	"php":     {{Vendor: "php", Product: "php"}},
	"php-fpm": {{Vendor: "php", Product: "php"}},
	"python":  {{Vendor: "python", Product: "python"}},
	"python3": {{Vendor: "python", Product: "python"}},
	"nodejs":  {{Vendor: "nodejs", Product: "node.js"}, {Vendor: "node.js", Product: "node.js"}},
	"node":    {{Vendor: "nodejs", Product: "node.js"}},
	"ruby":    {{Vendor: "ruby-lang", Product: "ruby"}},
	"perl":    {{Vendor: "perl", Product: "perl"}},
	"java":    {{Vendor: "oracle", Product: "jre"}, {Vendor: "oracle", Product: "jdk"}, {Vendor: "oracle", Product: "java_se"}},
	"openjdk": {{Vendor: "oracle", Product: "openjdk"}, {Vendor: "redhat", Product: "openjdk"}},
	"jre":     {{Vendor: "oracle", Product: "jre"}, {Vendor: "sun", Product: "jre"}},
	"jdk":     {{Vendor: "oracle", Product: "jdk"}, {Vendor: "sun", Product: "jdk"}},
	"dotnet":  {{Vendor: "microsoft", Product: ".net"}, {Vendor: "microsoft", Product: ".net_framework"}},
	"go":      {{Vendor: "golang", Product: "go"}},
	"golang":  {{Vendor: "golang", Product: "go"}},

	// Web app servers / proxies the existing map missed.
	"gunicorn":   {{Vendor: "gunicorn", Product: "gunicorn"}},
	"uwsgi":      {{Vendor: "unbit", Product: "uwsgi"}},
	"kong":       {{Vendor: "konghq", Product: "kong"}},
	"varnish":    {{Vendor: "varnish_cache_project", Product: "varnish_cache"}, {Vendor: "varnish-software", Product: "varnish_cache_plus"}},
	"squid":      {{Vendor: "squid-cache", Product: "squid"}},
	"openresty":  {{Vendor: "openresty", Product: "openresty"}},
	"nginx-plus": {{Vendor: "f5", Product: "nginx_plus"}},

	// Mail.
	"postfix":  {{Vendor: "postfix", Product: "postfix"}},
	"sendmail": {{Vendor: "proofpoint", Product: "sendmail"}, {Vendor: "sendmail", Product: "sendmail"}},
	"exim":     {{Vendor: "exim", Product: "exim"}},
	"courier":  {{Vendor: "courier-mta", Product: "courier-mta"}},

	// Databases / cache / queues the original map missed.
	"clickhouse": {{Vendor: "yandex", Product: "clickhouse"}, {Vendor: "clickhouse", Product: "clickhouse"}},
	"cassandra":  {{Vendor: "apache", Product: "cassandra"}},
	"scylla":     {{Vendor: "scylladb", Product: "scylla"}},
	"mariadb":    {{Vendor: "mariadb", Product: "mariadb"}},
	"cockroach":  {{Vendor: "cockroachlabs", Product: "cockroachdb"}, {Vendor: "cockroach_labs", Product: "cockroachdb"}},
	"influxdb":   {{Vendor: "influxdata", Product: "influxdb"}},
	"prometheus": {{Vendor: "prometheus", Product: "prometheus"}},
	"grafana":    {{Vendor: "grafana", Product: "grafana"}},
	"kibana":     {{Vendor: "elastic", Product: "kibana"}},
	"logstash":   {{Vendor: "elastic", Product: "logstash"}},
	"etcd":       {{Vendor: "etcd", Product: "etcd"}, {Vendor: "coreos", Product: "etcd"}},
	"zookeeper":  {{Vendor: "apache", Product: "zookeeper"}},
	"rabbitmq":   {{Vendor: "pivotal_software", Product: "rabbitmq"}, {Vendor: "rabbitmq", Product: "rabbitmq"}},
	"nats":       {{Vendor: "nats", Product: "nats-server"}, {Vendor: "synadia", Product: "nats_server"}},

	// DevOps platforms.
	"jenkins":       {{Vendor: "jenkins", Product: "jenkins"}, {Vendor: "cloudbees", Product: "jenkins"}},
	"gitlab":        {{Vendor: "gitlab", Product: "gitlab"}},
	"gitea":         {{Vendor: "gitea", Product: "gitea"}},
	"gogs":          {{Vendor: "gogs", Product: "gogs"}},
	"nexus":         {{Vendor: "sonatype", Product: "nexus"}, {Vendor: "sonatype", Product: "nexus_repository_manager"}},
	"harbor":        {{Vendor: "linuxfoundation", Product: "harbor"}, {Vendor: "vmware", Product: "harbor"}},
	"vault":         {{Vendor: "hashicorp", Product: "vault"}},
	"consul":        {{Vendor: "hashicorp", Product: "consul"}},
	"nomad":         {{Vendor: "hashicorp", Product: "nomad"}},
	"terraform":     {{Vendor: "hashicorp", Product: "terraform"}},
	"keycloak":      {{Vendor: "redhat", Product: "keycloak"}, {Vendor: "keycloak", Product: "keycloak"}},
	"sonarqube":     {{Vendor: "sonarsource", Product: "sonarqube"}},
	"argocd":        {{Vendor: "argoproj", Product: "argo_cd"}, {Vendor: "linuxfoundation", Product: "argo_cd"}},
	"prometheus-am": {{Vendor: "prometheus", Product: "alertmanager"}},

	// CMS / web apps.
	"wordpress":  {{Vendor: "wordpress", Product: "wordpress"}, {Vendor: "wordpress.org", Product: "wordpress"}},
	"drupal":     {{Vendor: "drupal", Product: "drupal"}},
	"joomla":     {{Vendor: "joomla", Product: "joomla\\!"}},
	"magento":    {{Vendor: "magento", Product: "magento"}, {Vendor: "adobe", Product: "commerce"}, {Vendor: "adobe", Product: "magento"}},
	"ghost":      {{Vendor: "ghost", Product: "ghost"}},
	"mediawiki":  {{Vendor: "mediawiki", Product: "mediawiki"}, {Vendor: "wikimedia", Product: "mediawiki"}},
	"typo3":      {{Vendor: "typo3", Product: "typo3"}},
	"phpmyadmin": {{Vendor: "phpmyadmin", Product: "phpmyadmin"}},
	"phpbb":      {{Vendor: "phpbb", Product: "phpbb"}},
	"redmine":    {{Vendor: "redmine", Product: "redmine"}},
	"discourse":  {{Vendor: "discourse", Product: "discourse"}},
	"nextcloud":  {{Vendor: "nextcloud", Product: "nextcloud_server"}, {Vendor: "nextcloud", Product: "nextcloud"}},
	"owncloud":   {{Vendor: "owncloud", Product: "owncloud"}, {Vendor: "owncloud", Product: "core"}},
	"moodle":     {{Vendor: "moodle", Product: "moodle"}},

	// Atlassian.
	"jira":       {{Vendor: "atlassian", Product: "jira"}, {Vendor: "atlassian", Product: "jira_server"}, {Vendor: "atlassian", Product: "jira_software"}},
	"confluence": {{Vendor: "atlassian", Product: "confluence"}, {Vendor: "atlassian", Product: "confluence_server"}, {Vendor: "atlassian", Product: "confluence_data_center"}},
	"bitbucket":  {{Vendor: "atlassian", Product: "bitbucket"}, {Vendor: "atlassian", Product: "bitbucket_server"}},
	"crowd":      {{Vendor: "atlassian", Product: "crowd"}},

	// MS / VMware enterprise.
	"exchange":   {{Vendor: "microsoft", Product: "exchange_server"}},
	"sharepoint": {{Vendor: "microsoft", Product: "sharepoint_server"}, {Vendor: "microsoft", Product: "sharepoint_foundation"}},
	"vcenter":    {{Vendor: "vmware", Product: "vcenter_server"}},
	"vsphere":    {{Vendor: "vmware", Product: "vsphere"}},
	"esxi":       {{Vendor: "vmware", Product: "esxi"}},

	// VPN / remote access.
	"openvpn":       {{Vendor: "openvpn", Product: "openvpn"}, {Vendor: "openvpn", Product: "openvpn_access_server"}},
	"wireguard":     {{Vendor: "wireguard", Product: "wireguard"}},
	"fortinet":      {{Vendor: "fortinet", Product: "fortios"}, {Vendor: "fortinet", Product: "fortigate"}},
	"pulse-vpn":     {{Vendor: "pulsesecure", Product: "pulse_connect_secure"}},
	"globalprotect": {{Vendor: "paloaltonetworks", Product: "globalprotect"}, {Vendor: "paloaltonetworks", Product: "pan-os"}},

	// Container / Kubernetes ecosystem.
	"docker":     {{Vendor: "docker", Product: "docker"}, {Vendor: "docker", Product: "engine"}},
	"containerd": {{Vendor: "linuxfoundation", Product: "containerd"}},
	"kubernetes": {{Vendor: "kubernetes", Product: "kubernetes"}},
	"kubelet":    {{Vendor: "kubernetes", Product: "kubernetes"}},
	"rancher":    {{Vendor: "suse", Product: "rancher"}, {Vendor: "rancher", Product: "rancher"}},

	// Misc commonly fingerprinted services.
	"strapi":   {{Vendor: "strapi", Product: "strapi"}},
	"mautic":   {{Vendor: "mautic", Product: "mautic"}},
	"airflow":  {{Vendor: "apache", Product: "airflow"}},
	"superset": {{Vendor: "apache", Product: "superset"}},
	"spark":    {{Vendor: "apache", Product: "spark"}},
	"flink":    {{Vendor: "apache", Product: "flink"}},
	"nifi":     {{Vendor: "apache", Product: "nifi"}},
	"solr":     {{Vendor: "apache", Product: "solr"}},
	"struts":   {{Vendor: "apache", Product: "struts"}},
	"hadoop":   {{Vendor: "apache", Product: "hadoop"}},
	"hive":     {{Vendor: "apache", Product: "hive"}},
	"druid":    {{Vendor: "apache", Product: "druid"}},

	// Russian-stack defaults often seen on local infrastructure.
	"1c-bitrix": {{Vendor: "bitrix", Product: "bitrix24"}, {Vendor: "1c-bitrix", Product: "bitrix_site_manager"}},
	"bitrix":    {{Vendor: "1c-bitrix", Product: "bitrix_site_manager"}, {Vendor: "bitrix", Product: "bitrix24"}},

	// Wire-form products picked up by the HTTP/TLS derived fingerprinters
	// (see internal/pkg/probe/derived.go). The HTTP server world is full of
	// these — adding them here is what turns "Server: Werkzeug/2.3.7" into
	// a real CVE match instead of a dropped fingerprint.
	"asp_net":   {{Vendor: "microsoft", Product: "asp.net_core"}, {Vendor: "microsoft", Product: ".net_framework"}, {Vendor: "microsoft", Product: ".net"}},
	"jboss":     {{Vendor: "redhat", Product: "jboss_enterprise_application_platform"}, {Vendor: "redhat", Product: "jboss_application_server"}},
	"wildfly":   {{Vendor: "redhat", Product: "wildfly"}, {Vendor: "wildfly", Product: "wildfly"}},
	"glassfish": {{Vendor: "oracle", Product: "glassfish_server"}, {Vendor: "eclipse", Product: "glassfish"}},
	"passenger": {{Vendor: "phusion", Product: "passenger"}},
	"werkzeug":  {{Vendor: "palletsprojects", Product: "werkzeug"}, {Vendor: "pallets", Product: "werkzeug"}},
	"express":   {{Vendor: "expressjs", Product: "express"}, {Vendor: "openjsf", Product: "express"}},
	"libssh":    {{Vendor: "libssh", Product: "libssh"}},
	"sun_one":   {{Vendor: "sun", Product: "one_web_server"}},
	"litespeed": {{Vendor: "litespeedtech", Product: "openlitespeed"}, {Vendor: "litespeedtech", Product: "litespeed_web_server"}},
	"webrick":   {{Vendor: "ruby-lang", Product: "ruby"}},
	"puma":      {{Vendor: "puma", Product: "puma"}},
	"unicorn":   {{Vendor: "unicorn_project", Product: "unicorn"}},
	"thin":      {{Vendor: "thin", Product: "thin"}},
	"hiawatha":  {{Vendor: "hiawatha-webserver", Product: "hiawatha"}},
	"openshift": {{Vendor: "redhat", Product: "openshift_container_platform"}, {Vendor: "redhat", Product: "openshift"}},
	"mailcow":   {{Vendor: "mailcow", Product: "mailcow_dockerized"}},

	// Industrial control systems (PLCs, building automation, IoT gateways)
	// — entries match the keys produced by probes/modbus.go, enip.go,
	// opcua.go, bacnet.go and jetdirect.go. We map vendor-specific banners
	// (Schneider, Rockwell, Siemens, Honeywell, Johnson Controls…) onto
	// the CPE coordinates the NVD catalog uses for *generic* product
	// families. Per-firmware CVEs land via VendorProduct lookups inside
	// cvematch once a leaf for that exact firmware revision exists.
	"modbus":                     {{Vendor: "modbus", Product: "modbus"}},
	"ethernet_ip":                {{Vendor: "odva", Product: "common_industrial_protocol"}, {Vendor: "rockwellautomation", Product: "ethernetip"}},
	"opcua":                      {{Vendor: "open62541", Product: "open62541"}, {Vendor: "opcfoundation", Product: "ua-.net-standard"}, {Vendor: "unified_automation", Product: "uasdk"}},
	"bacnet":                     {{Vendor: "ashrae", Product: "bacnet"}},
	"schneider_electric_modicon": {{Vendor: "schneider-electric", Product: "modicon"}, {Vendor: "schneider-electric", Product: "modicon_m340"}, {Vendor: "schneider-electric", Product: "ecostruxure_control_expert"}},
	"siemens_simatic":            {{Vendor: "siemens", Product: "simatic_s7-1200"}, {Vendor: "siemens", Product: "simatic_s7-1500"}, {Vendor: "siemens", Product: "simatic_s7-300"}, {Vendor: "siemens", Product: "simatic_s7-400"}, {Vendor: "siemens", Product: "step_7"}},
	"rockwell_logix":             {{Vendor: "rockwellautomation", Product: "controllogix"}, {Vendor: "rockwellautomation", Product: "compactlogix"}, {Vendor: "rockwellautomation", Product: "rslogix"}, {Vendor: "rockwellautomation", Product: "studio_5000_logix_designer"}},
	"wago_plc":                   {{Vendor: "wago", Product: "750_series"}, {Vendor: "wago", Product: "pfc200_firmware"}},
	"phoenix_contact_plc":        {{Vendor: "phoenixcontact", Product: "ilc_151_eth"}, {Vendor: "phoenixcontact", Product: "axc_3050"}, {Vendor: "phoenixcontact", Product: "axc_1050"}},
	"omron_plc":                  {{Vendor: "omron", Product: "cj2m"}, {Vendor: "omron", Product: "nj-series_machine_automation_controllers"}, {Vendor: "omron", Product: "sysmac_studio"}},
	"abb_plc":                    {{Vendor: "abb", Product: "ac500-eco"}, {Vendor: "abb", Product: "ac500"}, {Vendor: "abb", Product: "rtu500"}},
	"honeywell_bacnet":           {{Vendor: "honeywell", Product: "xls80e_firmware"}, {Vendor: "honeywell", Product: "experion_pks"}, {Vendor: "honeywell", Product: "ip-ak2"}},
	"johnson_controls":           {{Vendor: "johnsoncontrols", Product: "metasys"}, {Vendor: "johnsoncontrols", Product: "facility_explorer"}},
	"trane_bacnet":               {{Vendor: "trane", Product: "tracer_sc"}},
	"delta_controls_bacnet":      {{Vendor: "deltacontrols", Product: "entelitouch"}},
	"tridium_niagara":            {{Vendor: "tridium", Product: "niagara_framework"}, {Vendor: "tridium", Product: "niagara_4"}, {Vendor: "tridium", Product: "niagara_ax_framework"}},
	"automatedlogic_bacnet":      {{Vendor: "automatedlogic", Product: "webctrl"}},
	"kmc_controls":               {{Vendor: "kmccontrols", Product: "bac-9300"}},
	"kieback_peter_bacnet":       {{Vendor: "kieback-peter", Product: "dms"}},

	// Printers — CVE feed maps to firmware families, but the printer also
	// frequently exposes a vulnerable embedded web server and LPD service.
	"jetdirect":       {{Vendor: "hp", Product: "jetdirect"}},
	"hp_printer":      {{Vendor: "hp", Product: "laserjet"}, {Vendor: "hp", Product: "officejet_pro"}, {Vendor: "hp", Product: "deskjet"}, {Vendor: "hp", Product: "color_laserjet"}},
	"brother_printer": {{Vendor: "brother", Product: "printer_firmware"}},
	"kyocera_printer": {{Vendor: "kyoceradocumentsolutions", Product: "command_center_rx"}, {Vendor: "kyoceramita", Product: "command_center_rx"}},
	"lexmark_printer": {{Vendor: "lexmark", Product: "ms410_firmware"}, {Vendor: "lexmark", Product: "cx410_firmware"}, {Vendor: "lexmark", Product: "mx410_firmware"}},
	"xerox_printer":   {{Vendor: "xerox", Product: "workcentre"}, {Vendor: "xerox", Product: "phaser"}},
	"ricoh_printer":   {{Vendor: "ricoh", Product: "printer_firmware"}, {Vendor: "ricoh", Product: "im_c4500_firmware"}},
	"epson_printer":   {{Vendor: "epson", Product: "epson_printer_firmware"}},
	"canon_printer":   {{Vendor: "canon", Product: "printer_firmware"}, {Vendor: "canon", Product: "imagerunner_firmware"}},

	// Smart-home / IoT gateways. probeHTTP picks the banner up first
	// (since they all speak HTTP on 80/8080/3000/8123/8086…) and our
	// derived.go fingerprinter converts the Server / X-Powered-By /
	// <meta generator> tokens into the product names below.
	"home_assistant": {{Vendor: "home-assistant", Product: "home-assistant"}, {Vendor: "home_assistant", Product: "home_assistant_core"}},
	"tasmota":        {{Vendor: "tasmota", Product: "tasmota"}},
	"esphome":        {{Vendor: "esphome", Product: "esphome"}},
	"wled":           {{Vendor: "wled", Product: "wled"}},
	"shelly":         {{Vendor: "allterco_robotics", Product: "shelly_smart_relay"}, {Vendor: "shelly", Product: "shelly_pro_4pm_firmware"}},
	"hue_bridge":     {{Vendor: "philips", Product: "hue_bridge_firmware"}, {Vendor: "signify", Product: "hue_bridge"}},
	"openhab":        {{Vendor: "openhab", Product: "openhab"}},

	// IP cameras / DVR — banners are usually unique enough to derive a
	// vendor key, and the CPE coordinates point at the firmware family.
	"hikvision_camera": {{Vendor: "hikvision", Product: "ip_camera_firmware"}, {Vendor: "hikvision", Product: "dvr_firmware"}, {Vendor: "hikvision", Product: "nvr_firmware"}},
	"dahua_camera":     {{Vendor: "dahua", Product: "ip_camera_firmware"}, {Vendor: "dahuasecurity", Product: "ip_camera_firmware"}, {Vendor: "dahuasecurity", Product: "nvr_firmware"}},
	"axis_camera":      {{Vendor: "axis", Product: "communications_axis_os"}, {Vendor: "axis", Product: "axis_os"}, {Vendor: "axis", Product: "axis_camera_firmware"}},
	"foscam_camera":    {{Vendor: "foscam", Product: "ip_camera_firmware"}, {Vendor: "foscam", Product: "fi8918w_firmware"}},
	"reolink_camera":   {{Vendor: "reolink", Product: "camera_firmware"}},
	"ubiquiti_camera":  {{Vendor: "ui", Product: "unifi_video"}, {Vendor: "ubiquiti_networks", Product: "unifi_video"}},

	// Energy/SCADA protocol stacks. The probe writes the protocol name as
	// Product (dnp3, iec_60870_5_104) so the catalog still has a shot at
	// implementation-wide CVEs (e.g. open-source DNP3 stacks, Triangle
	// MicroWorks libraries used by dozens of substation vendors).
	"dnp3":            {{Vendor: "trianglemicroworks", Product: "scada_data_gateway"}, {Vendor: "automatak", Product: "opendnp3"}, {Vendor: "automatak", Product: "dnp3"}},
	"iec_60870_5_104": {{Vendor: "siemens", Product: "iec_104"}, {Vendor: "freyrscada", Product: "iec-60870-5-104"}, {Vendor: "openscada", Product: "iec_60870-5-104"}},
	"iec_61850_mms":   {{Vendor: "libiec61850", Product: "libiec61850"}, {Vendor: "schweitzer_engineering_laboratories", Product: "sel-3530_rtac"}, {Vendor: "sel", Product: "sel-3530"}},
	"knx_ip":          {{Vendor: "knx_association", Product: "knx_falcon_sdk"}, {Vendor: "calimero-project", Product: "calimero-core"}, {Vendor: "knx", Product: "knxd"}},
	"bacnet_secure":   {{Vendor: "ashrae", Product: "bacnet"}, {Vendor: "bacnet", Product: "bacnet"}},
	"lonworks":        {{Vendor: "echelon", Product: "smartserver_2"}, {Vendor: "echelon", Product: "lonworks"}, {Vendor: "echelon", Product: "i.lon"}},

	// Traffic-signal controllers. NTCIP-conformant boxes use SNMP for
	// configuration; their sysDescr leaks vendor + firmware. CPE
	// coordinates are stable for the big four US/EU manufacturers.
	"econolite_asc3":    {{Vendor: "econolite", Product: "eos"}, {Vendor: "econolite", Product: "cobalt"}, {Vendor: "econolite", Product: "asc_3"}},
	"econolite_cobalt":  {{Vendor: "econolite", Product: "cobalt"}},
	"mccain_atc":        {{Vendor: "mccain", Product: "atc"}, {Vendor: "mccain", Product: "atc_eX"}},
	"trafficware_atc":   {{Vendor: "trafficware", Product: "scout"}, {Vendor: "trafficware", Product: "commander"}, {Vendor: "cubic_its", Product: "scout"}},
	"siemens_sitraffic": {{Vendor: "siemens", Product: "sitraffic_concert"}, {Vendor: "siemens", Product: "scala"}, {Vendor: "siemens", Product: "sx_traffic_controller"}},
	"swarco_traffic":    {{Vendor: "swarco", Product: "trafficcontroller"}, {Vendor: "swarco", Product: "actros"}},
	"intelight_x1":      {{Vendor: "intelight", Product: "x1"}, {Vendor: "intelight", Product: "maxtime"}},

	// Lighting / building-automation control panels. These run either an
	// embedded HTTP UI or a proprietary TCP RPC; cvematch pairs them with
	// firmware-level applicability statements in the catalog.
	"lutron_homeworks": {{Vendor: "lutron", Product: "homeworks_qs"}, {Vendor: "lutron", Product: "radiora2"}, {Vendor: "lutron", Product: "caseta_pro"}},
	"crestron_control": {{Vendor: "crestron", Product: "control_system"}, {Vendor: "crestron", Product: "tsw_panel_firmware"}, {Vendor: "crestron_electronics", Product: "control_system_firmware"}},
	"amx_netlinx":      {{Vendor: "harman", Product: "amx_netlinx"}, {Vendor: "amx", Product: "netlinx"}},
	"helvar_imagine":   {{Vendor: "helvar", Product: "imagine_910"}, {Vendor: "helvar", Product: "imagine_router"}},
	"tridonic_dali":    {{Vendor: "tridonic", Product: "dali_gateway"}, {Vendor: "tridonic", Product: "x_gateway"}},
	"dynalite_dynet":   {{Vendor: "philips", Product: "dynalite"}, {Vendor: "signify", Product: "dynalite"}},
	"dali2_iot":        {{Vendor: "lunatone", Product: "dali2_iot"}, {Vendor: "lunatone", Product: "dali_cockpit"}},
	"casambi_gateway":  {{Vendor: "casambi", Product: "evolution_gateway"}, {Vendor: "casambi", Product: "key"}},

	// Energy management — relays, RTUs, smart inverters.
	"sel_rtac":       {{Vendor: "schweitzer_engineering_laboratories", Product: "sel-3530_rtac"}, {Vendor: "sel", Product: "rtac"}, {Vendor: "sel", Product: "sel-3530-4"}},
	"eaton_xcomfort": {{Vendor: "eaton", Product: "xcomfort_smart_home_controller"}, {Vendor: "eaton", Product: "intelligent_power_manager"}},
	"sma_inverter":   {{Vendor: "sma", Product: "sunny_webbox"}, {Vendor: "sma", Product: "sunny_boy_storage"}},
	"fronius_solar":  {{Vendor: "fronius", Product: "datamanager"}, {Vendor: "fronius", Product: "solar.web"}},

	// Network gear — Cisco / MikroTik / Ubiquiti / Juniper. Cisco IOS-XE
	// and RouterOS in particular have a long catalogue of remotely
	// exploitable CVEs.
	"cisco_ios":         {{Vendor: "cisco", Product: "ios"}, {Vendor: "cisco", Product: "ios_xe"}},
	"cisco_asa":         {{Vendor: "cisco", Product: "adaptive_security_appliance"}, {Vendor: "cisco", Product: "asa_5500-x"}},
	"cisco_nxos":        {{Vendor: "cisco", Product: "nx-os"}},
	"mikrotik_routeros": {{Vendor: "mikrotik", Product: "routeros"}, {Vendor: "mikrotik", Product: "router_os"}}, //nolint:misspell // RouterOS is MikroTik's product name
	"ubiquiti_edgeos":   {{Vendor: "ubiquiti_networks", Product: "edgeos"}, {Vendor: "ubiquiti", Product: "edgerouter_firmware"}, {Vendor: "ui", Product: "unifi"}},
	"juniper_junos":     {{Vendor: "juniper", Product: "junos"}, {Vendor: "juniper", Product: "junos_os"}},

	// Video management / access control — building, retail and city
	// surveillance suites.
	"genetec_security_center": {{Vendor: "genetec", Product: "security_center"}, {Vendor: "genetec", Product: "synergis_softwire"}},
	"milestone_xprotect":      {{Vendor: "milestone", Product: "xprotect_corporate"}, {Vendor: "milestonesys", Product: "xprotect"}, {Vendor: "milestone", Product: "xprotect_smart_client"}},
	"bosch_bvms":              {{Vendor: "bosch", Product: "video_management_system"}, {Vendor: "bosch", Product: "bvms"}},
	"honeywell_prowatch":      {{Vendor: "honeywell", Product: "pro-watch"}, {Vendor: "honeywell", Product: "prowatch"}},
	"avigilon_acc":            {{Vendor: "avigilon", Product: "control_center"}, {Vendor: "avigilon", Product: "acc"}},

	// EV charging / metering exposed over OCPP-WS or vendor HTTP.
	"abb_ev_charger":   {{Vendor: "abb", Product: "terra_ac_wallbox_firmware"}, {Vendor: "abb", Product: "terra_dc_charger_firmware"}},
	"schneider_evlink": {{Vendor: "schneider-electric", Product: "evlink_city"}, {Vendor: "schneider-electric", Product: "evlink_parking"}},
	"keba_charger":     {{Vendor: "keba", Product: "kecontact_p30"}, {Vendor: "keba", Product: "kecontact_p20"}},

	// OCPP central-system implementations. The probe lands here when the
	// /OCPP/<id> upgrade echoes back the ocpp1.6/ocpp2.0.1 subprotocol or
	// when the Server banner matches a known CSMS.
	"ocpp":              {{Vendor: "openchargealliance", Product: "ocpp"}, {Vendor: "ocpp", Product: "ocpp-j"}},
	"steve_ocpp":        {{Vendor: "rwth-i5", Product: "steve"}, {Vendor: "rwth-i5-it", Product: "steve"}},
	"maeve_csms":        {{Vendor: "thoughtworks", Product: "maeve_csms"}, {Vendor: "subnetzero", Product: "maeve"}},
	"wallbox_mywallbox": {{Vendor: "wallbox", Product: "mywallbox"}, {Vendor: "wallbox", Product: "copper_sb_firmware"}, {Vendor: "wallbox", Product: "pulsar_plus_firmware"}},
	"compleo_csms":      {{Vendor: "compleo", Product: "etrel_inch_pro_firmware"}, {Vendor: "compleo", Product: "ebox_charging_station"}},
	"ev_manager":        {{Vendor: "ev_manager", Product: "ev_manager"}},

	// CODESYS V3 / V2 runtime and gateway. Most field deployments
	// (Schneider M251, Wago PFC200, Bosch Rexroth IndraDrive, ABB AC500,
	// Beckhoff TwinCAT 2 legacy) re-package the same runtime, so cvematch
	// gets useful hits even when the firmware revision stays hidden.
	"codesys_v3": {{Vendor: "codesys", Product: "control_runtime_system_toolkit"}, {Vendor: "codesys", Product: "control_for_iot2000_sl"}, {Vendor: "codesys", Product: "control_v3"}, {Vendor: "codesys", Product: "gateway"}, {Vendor: "3s-smart_software_solutions", Product: "codesys"}},

	// Printing stack — IPP fallback when CUPS-specific markers aren't
	// detected, and the CUPS scheduler itself (which got hit by the
	// CVE-2024-47076/47175/47176/47177 chain that briefly looked like
	// the next Heartbleed).
	"cups": {{Vendor: "apple", Product: "cups"}, {Vendor: "openprinting", Product: "cups"}, {Vendor: "cups", Product: "cups"}, {Vendor: "openprinting", Product: "cups-browsed"}, {Vendor: "openprinting", Product: "cups-filters"}},
	"ipp":  {{Vendor: "pwg", Product: "ipp"}, {Vendor: "openprinting", Product: "ipp_everywhere"}},

	// Physical access control / payment-and-pass systems. CPE coordinates
	// match the firmware families NVD publishes for each ecosystem; many
	// of these systems (Lenel OnGuard, S2 NetBox, Software House C-CURE,
	// HID Mercury, Suprema BioStar) have a long track record of remotely
	// exploitable CVEs.
	"lenel_onguard":            {{Vendor: "lenel", Product: "onguard"}, {Vendor: "carrier", Product: "lenel_onguard"}},
	"software_house_ccure":     {{Vendor: "tyco", Product: "c-cure_9000"}, {Vendor: "softwarehouse", Product: "c-cure_9000"}, {Vendor: "johnsoncontrols", Product: "c-cure_9000"}},
	"software_house_istar":     {{Vendor: "tyco", Product: "istar_ultra"}, {Vendor: "softwarehouse", Product: "istar_ultra_firmware"}, {Vendor: "johnsoncontrols", Product: "istar_ultra"}},
	"s2_netbox":                {{Vendor: "s2", Product: "netbox"}, {Vendor: "lenel", Product: "netbox"}},
	"hid_mercury":              {{Vendor: "mercury_security", Product: "lp1502"}, {Vendor: "mercury_security", Product: "lp4502"}, {Vendor: "mercury_security", Product: "mr52"}, {Vendor: "hid", Product: "mercury_lp1501"}, {Vendor: "hid", Product: "mercury_lp1502_firmware"}},
	"hid_vertx":                {{Vendor: "hid", Product: "vertx_evo_v1000_firmware"}, {Vendor: "hid", Product: "vertx_evo_v2000_firmware"}},
	"hid_edge":                 {{Vendor: "hid", Product: "edge_evo_firmware"}, {Vendor: "hid", Product: "edge_evo"}},
	"identiv_velocity":         {{Vendor: "identiv", Product: "velocity"}, {Vendor: "hirsch", Product: "velocity"}},
	"gallagher_command":        {{Vendor: "gallagher", Product: "command_centre"}},
	"vanderbilt_aliro":         {{Vendor: "vanderbilt", Product: "aliro"}, {Vendor: "vanderbilt", Product: "siveillance_access"}},
	"suprema_biostar":          {{Vendor: "suprema", Product: "biostar_2"}, {Vendor: "supremainc", Product: "biostar_2"}},
	"zkteco_biosecurity":       {{Vendor: "zkteco", Product: "zkbiosecurity"}, {Vendor: "zkteco", Product: "pushsdk"}},
	"paxton_net2":              {{Vendor: "paxton", Product: "net2"}, {Vendor: "paxton-access", Product: "net2"}},
	"nedap_aeos":               {{Vendor: "nedap", Product: "aeos"}, {Vendor: "nedap-security-management", Product: "aeos"}},
	"genetec_synergis":         {{Vendor: "genetec", Product: "synergis_softwire"}, {Vendor: "genetec", Product: "synergis_master_controller"}},
	"axis_a1001":               {{Vendor: "axis", Product: "a1001_network_door_controller_firmware"}, {Vendor: "axis", Product: "a1601_network_door_controller_firmware"}},
	"axis_entry_manager":       {{Vendor: "axis", Product: "entry_manager"}},
	"bolid_orion":              {{Vendor: "bolid", Product: "orion_pro"}, {Vendor: "bolid", Product: "s2000m"}},
	"perco_web":                {{Vendor: "perco", Product: "web2"}, {Vendor: "perco", Product: "s-20"}},
	"sigur_access":             {{Vendor: "sigur", Product: "access_management"}},
	"skidata_parking":          {{Vendor: "skidata", Product: "parking_management_system"}},
	"scheidt_bachmann_entervo": {{Vendor: "scheidt-bachmann", Product: "entervo"}},

	// Fare-collection / public transport ticketing back-ends. Often
	// expose HTTP UIs on field terminals or fare gates.
	"cubic_nextfare":  {{Vendor: "cubic", Product: "nextfare"}, {Vendor: "cubic_transportation_systems", Product: "nextfare"}},
	"thales_revenue":  {{Vendor: "thales", Product: "revenue_collection_system"}, {Vendor: "thales", Product: "transport_ticketing_system"}},
	"indra_ticketing": {{Vendor: "indra", Product: "ticketing"}, {Vendor: "indracompany", Product: "ticketing_system"}},

	// Fire-alarm panels / mass-notification systems. Their embedded web
	// UIs (and Modbus / BACnet stacks) routinely show up in CVE feeds.
	"notifier_onyx":    {{Vendor: "honeywell", Product: "onyx_nfn_gateway"}, {Vendor: "honeywell", Product: "onyxworks"}, {Vendor: "honeywell", Product: "notifier_inspire_facp_firmware"}},
	"siemens_cerberus": {{Vendor: "siemens", Product: "cerberus_pro_fc72x"}, {Vendor: "siemens", Product: "cerberus_pro_fs720"}, {Vendor: "siemens", Product: "cerberus_dms"}},
	"bosch_avenar":     {{Vendor: "bosch", Product: "avenar_panel_8000_firmware"}, {Vendor: "bosch", Product: "avenar_panel_2000_firmware"}, {Vendor: "bosch", Product: "fpa-1200"}},
	"edwards_est3":     {{Vendor: "edwards", Product: "est3_firmware"}, {Vendor: "carrier", Product: "est3"}, {Vendor: "edwards", Product: "est3x_firmware"}},
	"simplex_4100es":   {{Vendor: "simplex", Product: "4100es_firmware"}, {Vendor: "tyco", Product: "simplex_4100es"}, {Vendor: "johnsoncontrols", Product: "simplex_4100es_firmware"}},
	"schrack_seconet":  {{Vendor: "schrack-seconet", Product: "integral_ip"}, {Vendor: "schrack-seconet", Product: "integral_mx"}},
	"apollo_fire":      {{Vendor: "apollo", Product: "discovery_facp_firmware"}, {Vendor: "apollo-fire-detectors", Product: "discovery"}},
	"hochiki_fire":     {{Vendor: "hochiki", Product: "ekho"}, {Vendor: "hochiki", Product: "esp-r"}},
	"gent_fire":        {{Vendor: "gent", Product: "vigilon"}, {Vendor: "honeywell", Product: "gent_vigilon"}},
	"morley_facp":      {{Vendor: "morley-ias", Product: "zx-series"}, {Vendor: "honeywell", Product: "morley_zx5"}},
	"autronica_fire":   {{Vendor: "autronica", Product: "autroprime"}, {Vendor: "autronica", Product: "autrosafe"}},

	// Water / wastewater SCADA and process historians. These all sit on
	// long-running OT networks and accumulate CVEs faster than most IT
	// stacks because patch cycles are 2-5 years.
	"mitsubishi_melsec":  {{Vendor: "mitsubishielectric", Product: "melsec_iq-r_series"}, {Vendor: "mitsubishielectric", Product: "melsec_iq-f_series"}, {Vendor: "mitsubishielectric", Product: "melsec_q_series"}, {Vendor: "mitsubishi", Product: "melsec"}},
	"osisoft_pi":         {{Vendor: "osisoft", Product: "pi_server"}, {Vendor: "osisoft", Product: "pi_web_api"}, {Vendor: "aveva", Product: "pi_server"}, {Vendor: "aveva", Product: "pi_data_archive"}},
	"wonderware_intouch": {{Vendor: "aveva", Product: "intouch"}, {Vendor: "aveva", Product: "system_platform"}, {Vendor: "wonderware", Product: "intouch"}, {Vendor: "schneider-electric", Product: "intouch_access_anywhere"}},
	"iconics_genesis":    {{Vendor: "iconics", Product: "genesis64"}, {Vendor: "mitsubishielectric", Product: "iconics_genesis64"}},
	"yokogawa_centum":    {{Vendor: "yokogawa", Product: "centum_vp"}, {Vendor: "yokogawa", Product: "centum_cs_3000"}, {Vendor: "yokogawa", Product: "exaopc"}},
	"emerson_deltav":     {{Vendor: "emerson", Product: "deltav"}, {Vendor: "emersonprocess", Product: "deltav"}},
	"emerson_ovation":    {{Vendor: "emerson", Product: "ovation"}, {Vendor: "westinghouse", Product: "ovation"}},
	"abb_800xa":          {{Vendor: "abb", Product: "system_800xa"}, {Vendor: "abb", Product: "800xa"}},
	"endress_hauser":     {{Vendor: "endress-hauser", Product: "fieldcare"}, {Vendor: "endress-hauser", Product: "memograph_m_rsg45"}},
	"sensus_flexnet":     {{Vendor: "sensus", Product: "flexnet"}, {Vendor: "xylem", Product: "sensus_flexnet"}},
	"itron_openway":      {{Vendor: "itron", Product: "openway_riva"}, {Vendor: "itron", Product: "centron"}},
	"hach_wims":          {{Vendor: "hach", Product: "wims"}, {Vendor: "hach", Product: "claros"}},
	"mueller_mi":         {{Vendor: "mueller", Product: "mi.net"}, {Vendor: "mueller-water-products", Product: "hydro-guard"}},
	"badger_meter":       {{Vendor: "badgermeter", Product: "beacon_ama"}, {Vendor: "badger-meter", Product: "orion_se"}},

	// Smart irrigation controllers. Hunter Hydrawise + Rain Bird ESP-Me
	// + Toro Tempus account for ~80% of the commercial market.
	"rain_bird_esp":     {{Vendor: "rainbird", Product: "esp-tm2_firmware"}, {Vendor: "rainbird", Product: "esp-me_firmware"}, {Vendor: "rain_bird", Product: "lnk_wifi_module"}},
	"hunter_hydrawise":  {{Vendor: "hunterindustries", Product: "hydrawise"}, {Vendor: "hunter", Product: "hydrawise_cloud"}},
	"toro_tempus":       {{Vendor: "toro", Product: "tempus_air_firmware"}, {Vendor: "toro", Product: "sentinel_central_control"}},
	"netafim_netbeat":   {{Vendor: "netafim", Product: "netbeat_controller"}, {Vendor: "netafim", Product: "growsphere"}},
	"galcon_irrigation": {{Vendor: "galcon", Product: "wifi_controller"}, {Vendor: "galcon", Product: "8056"}},

	// Smart-appliance cloud gateways. These almost never speak a probe-
	// friendly protocol on the LAN — the appliance phones home via TLS
	// to a vendor cloud, and only a thin admin UI is reachable from the
	// scanner. cvematch picks them up through TLS Subject / Server
	// header markers (derived.go), so the CPE coordinates below land
	// version-less applicability matches on each vendor's published
	// CPE — useful for catalogue entries that affect all firmware
	// builds (e.g. Samsung Family Hub cookie-leak CVEs).
	"samsung_smartthings":     {{Vendor: "samsung", Product: "smartthings"}, {Vendor: "samsung", Product: "smartthings_hub_firmware"}, {Vendor: "samsung", Product: "smartthings_station_firmware"}},
	"lg_thinq":                {{Vendor: "lg", Product: "thinq"}, {Vendor: "lge", Product: "thinq"}, {Vendor: "lg", Product: "smartthinq_app"}},
	"bsh_home_connect":        {{Vendor: "bsh-group", Product: "home_connect"}, {Vendor: "bsh_hausgeraete", Product: "home_connect"}, {Vendor: "bosch", Product: "home_connect"}},
	"whirlpool_smart":         {{Vendor: "whirlpool", Product: "6th_sense_live"}, {Vendor: "whirlpool", Product: "smart_appliance_firmware"}, {Vendor: "whirlpool", Product: "whirlpool_app"}},
	"haier_hon":               {{Vendor: "haier", Product: "hon"}, {Vendor: "haier", Product: "hon_app"}, {Vendor: "haier", Product: "smart_appliance_firmware"}},
	"liebherr_smartdevicebox": {{Vendor: "liebherr", Product: "smartdevicebox"}, {Vendor: "liebherr", Product: "smartdevice_firmware"}},
	"miele_xkm":               {{Vendor: "miele", Product: "xkm_3100w"}, {Vendor: "miele", Product: "xgw3000"}, {Vendor: "miele", Product: "miele_at_home"}},
	"electrolux_appliances":   {{Vendor: "electrolux", Product: "my_electrolux"}, {Vendor: "electrolux", Product: "aeg_my_aeg_kitchen"}, {Vendor: "electrolux", Product: "smart_appliance_firmware"}},

	// Smart TVs / set-top boxes / cast receivers. Probes for Tizen
	// (samsung_tv.go), webOS (webos_tv.go), Cast/Android TV
	// (chromecast.go), Roku (roku.go) and AirPlay (airplay.go) write
	// these product keys directly. The Sony BRAVIA / Xiaomi Mi TV / TCL
	// / Hisense / Vizio entries are reached through derived.go header
	// and TLS-subject aliases — they don't run a dedicated probe yet.
	"samsung_tizen_tv":  {{Vendor: "samsung", Product: "tizen"}, {Vendor: "samsung", Product: "tizen_firmware"}, {Vendor: "samsung", Product: "smart_tv_firmware"}, {Vendor: "tizenproject", Product: "tizen"}},
	"lg_webos_tv":       {{Vendor: "lg", Product: "webos"}, {Vendor: "lge", Product: "webos"}, {Vendor: "lg", Product: "webos_tv_firmware"}, {Vendor: "lge", Product: "webos_tv_firmware"}},
	"google_chromecast": {{Vendor: "google", Product: "chromecast"}, {Vendor: "google", Product: "chromecast_firmware"}, {Vendor: "google", Product: "cast"}, {Vendor: "google", Product: "android_tv"}, {Vendor: "google", Product: "android_tv_firmware"}},
	"roku_tv":           {{Vendor: "roku", Product: "roku_os"}, {Vendor: "roku", Product: "streaming_player_firmware"}, {Vendor: "roku", Product: "tv_firmware"}, {Vendor: "roku", Product: "roku"}},
	"apple_tv":          {{Vendor: "apple", Product: "tvos"}, {Vendor: "apple", Product: "apple_tv"}, {Vendor: "apple", Product: "apple_tv_firmware"}, {Vendor: "apple", Product: "airplay"}},
	"sony_bravia_tv":    {{Vendor: "sony", Product: "bravia"}, {Vendor: "sony", Product: "bravia_firmware"}, {Vendor: "sony", Product: "android_tv_firmware"}, {Vendor: "sony", Product: "smart_tv_firmware"}},
	"xiaomi_mi_tv":      {{Vendor: "xiaomi", Product: "mi_tv"}, {Vendor: "xiaomi", Product: "mi_tv_firmware"}, {Vendor: "xiaomi", Product: "mitv_stick"}},
	"tcl_android_tv":    {{Vendor: "tcl", Product: "android_tv_firmware"}, {Vendor: "tcl", Product: "smart_tv_firmware"}, {Vendor: "tcl", Product: "google_tv_firmware"}},
	"hisense_vidaa":     {{Vendor: "hisense", Product: "vidaa"}, {Vendor: "hisense", Product: "vidaa_firmware"}, {Vendor: "hisense", Product: "smart_tv_firmware"}},
	"vizio_smartcast":   {{Vendor: "vizio", Product: "smartcast"}, {Vendor: "vizio", Product: "smartcast_firmware"}, {Vendor: "vizio", Product: "smart_tv_firmware"}},

	// Precision-agriculture controllers / farm-management gateways. Many
	// are HTTP-frontended Linux boxes with vendor-branded admin consoles.
	"john_deere_jdlink":  {{Vendor: "deere", Product: "jdlink"}, {Vendor: "deere", Product: "operations_center"}, {Vendor: "deere", Product: "4g_mtg"}},
	"agleader_incommand": {{Vendor: "ag_leader", Product: "incommand_1200_firmware"}, {Vendor: "ag-leader", Product: "incommand_800_firmware"}},
	"trimble_ag":         {{Vendor: "trimble", Product: "ag_software"}, {Vendor: "trimble", Product: "agdata_solutions"}, {Vendor: "trimble", Product: "tmx-2050_firmware"}},
	"topcon_x35":         {{Vendor: "topcon", Product: "x35_ag_console_firmware"}, {Vendor: "topcon", Product: "x14_console"}},
	"raven_viper":        {{Vendor: "ravenind", Product: "viper_4"}, {Vendor: "raven_industries", Product: "viper_4+_firmware"}},
	"lely_astronaut":     {{Vendor: "lely", Product: "astronaut_a5_firmware"}, {Vendor: "lely", Product: "vector"}, {Vendor: "lely", Product: "discovery_120"}},
	"delaval_vms":        {{Vendor: "delaval", Product: "vms_v300_firmware"}, {Vendor: "delaval", Product: "delpro"}},
	"gea_dairy":          {{Vendor: "gea", Product: "dairyplan_c21"}, {Vendor: "gea-group", Product: "dairyplan_c21"}},
	"nedap_cowcontrol":   {{Vendor: "nedap-livestock", Product: "cowcontrol"}, {Vendor: "nedap", Product: "smarttag_neck"}},
	"valley_irrigation":  {{Vendor: "valley_irrigation", Product: "icon_x_firmware"}, {Vendor: "valley", Product: "icon10"}},
	"lindsay_fieldnet":   {{Vendor: "lindsay", Product: "fieldnet_advisor"}, {Vendor: "lindsay-corporation", Product: "fieldnet"}},

	// Broad IoT ecosystem — hubs, gateways, bridges. Most of these are
	// keyed off the manufacturer's wire-form name as it appears in
	// Server / X-Powered-By headers, mDNS service names, or the UPnP
	// device description XML. CPE coordinates pick the firmware family
	// NVD attaches CVEs to; when the catalog uses several vendor names
	// for the same hardware (e.g. Signify vs Philips for Hue v2), we
	// list both so cvematch sees every candidate.
	"zigbee2mqtt":             {{Vendor: "koenkk", Product: "zigbee2mqtt"}, {Vendor: "zigbee2mqtt", Product: "zigbee2mqtt"}},
	"deconz_conbee":           {{Vendor: "dresden-elektronik", Product: "deconz"}, {Vendor: "dresden_elektronik", Product: "conbee_ii"}},
	"zwave_js_ui":             {{Vendor: "zwave-js", Product: "zwave-js-ui"}, {Vendor: "zwave-js", Product: "zwavejs2mqtt"}},
	"aeotec_zstick":           {{Vendor: "aeotec", Product: "z-stick_7"}, {Vendor: "aeon_labs", Product: "z-stick"}},
	"homey_pro":               {{Vendor: "athom", Product: "homey_pro"}, {Vendor: "athom", Product: "homey"}},
	"samsung_smartthings_hub": {{Vendor: "samsung", Product: "smartthings_hub_firmware"}, {Vendor: "smartthings", Product: "hub_v3_firmware"}, {Vendor: "aeotec", Product: "smartthings_hub_v3"}},
	"apple_homekit_bridge":    {{Vendor: "apple", Product: "homekit"}, {Vendor: "homebridge", Product: "homebridge"}},
	"matter_otbr":             {{Vendor: "openthread", Product: "ot-br-posix"}, {Vendor: "nordicsemi", Product: "openthread_border_router"}, {Vendor: "google", Product: "openthread_border_router"}},
	"matter_node":             {{Vendor: "csa-iot", Product: "matter"}, {Vendor: "project-chip", Product: "connectedhomeip"}},

	// Voice assistants, smart speakers, multi-room audio.
	"amazon_echo":       {{Vendor: "amazon", Product: "echo_dot"}, {Vendor: "amazon", Product: "echo_show"}, {Vendor: "amazon", Product: "alexa"}},
	"google_nest_audio": {{Vendor: "google", Product: "nest_audio"}, {Vendor: "google", Product: "nest_mini"}, {Vendor: "google", Product: "nest_hub_firmware"}},
	"bose_soundtouch":   {{Vendor: "bose", Product: "soundtouch_10"}, {Vendor: "bose", Product: "soundtouch_30_firmware"}},
	"denon_heos":        {{Vendor: "denon", Product: "heos"}, {Vendor: "denon", Product: "heos_drive_firmware"}, {Vendor: "soundunited", Product: "heos"}},
	"yamaha_musiccast":  {{Vendor: "yamaha", Product: "musiccast"}, {Vendor: "yamahacorporation", Product: "musiccast"}},
	"sonos":             {{Vendor: "sonos", Product: "sonos"}, {Vendor: "sonos", Product: "controller"}, {Vendor: "sonos", Product: "play_5"}, {Vendor: "sonos", Product: "one_firmware"}},

	// Smart locks. Most of these are paired with vendor cloud bridges
	// but the on-device firmware itself is what NVD CVEs target.
	"august_lock":    {{Vendor: "august", Product: "smart_lock"}, {Vendor: "august_home", Product: "wi-fi_smart_lock_firmware"}},
	"yale_assure":    {{Vendor: "yale", Product: "assure_lock"}, {Vendor: "assa_abloy", Product: "yale_assure_lock_firmware"}},
	"schlage_encode": {{Vendor: "schlage", Product: "encode"}, {Vendor: "allegion", Product: "schlage_encode_firmware"}},
	"kwikset_halo":   {{Vendor: "kwikset", Product: "halo"}, {Vendor: "spectrum_brands", Product: "kwikset_halo_firmware"}},
	"lockly_secure":  {{Vendor: "lockly", Product: "secure_pro_firmware"}, {Vendor: "lockly", Product: "vision_firmware"}},
	"igloohome":      {{Vendor: "igloohome", Product: "smart_padlock"}, {Vendor: "igloohome", Product: "smart_lock_firmware"}},

	// Consumer / prosumer cameras + doorbells that the existing camera
	// section didn't already cover.
	"ring_doorbell":  {{Vendor: "ring", Product: "video_doorbell"}, {Vendor: "amazon", Product: "ring_doorbell_firmware"}, {Vendor: "ring", Product: "stickup_cam_firmware"}},
	"nest_doorbell":  {{Vendor: "google", Product: "nest_doorbell"}, {Vendor: "google", Product: "nest_cam"}, {Vendor: "nest", Product: "doorbell_firmware"}},
	"arlo_pro":       {{Vendor: "arlo", Product: "pro_3_firmware"}, {Vendor: "arlo_technologies", Product: "base_station_firmware"}, {Vendor: "netgear", Product: "arlo"}},
	"eufy_security":  {{Vendor: "eufy", Product: "security_camera_firmware"}, {Vendor: "anker", Product: "eufy_security_camera"}},
	"wyze_cam":       {{Vendor: "wyze", Product: "cam_v3_firmware"}, {Vendor: "wyze_labs", Product: "cam_pan_v2_firmware"}},
	"amcrest_camera": {{Vendor: "amcrest", Product: "ip_camera_firmware"}, {Vendor: "amcrest", Product: "ip2m-841_firmware"}},
	"swann_dvr":      {{Vendor: "swann", Product: "dvr_firmware"}, {Vendor: "swann", Product: "nvr_firmware"}, {Vendor: "swann_communications", Product: "dvr_firmware"}},
	"vivotek_camera": {{Vendor: "vivotek", Product: "ip_camera_firmware"}, {Vendor: "vivotek", Product: "network_camera_firmware"}},

	// Sensor hubs and automation gateways beyond the original
	// Tasmota/ESPHome/Shelly/Hue v1 block.
	"aqara_hub":            {{Vendor: "aqara", Product: "hub_m2_firmware"}, {Vendor: "aqara", Product: "hub_e1_firmware"}, {Vendor: "lumi", Product: "aqara_hub"}},
	"sonoff_zbbridge":      {{Vendor: "sonoff", Product: "zbbridge"}, {Vendor: "itead", Product: "sonoff_zbbridge_firmware"}},
	"philips_hue_v2":       {{Vendor: "signify", Product: "hue_bridge_2"}, {Vendor: "signify_netherlands", Product: "hue_bridge_2"}, {Vendor: "philips", Product: "hue_bridge_v2"}},
	"lifx_bulb":            {{Vendor: "lifx", Product: "smart_bulb"}, {Vendor: "lifx", Product: "lifx_bulb_firmware"}},
	"nanoleaf_aurora":      {{Vendor: "nanoleaf", Product: "aurora"}, {Vendor: "nanoleaf", Product: "light_panels_firmware"}, {Vendor: "nanoleaf", Product: "canvas_firmware"}},
	"yeelight":             {{Vendor: "yeelight", Product: "smart_bulb"}, {Vendor: "xiaomi", Product: "yeelight"}, {Vendor: "yeelink", Product: "yeelight"}},
	"ikea_dirigera":        {{Vendor: "ikea", Product: "dirigera"}, {Vendor: "ikea_of_sweden", Product: "dirigera_firmware"}},
	"ikea_tradfri_gateway": {{Vendor: "ikea", Product: "tradfri_gateway_firmware"}, {Vendor: "ikea_of_sweden", Product: "tradfri_gateway"}},

	// Industrial IoT / Edge gateway brands. These appliances tend to
	// host vendor-branded Linux distros with a long-lived HTTP admin UI.
	"dell_edge_gateway":      {{Vendor: "dell", Product: "edge_gateway_3000"}, {Vendor: "dell", Product: "edge_gateway_5100"}, {Vendor: "dell", Product: "edge_gateway_5200"}},
	"advantech_iot":          {{Vendor: "advantech", Product: "wise-paas"}, {Vendor: "advantech", Product: "edgelink"}, {Vendor: "advantech", Product: "uno-2271g_firmware"}},
	"moxa_iot":               {{Vendor: "moxa", Product: "uc-8112-me-t-linux"}, {Vendor: "moxa", Product: "mgate_mb3170_firmware"}, {Vendor: "moxa", Product: "iologik_e1212_firmware"}},
	"siemens_iot2050":        {{Vendor: "siemens", Product: "simatic_iot2050"}, {Vendor: "siemens", Product: "simatic_iot2040"}, {Vendor: "siemens", Product: "iot2050_firmware"}},
	"phoenix_contact_router": {{Vendor: "phoenixcontact", Product: "fl_mguard_rs4000_firmware"}, {Vendor: "phoenixcontact", Product: "tc_router_3002t-4g"}, {Vendor: "phoenixcontact", Product: "fl_switch_3005"}},
	"red_lion_iot":           {{Vendor: "redlion", Product: "flexedge"}, {Vendor: "red_lion_controls", Product: "graphite_hmi_firmware"}, {Vendor: "redlion", Product: "n-tron_702-w"}},

	// Protocol-stack keys used directly by the new probes (coap.go,
	// tuya.go, sonos.go, wemo.go, xiaomi_miio.go, edgex.go).
	"coap":               {{Vendor: "ietf", Product: "coap"}, {Vendor: "californium", Product: "californium"}, {Vendor: "eclipse", Product: "californium"}},
	"lwm2m":              {{Vendor: "openmobilealliance", Product: "lwm2m"}, {Vendor: "eclipse", Product: "leshan"}, {Vendor: "eclipse", Product: "wakaama"}},
	"tuya_device":        {{Vendor: "tuya", Product: "smart_device_firmware"}, {Vendor: "tuya", Product: "smart_life"}, {Vendor: "tuya", Product: "tuya_convenience_go_firmware"}},
	"belkin_wemo":        {{Vendor: "belkin", Product: "wemo_insight_switch_firmware"}, {Vendor: "belkin", Product: "wemo_smart_plug_firmware"}, {Vendor: "belkin", Product: "wemo_switch_firmware"}, {Vendor: "linksys", Product: "wemo_link_firmware"}},
	"xiaomi_miio_device": {{Vendor: "xiaomi", Product: "miio"}, {Vendor: "xiaomi", Product: "mi_home"}, {Vendor: "xiaomi", Product: "mihome"}},
	"edgex_foundry":      {{Vendor: "linuxfoundation", Product: "edgex_foundry"}, {Vendor: "edgexfoundry", Product: "core-data"}, {Vendor: "edgexfoundry", Product: "edgex-go"}},

	// EV charging stations beyond the OCPP-WS / ABB-Schneider-KEBA
	// trio above. Most consumer and commercial wallboxes don't expose
	// a proprietary on-port protocol — they speak OCPP-WS to the
	// vendor cloud, Modbus TCP for grid coupling, and a plain
	// HTTP/HTTPS admin console. The fingerprint lands here through
	// derived.go aliases on the Server header and self-signed TLS
	// Subject markers, and — for Tesla Wall Connector — via a JSON
	// body shape (see tesla_wallconnector.go) that no other vendor
	// produces. CPE coordinates are best-guess for vendors whose
	// firmware does not yet have a dedicated NVD applicability entry.
	"tesla_wall_connector":  {{Vendor: "tesla", Product: "wall_connector_gen_3_firmware"}},
	"wallbox_pulsar":        {{Vendor: "wallbox", Product: "pulsar_plus_firmware"}},
	"wallbox_quasar":        {{Vendor: "wallbox", Product: "quasar_firmware"}},
	"easee_home":            {{Vendor: "easee", Product: "home_charger_firmware"}, {Vendor: "easee", Product: "equalizer"}},
	"alfen_eve":             {{Vendor: "alfen", Product: "eve_single_pro-line"}, {Vendor: "alfen", Product: "eve_double_pro-line"}, {Vendor: "alfen", Product: "nf-firmware"}},
	"webasto_live":          {{Vendor: "webasto", Product: "live_charging_station"}},
	"evbox_elvi":            {{Vendor: "evbox", Product: "elvi_firmware"}, {Vendor: "evbox", Product: "liviqo"}, {Vendor: "engie", Product: "evbox_elvi"}},
	"chargepoint_home_flex": {{Vendor: "chargepoint", Product: "home_flex_firmware"}},
	"enelx_juicebox":        {{Vendor: "enelx", Product: "juicebox_40_firmware"}, {Vendor: "enelx", Product: "juicepump_firmware"}},
	"garo_gnm":              {{Vendor: "garo", Product: "gnm_firmware"}, {Vendor: "garo", Product: "entity_pro"}},
	"phoenix_contact_charx": {{Vendor: "phoenixcontact", Product: "charx_sec-3100_firmware"}},
	"keba_p40":              {{Vendor: "keba", Product: "kecontact_p40_firmware"}},
	"v2c_trydan":            {{Vendor: "v2c", Product: "trydan_firmware"}},
	"circontrol_raption":    {{Vendor: "circontrol", Product: "raption_firmware"}},
	"innogy_ebox":           {{Vendor: "innogy", Product: "eboxprofessional_firmware"}, {Vendor: "eon", Product: "drive_v2g"}},
	"smappee_ev_wall":       {{Vendor: "smappee", Product: "ev_wall_firmware"}},
	"myenergi_zappi":        {{Vendor: "myenergi", Product: "zappi_firmware"}, {Vendor: "myenergi", Product: "eddi_firmware"}},
	"andersen_a2":           {{Vendor: "andersen-ev", Product: "a2_firmware"}},
	"ohme_home_pro":         {{Vendor: "ohme", Product: "home_pro_firmware"}},
	"tritium_pkm":           {{Vendor: "tritium", Product: "pk-series_firmware"}, {Vendor: "tritium", Product: "rt175s_firmware"}},
	"delta_dc":              {{Vendor: "delta", Product: "dc_fast_charger_firmware"}, {Vendor: "delta_energy", Product: "ufc_200_firmware"}},
	"signet_dc":             {{Vendor: "signet", Product: "ev_charger_firmware"}},
	"efacec_qc":             {{Vendor: "efacec", Product: "qc45_firmware"}},
	"touchenergy_ru":        {{Vendor: "touchenergy", Product: "ac_charger_firmware"}},
	"parkline_ev_ru":        {{Vendor: "parkline", Product: "ev_charger_firmware"}},
	"evolve_charge":         {{Vendor: "evolve-charge", Product: "firmware"}},

	// Oracle Net "Listener" — exposed by every Oracle Database instance on
	// TCP 1521/1522/1525/2483. CPE-side, NVD lists vulnerabilities under
	// both oracle/database_server and oracle/database depending on the
	// applicability range, so both are returned to give cvematch a chance
	// at either ranking.
	"oracle_database": {{Vendor: "oracle", Product: "database_server"}, {Vendor: "oracle", Product: "database"}},

	// IPsec / IKE — VPN concentrators (Cisco ASA / ASR / IOS, Fortinet
	// FortiGate, Palo Alto PAN-OS, SonicWall, Check Point, strongSwan,
	// Libreswan, Mikrotik RouterOS, Juniper SRX). The generic "ipsec_ike"
	// key buys us strongSwan/libreswan CVEs out of the box; vendor-side
	// CVEs are picked up via the dedicated firmware/CPE keys those
	// products already map to elsewhere.
	"ipsec_ike": {{Vendor: "strongswan", Product: "strongswan"}, {Vendor: "libreswan", Product: "libreswan"}},

	// SIP servers and PBX stacks — anything that answers OPTIONS on
	// UDP 5060. The umbrella key keeps a CPE on file when we cannot pin
	// the exact stack; specific PBX brands resolve through the keys
	// below.
	"sip_server":        {{Vendor: "ietf", Product: "session_initiation_protocol"}},
	"asterisk_pbx":      {{Vendor: "asterisk", Product: "asterisk"}, {Vendor: "digium", Product: "asterisk"}},
	"freepbx":           {{Vendor: "sangoma", Product: "freepbx"}, {Vendor: "freepbx", Product: "freepbx"}},
	"tcx_phone_system":  {{Vendor: "3cx", Product: "3cx_phone_system"}},
	"freeswitch":        {{Vendor: "freeswitch", Product: "freeswitch"}, {Vendor: "signalwire", Product: "freeswitch"}},
	"kamailio":          {{Vendor: "kamailio", Product: "kamailio"}},
	"opensips":          {{Vendor: "opensips", Product: "opensips"}},
	"mitel_sip":         {{Vendor: "mitel", Product: "micollab"}, {Vendor: "mitel", Product: "mivoice_connect"}},
	"cisco_sip_gateway": {{Vendor: "cisco", Product: "ios"}, {Vendor: "cisco", Product: "unified_communications_manager"}},
	"cisco_cucm":        {{Vendor: "cisco", Product: "unified_communications_manager"}, {Vendor: "cisco", Product: "unified_cm"}},
	"yealink_phone":     {{Vendor: "yealink", Product: "sip-t46s_firmware"}, {Vendor: "yealink", Product: "sip-t48u_firmware"}, {Vendor: "yealink", Product: "phone_firmware"}},
	"polycom_phone":     {{Vendor: "polycom", Product: "vvx_firmware"}, {Vendor: "polycom", Product: "ucs"}, {Vendor: "poly", Product: "ucs"}},
	"grandstream_phone": {{Vendor: "grandstream", Product: "gxp_firmware"}, {Vendor: "grandstream", Product: "ht_firmware"}, {Vendor: "grandstream", Product: "ucm_firmware"}},
	"avaya_aura":        {{Vendor: "avaya", Product: "aura_communication_manager"}, {Vendor: "avaya", Product: "aura_session_manager"}, {Vendor: "avaya", Product: "session_border_controller_for_enterprise"}},
	"sangoma_pbx":       {{Vendor: "sangoma", Product: "pbxact"}, {Vendor: "sangoma", Product: "freepbx"}},

	// Healthcare — DICOM / HL7 / EMR stacks.
	"dicom":             {{Vendor: "dicom", Product: "dicom"}, {Vendor: "nema", Product: "dicom"}},
	"hl7_mllp":          {{Vendor: "hl7", Product: "mllp"}, {Vendor: "hl7", Product: "hl7"}},
	"orthanc_dicom":     {{Vendor: "orthanc-server", Product: "orthanc"}, {Vendor: "osimis", Product: "orthanc"}},
	"dcm4chee":          {{Vendor: "dcm4che", Product: "dcm4chee"}, {Vendor: "dcm4che", Product: "dcm4che"}},
	"openmrs":           {{Vendor: "openmrs", Product: "openmrs"}},
	"openemr":           {{Vendor: "open-emr", Product: "openemr"}, {Vendor: "openemr", Product: "openemr"}},
	"dcmtk":             {{Vendor: "offis", Product: "dcmtk"}, {Vendor: "dcmtk", Product: "dcmtk"}},
	"pacscube":          {{Vendor: "pacscube", Product: "pacscube"}},
	"osirix":            {{Vendor: "pixmeo", Product: "osirix"}, {Vendor: "pixmeo", Product: "osirix_md"}},
	"mirth_connect":     {{Vendor: "nextgen", Product: "mirth_connect"}, {Vendor: "mirth", Product: "mirth_connect"}, {Vendor: "nextgen", Product: "connect"}},
	"epic_chronicles":   {{Vendor: "epic_systems", Product: "chronicles"}, {Vendor: "epic", Product: "chronicles"}},
	"cerner_millennium": {{Vendor: "cerner", Product: "millennium"}, {Vendor: "oracle", Product: "cerner_millennium"}},

	// Hypervisor management / cloud-control plane.
	"proxmox_ve":         {{Vendor: "proxmox", Product: "virtual_environment"}, {Vendor: "proxmox", Product: "ve"}, {Vendor: "proxmox-server-solutions", Product: "proxmox_ve"}},
	"ovirt_engine":       {{Vendor: "redhat", Product: "virtualization"}, {Vendor: "ovirt", Product: "ovirt-engine"}, {Vendor: "ovirt", Product: "engine"}},
	"xenserver_xapi":     {{Vendor: "citrix", Product: "xenserver"}, {Vendor: "citrix", Product: "hypervisor"}},
	"xcp_ng":             {{Vendor: "vates", Product: "xcp-ng"}, {Vendor: "xcp-ng", Product: "xcp-ng"}},
	"openstack_keystone": {{Vendor: "openstack", Product: "keystone"}, {Vendor: "redhat", Product: "openstack_platform_director"}},
	"openstack_nova":     {{Vendor: "openstack", Product: "nova"}, {Vendor: "redhat", Product: "openstack_platform"}},
	"openstack_neutron":  {{Vendor: "openstack", Product: "neutron"}, {Vendor: "redhat", Product: "openstack_platform"}},

	// Backup software.
	"veeam_backup":          {{Vendor: "veeam", Product: "backup_\u0026_replication"}, {Vendor: "veeam", Product: "veeam_backup_\u0026_replication"}, {Vendor: "veeam", Product: "backup_for_microsoft_365"}},
	"commvault_backup":      {{Vendor: "commvault", Product: "commvault"}, {Vendor: "commvault", Product: "backup_\u0026_recovery"}, {Vendor: "commvault", Product: "commcell"}},
	"rubrik_cdm":            {{Vendor: "rubrik", Product: "cdm"}, {Vendor: "rubrik", Product: "cloud_data_management"}},
	"netbackup":             {{Vendor: "veritas", Product: "netbackup"}, {Vendor: "veritas", Product: "appliance"}},
	"cohesity_dataplatform": {{Vendor: "cohesity", Product: "dataplatform"}, {Vendor: "cohesity", Product: "data_cloud"}},
	"bareos":                {{Vendor: "bareos", Product: "bareos"}, {Vendor: "bareos-gmbh", Product: "bareos"}},
	"bacula":                {{Vendor: "bacula", Product: "bacula"}, {Vendor: "kern_sibbald", Product: "bacula"}},
	"arcserve_udp":          {{Vendor: "arcserve", Product: "udp"}, {Vendor: "arcserve", Product: "unified_data_protection"}},

	// APM / observability stacks.
	"splunk":                  {{Vendor: "splunk", Product: "splunk"}, {Vendor: "splunk", Product: "splunk_enterprise"}, {Vendor: "splunk", Product: "splunk_cloud"}},
	"datadog_agent":           {{Vendor: "datadoghq", Product: "agent"}, {Vendor: "datadog", Product: "agent"}, {Vendor: "datadog", Product: "datadog_agent"}},
	"grafana_loki":            {{Vendor: "grafana", Product: "loki"}, {Vendor: "grafanalabs", Product: "loki"}},
	"grafana_tempo":           {{Vendor: "grafana", Product: "tempo"}, {Vendor: "grafanalabs", Product: "tempo"}},
	"victoria_metrics":        {{Vendor: "victoriametrics", Product: "victoriametrics"}},
	"prometheus_alertmanager": {{Vendor: "prometheus", Product: "alertmanager"}},
	"prometheus_pushgateway":  {{Vendor: "prometheus", Product: "pushgateway"}},

	// Service mesh / cloud-native proxies.
	"istio_pilot":   {{Vendor: "istio", Product: "istio"}, {Vendor: "google", Product: "istio"}},
	"linkerd_proxy": {{Vendor: "linkerd", Product: "linkerd2"}, {Vendor: "linkerd", Product: "linkerd"}, {Vendor: "buoyant", Product: "linkerd"}},
	"cilium_agent":  {{Vendor: "cilium", Product: "cilium"}, {Vendor: "isovalent", Product: "cilium"}},
	"kuma_cp":       {{Vendor: "kuma", Product: "kuma"}, {Vendor: "konghq", Product: "kuma"}},

	// Cyber-energy SCADA / metering.
	"dlms_cosem":        {{Vendor: "dlms", Product: "cosem"}, {Vendor: "iec", Product: "62056"}},
	"synchrophasor_pmu": {{Vendor: "ieee", Product: "c37.118"}},
	"sel_3373":          {{Vendor: "schweitzer", Product: "sel-3373"}, {Vendor: "selinc", Product: "sel-3373"}},
	"siemens_sicam_pas": {{Vendor: "siemens", Product: "sicam_pas"}, {Vendor: "siemens", Product: "sicam"}},

	// Secure DNS.
	"dns_over_tls":   {{Vendor: "ietf", Product: "rfc7858"}, {Vendor: "isc", Product: "bind"}},
	"dns_over_https": {{Vendor: "ietf", Product: "rfc8484"}, {Vendor: "cloudflare", Product: "cloudflare_dns"}},
	"unbound":        {{Vendor: "nlnetlabs", Product: "unbound"}, {Vendor: "nlnet_labs", Product: "unbound"}},
	"knot_resolver":  {{Vendor: "cz.nic", Product: "knot_resolver"}, {Vendor: "cz_nic", Product: "knot-resolver"}},
	"cloudflared":    {{Vendor: "cloudflare", Product: "cloudflared"}, {Vendor: "cloudflare", Product: "cloudflare_tunnel"}},
	"adguard_home":   {{Vendor: "adguard", Product: "adguard_home"}, {Vendor: "adguardteam", Product: "adguardhome"}},

	// CI/CD platforms.
	"jetbrains_teamcity": {{Vendor: "jetbrains", Product: "teamcity"}},
	"gocd":               {{Vendor: "thoughtworks", Product: "gocd"}, {Vendor: "gocd", Product: "gocd"}},
	"drone_ci":           {{Vendor: "drone", Product: "drone"}, {Vendor: "harness", Product: "drone"}},
	"concourse_ci":       {{Vendor: "concourse-ci", Product: "concourse"}, {Vendor: "pivotal_software", Product: "concourse"}},
	"github_enterprise":  {{Vendor: "github", Product: "enterprise_server"}, {Vendor: "github", Product: "enterprise"}},
	"woodpecker_ci":      {{Vendor: "woodpecker-ci", Product: "woodpecker"}, {Vendor: "woodpecker", Product: "woodpecker"}},
	"argo_workflows":     {{Vendor: "argoproj", Product: "argo_workflows"}, {Vendor: "linuxfoundation", Product: "argo"}},

	// Storage stacks.
	"iscsi_target":          {{Vendor: "linux-iscsi", Product: "lio"}, {Vendor: "open-iscsi", Product: "open-iscsi"}, {Vendor: "openatom", Product: "tgt"}},
	"nfs_server":            {{Vendor: "linux", Product: "linux_kernel"}, {Vendor: "freebsd", Product: "freebsd"}, {Vendor: "openbsd", Product: "openbsd"}},
	"apple_filing_protocol": {{Vendor: "apple", Product: "macos"}, {Vendor: "netatalk", Product: "netatalk"}},
	"lustre":                {{Vendor: "lustre", Product: "lustre"}, {Vendor: "ddn", Product: "lustre"}},
	"gluster_fs":            {{Vendor: "redhat", Product: "gluster_storage"}, {Vendor: "gluster", Product: "glusterfs"}},
	"ceph_mon":              {{Vendor: "redhat", Product: "ceph_storage"}, {Vendor: "ceph", Product: "ceph"}},
	"minio_server":          {{Vendor: "minio", Product: "minio"}},
	"netapp_ontap":          {{Vendor: "netapp", Product: "data_ontap"}, {Vendor: "netapp", Product: "ontap"}},
	"emc_isilon":            {{Vendor: "dell", Product: "isilon_onefs"}, {Vendor: "emc", Product: "isilon_onefs"}},
	"pure_storage":          {{Vendor: "purestorage", Product: "purity"}, {Vendor: "pure_storage", Product: "purity_oe"}},

	// Robotics platforms.
	"ros_master":           {{Vendor: "ros", Product: "ros"}, {Vendor: "openrobotics", Product: "ros"}},
	"ros2_dds":             {{Vendor: "ros", Product: "ros2"}, {Vendor: "openrobotics", Product: "ros2"}},
	"kuka_krc":             {{Vendor: "kuka", Product: "krc4"}, {Vendor: "kuka", Product: "system_software"}},
	"abb_robotware":        {{Vendor: "abb", Product: "robotware"}, {Vendor: "abb", Product: "irc5"}},
	"rockwell_factorytalk": {{Vendor: "rockwellautomation", Product: "factorytalk_linx"}, {Vendor: "rockwell_automation", Product: "factorytalk_linx_gateway"}},
	"fanuc_focas":          {{Vendor: "fanuc", Product: "focas"}, {Vendor: "fanuc", Product: "cnc"}},
	"universal_robots":     {{Vendor: "universal-robots", Product: "polyscope"}, {Vendor: "universal_robots", Product: "urcontrol"}, {Vendor: "universal-robots", Product: "ursoftware"}},
	"yaskawa_motoman":      {{Vendor: "yaskawa", Product: "motoman"}, {Vendor: "yaskawa", Product: "yrc1000"}},
	"staubli_cs9":          {{Vendor: "staubli", Product: "cs9"}, {Vendor: "staeubli", Product: "cs9"}},
	"denso_robotics":       {{Vendor: "denso", Product: "rc8"}, {Vendor: "denso", Product: "robotics"}},

	// Marine / aviation receivers.
	"nmea0183":     {{Vendor: "nmea", Product: "nmea_0183"}, {Vendor: "iec", Product: "61162"}},
	"ais_receiver": {{Vendor: "itu", Product: "ais"}, {Vendor: "aishub", Product: "ais"}},
	"dump1090":     {{Vendor: "antirez", Product: "dump1090"}, {Vendor: "flightaware", Product: "dump1090-fa"}, {Vendor: "wiedehopf", Product: "readsb"}},
	"gnu_radio":    {{Vendor: "gnuradio", Product: "gnu_radio"}, {Vendor: "gnu", Product: "gnuradio"}},
	"acarsdec":     {{Vendor: "tlevecque", Product: "acarsdec"}, {Vendor: "thierry_leconte", Product: "acarsdec"}},

	// Crypto / game.
	"bitcoin_core":             {{Vendor: "bitcoin", Product: "bitcoin_core"}, {Vendor: "bitcoincore", Product: "bitcoin_core"}, {Vendor: "bitcoin", Product: "bitcoin"}},
	"ethereum_geth":            {{Vendor: "ethereum", Product: "go-ethereum"}, {Vendor: "go-ethereum", Product: "go-ethereum"}, {Vendor: "ethereum", Product: "geth"}},
	"ethereum_erigon":          {{Vendor: "ledgerwatch", Product: "erigon"}, {Vendor: "erigon", Product: "erigon"}},
	"ethereum_openethereum":    {{Vendor: "parity_technologies", Product: "parity-ethereum"}, {Vendor: "openethereum", Product: "openethereum"}},
	"hyperledger_besu":         {{Vendor: "hyperledger", Product: "besu"}, {Vendor: "consensys", Product: "besu"}},
	"ethereum_nethermind":      {{Vendor: "nethermindeth", Product: "nethermind"}, {Vendor: "nethermind", Product: "nethermind"}},
	"ethereum_lighthouse":      {{Vendor: "sigp", Product: "lighthouse"}, {Vendor: "lighthouse", Product: "lighthouse"}},
	"ethereum_prysm":           {{Vendor: "prysmaticlabs", Product: "prysm"}, {Vendor: "prysm", Product: "prysm"}},
	"bcoin_node":               {{Vendor: "bcoin", Product: "bcoin"}, {Vendor: "bcoin-org", Product: "bcoin"}},
	"btcd_node":                {{Vendor: "btcsuite", Product: "btcd"}},
	"bitcoin_knots":            {{Vendor: "bitcoinknots", Product: "bitcoin_knots"}, {Vendor: "luke-jr", Product: "bitcoin_knots"}},
	"litecoin_core":            {{Vendor: "litecoin", Product: "litecoin"}, {Vendor: "litecoin-project", Product: "litecoin"}},
	"monero_node":              {{Vendor: "monero", Product: "monero"}, {Vendor: "monero-project", Product: "monero"}},
	"lightning_network_daemon": {{Vendor: "lightningnetwork", Product: "lnd"}, {Vendor: "lightning", Product: "lnd"}},
	"minecraft_server":         {{Vendor: "mojang", Product: "minecraft"}, {Vendor: "microsoft", Product: "minecraft"}},
	"steam_dedicated_server":   {{Vendor: "valvesoftware", Product: "steam"}, {Vendor: "valve", Product: "steam"}},

	// Rsync / X11 / IRC — dominated `uv_service` rows where protocol fell
	// back to `tcp` (banner probe) on ports 873 / 6000+ / 6667+.
	"rsync": {{Vendor: "samba", Product: "rsync"}, {Vendor: "rsync", Product: "rsync"}, {Vendor: "openbsd", Product: "rsync"}},
	"x11":   {{Vendor: "x.org", Product: "x_server"}, {Vendor: "xfree86", Product: "xfree86"}, {Vendor: "xorg", Product: "x_server"}},
	"irc":   {{Vendor: "unrealircd", Product: "unrealircd"}, {Vendor: "inspircd", Product: "inspircd"}, {Vendor: "ircd-hybrid", Product: "ircd-hybrid"}},
}

// productAliases collapses common wire-form product names (the strings that
// land in FingerprintResult.Product directly from Server / X-Powered-By /
// X-Generator headers and from TLS subject markers) onto the canonical
// productMap key.
//
// The list is deliberately conservative: only aliases that resolve to an
// unambiguous CPE coordinate set are added — if two products share a wire
// name, the parser leaves it alone and we accept a miss over a misfire.
var productAliases = map[string]string{
	"httpd":              "apache",
	"apache_http_server": "apache",
	"apache-coyote":      "tomcat",
	"microsoft-iis":      "iis",
	"microsoft-httpapi":  "iis",
	"asp.net":            "asp_net",
	"asp-net":            "asp_net",
	"jboss-eap":          "jboss",
	"jboss-as":           "jboss",
	"squid-cache":        "squid",
	"caddyserver":        "caddy",
	"node":               "nodejs",
	"node.js":            "nodejs",
	"k8s":                "kubernetes",
	"joomla!":            "joomla",
	"nats-server":        "nats",
	"natsd":              "nats",
}

// CanonicalProductKey returns the cpemap productMap lookup key for a
// fingerprint product string (aliases applied, lower-cased).
func CanonicalProductKey(product string) string {
	key := strings.TrimSpace(strings.ToLower(product))
	if key == "" {
		return ""
	}

	if alias, ok := productAliases[key]; ok {
		return alias
	}

	return key
}

// Lookup returns the CPE coordinates registered for the given fingerprint
// product. The product string is matched case-insensitively. If the input
// is one of the well-known wire-form aliases (e.g. "httpd"), it is rewritten
// to the canonical productMap key ("apache") before lookup. The second
// return value reports whether the product is mapped at all; an unmapped
// product yields nil so callers can short-circuit.
func Lookup(product string) ([]Coord, bool) {
	key := CanonicalProductKey(product)
	if key == "" {
		return nil, false
	}

	cacheMu.RLock()
	defer cacheMu.RUnlock()

	m := cachedMap
	if m == nil {
		m = productMap
	}

	coords, ok := m[key]

	return coords, ok
}

// Range carries the bounds of one NVD applicability statement.
//
// Each bound is the raw string from the catalog ("" means the bound is
// open). ExactVersion is set when the CPE 2.3 URI itself pinned a single
// version with no surrounding range.
type Range struct {
	ExactVersion          string
	VersionStartIncluding string
	VersionStartExcluding string
	VersionEndIncluding   string
	VersionEndExcluding   string
}

// VersionMatches reports whether the captured version is covered by r.
//
// Strict semantics: when version is empty the result is always false, so an
// unknown service version never produces a CVE match. Both the captured
// version and the bounds are passed through NormalizeVersion before
// comparison so distro packaging metadata ("5.7.44-log", "1.18.0+dfsg,
// "2.4.41-2ubuntu2.5") doesn't artificially shift ordering.
func VersionMatches(version string, r Range) bool {
	v, _ := NormalizeVersion(version)
	if v == "" {
		return false
	}

	if r.ExactVersion != "" {
		exact, _ := NormalizeVersion(r.ExactVersion)

		return equalVersion(v, exact)
	}

	if r.VersionStartIncluding != "" {
		lo, _ := NormalizeVersion(r.VersionStartIncluding)
		if compareVersion(v, lo) < 0 {
			return false
		}
	}

	if r.VersionStartExcluding != "" {
		lo, _ := NormalizeVersion(r.VersionStartExcluding)
		if compareVersion(v, lo) <= 0 {
			return false
		}
	}

	if r.VersionEndIncluding != "" {
		hi, _ := NormalizeVersion(r.VersionEndIncluding)
		if compareVersion(v, hi) > 0 {
			return false
		}
	}

	if r.VersionEndExcluding != "" {
		hi, _ := NormalizeVersion(r.VersionEndExcluding)
		if compareVersion(v, hi) >= 0 {
			return false
		}
	}

	if r.VersionStartIncluding == "" && r.VersionStartExcluding == "" &&
		r.VersionEndIncluding == "" && r.VersionEndExcluding == "" {
		// No bounds and no exact version → not a valid applicability claim.
		return false
	}

	return true
}

func equalVersion(a, b string) bool {
	return compareVersion(a, b) == 0
}

// IsCatchAll reports whether r expresses "any version is affected": no
// exact pin and no upper or lower bound. NVD entries with this shape are
// the only ones the CVE matcher can use against fingerprints that lack a
// captured version, so version-less matching keys off it.
func IsCatchAll(r Range) bool {
	return r.ExactVersion == "" &&
		r.VersionStartIncluding == "" &&
		r.VersionStartExcluding == "" &&
		r.VersionEndIncluding == "" &&
		r.VersionEndExcluding == ""
}

// compareVersion returns -1, 0 or 1 ordering two dotted version strings.
// Both inputs are sliced into numeric and alphabetic runs which are compared
// component-by-component. Numeric components compare as integers; alphabetic
// components compare lexicographically. Shorter version strings pad with 0.
//
// Examples (truthy): 5.0.1 < 5.0.2 < 5.1 < 5.1.0.1 < 5.10.
func compareVersion(a, b string) int {
	pa := tokenize(a)
	pb := tokenize(b)

	maxLen := len(pa)
	if len(pb) > maxLen {
		maxLen = len(pb)
	}

	for i := range maxLen {
		var (
			tokA token
			tokB token
		)

		if i < len(pa) {
			tokA = pa[i]
		} else {
			tokA = token{kind: tokenNumeric, num: 0}
		}

		if i < len(pb) {
			tokB = pb[i]
		} else {
			tokB = token{kind: tokenNumeric, num: 0}
		}

		if c := compareTokens(tokA, tokB); c != 0 {
			return c
		}
	}

	return 0
}

func compareTokens(a, b token) int {
	if a.kind == tokenNumeric && b.kind == tokenNumeric {
		switch {
		case a.num < b.num:
			return -1
		case a.num > b.num:
			return 1
		default:
			return 0
		}
	}

	// Pre-release marker is strictly below anything else at the same
	// position. This makes "1.0.0-rc1 < 1.0.0" and "1.0.0-rc1 < 1.0.0-1".
	if a.kind == tokenPreRelease && b.kind != tokenPreRelease {
		return -1
	}

	if b.kind == tokenPreRelease && a.kind != tokenPreRelease {
		return 1
	}

	// Numeric beats alphabetic when both occupy the same position: 1.0 > 1.0a.
	if a.kind == tokenNumeric && b.kind == tokenAlpha {
		return 1
	}

	if a.kind == tokenAlpha && b.kind == tokenNumeric {
		return -1
	}

	switch {
	case a.text < b.text:
		return -1
	case a.text > b.text:
		return 1
	default:
		return 0
	}
}

type tokenKind int

const (
	tokenNumeric tokenKind = iota
	tokenAlpha
	tokenPreRelease
)

type token struct {
	kind tokenKind
	num  uint64
	text string
}

// preReleaseTokens are alpha runs that semver/PEP 440 treat as pre-release,
// i.e. anything tagged with them sorts strictly below the equivalent release.
//
// "snapshot", "dev", and "m" (Maven milestone) are common in Java land.
var preReleaseTokens = map[string]struct{}{
	"alpha":    {},
	"a":        {},
	"beta":     {},
	"b":        {},
	"rc":       {},
	"cr":       {},
	"pre":      {},
	"preview":  {},
	"dev":      {},
	"snapshot": {},
	"m":        {},
}

// distroSuffixRE matches trailing Debian/RPM/Alpine packaging metadata glued
// onto upstream versions, e.g. "5.7.44-log", "2.4.41-2ubuntu2.5",
// "8.0.33-1.el8", "1.18.0-1+deb11u1", "1.6.1-r0" (Alpine), "20210408-mariadb".
// These suffixes have no upstream versioning meaning, and breaking on the
// leading "-" leaves stray tokens that flip the comparator. The regex is
// intentionally permissive so the rare new distro doesn't slip past.
var distroSuffixRE = regexp.MustCompile(
	`(?i)-[\w.+]*` +
		`(?:ubuntu|deb|el\d|rh\d|fc\d|alpine|amzn|bpo|sles|rocky|ol\d|mariadb|log|fips|wheezy|jessie|stretch|buster|bullseye|bookworm|trusty|xenial|bionic|focal|jammy|noble)` +
		`[\w.+~-]*$`,
)

// distroRevisionRE matches a trailing Debian-style package revision such as
// "-1", "-3", "-12". It's applied only after distroSuffixRE so we don't fold
// "-rc1"/"-beta2" into the same trap.
var distroRevisionRE = regexp.MustCompile(`-\d+$`)

// NormalizeVersion strips packaging noise and reports whether distro-specific
// suffixes were removed. Exported for CVE matcher confidence heuristics.
func NormalizeVersion(s string) (version string, hadDistroSuffix bool) {
	v := strings.TrimSpace(s)
	if v == "" {
		return "", false
	}

	if v[0] == 'v' || v[0] == 'V' {
		v = v[1:]
	}

	if idx := strings.IndexAny(v, "~+"); idx >= 0 {
		v = v[:idx]
	}

	before := v
	v = distroSuffixRE.ReplaceAllString(v, "")
	hadDistroSuffix = v != before

	before = v
	v = distroRevisionRE.ReplaceAllString(v, "")
	hadDistroSuffix = hadDistroSuffix || v != before

	return strings.TrimSpace(v), hadDistroSuffix
}

// tokenize splits a version string into ordered numeric/alpha/pre-release
// runs, dropping separators (".", "-", "_", "+").
func tokenize(s string) []token {
	out := make([]token, 0, 8)
	buf := make([]byte, 0, len(s))
	kind := tokenNumeric

	flush := func() {
		if len(buf) == 0 {
			return
		}

		if kind == tokenNumeric {
			n := uint64(0)

			for _, c := range buf {
				n = n*10 + uint64(c-'0')
			}

			out = append(out, token{kind: tokenNumeric, num: n})
		} else {
			text := strings.ToLower(string(buf))
			tk := tokenAlpha

			if _, ok := preReleaseTokens[text]; ok {
				tk = tokenPreRelease
			}

			out = append(out, token{kind: tk, text: text})
		}

		buf = buf[:0]
	}

	for i := range len(s) {
		ch := s[i]

		switch {
		case ch == '.' || ch == '-' || ch == '_' || ch == '+':
			flush()
		case unicode.IsDigit(rune(ch)):
			if len(buf) > 0 && kind != tokenNumeric {
				flush()
			}

			buf = append(buf, ch)
			kind = tokenNumeric
		default:
			if len(buf) > 0 && kind != tokenAlpha {
				flush()
			}

			buf = append(buf, ch)
			kind = tokenAlpha
		}
	}

	flush()

	return out
}
