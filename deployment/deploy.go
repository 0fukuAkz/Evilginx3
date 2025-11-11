package deployment

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/kgretzky/evilginx2/log"
	"golang.org/x/crypto/ssh"
)

// DeploymentConfig contains deployment configuration
type DeploymentConfig struct {
	ServerIP        string
	ServerPort      int
	SSHUser         string
	SSHKeyPath      string
	SSHPassword     string
	Domain          string
	HTTPSPort       int
	DNSPort         int
	InstallPath     string
	ServiceName     string
	EnableFirewall  bool
	EnableAutoStart bool
}

// Deployment handles server deployment operations
type Deployment struct {
	config     *DeploymentConfig
	sshClient  *ssh.Client
	sftpClient interface{} // Will be SFTP client when implemented
}

// NewDeployment creates a new deployment instance
func NewDeployment(config *DeploymentConfig) *Deployment {
	// Set defaults
	if config.ServerPort == 0 {
		config.ServerPort = 22
	}
	if config.HTTPSPort == 0 {
		config.HTTPSPort = 443
	}
	if config.DNSPort == 0 {
		config.DNSPort = 53
	}
	if config.InstallPath == "" {
		config.InstallPath = "/opt/evilginx"
	}
	if config.ServiceName == "" {
		config.ServiceName = "evilginx2"
	}

	return &Deployment{
		config: config,
	}
}

// Connect establishes SSH connection to the server
func (d *Deployment) Connect() error {
	var auth []ssh.AuthMethod

	// Use SSH key if provided
	if d.config.SSHKeyPath != "" {
		key, err := ioutil.ReadFile(d.config.SSHKeyPath)
		if err != nil {
			return fmt.Errorf("failed to read SSH key: %v", err)
		}

		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return fmt.Errorf("failed to parse SSH key: %v", err)
		}

		auth = append(auth, ssh.PublicKeys(signer))
	} else if d.config.SSHPassword != "" {
		// Use password authentication
		auth = append(auth, ssh.Password(d.config.SSHPassword))
	} else {
		return fmt.Errorf("no SSH authentication method provided")
	}

	sshConfig := &ssh.ClientConfig{
		User:            d.config.SSHUser,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: Implement proper host key verification
		Timeout:         30 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", d.config.ServerIP, d.config.ServerPort)
	client, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %v", addr, err)
	}

	d.sshClient = client
	log.Info("Connected to server: %s", d.config.ServerIP)
	return nil
}

// Disconnect closes the SSH connection
func (d *Deployment) Disconnect() {
	if d.sshClient != nil {
		d.sshClient.Close()
		log.Info("Disconnected from server")
	}
}

// Deploy performs the full deployment
func (d *Deployment) Deploy() error {
	log.Info("Starting deployment to %s", d.config.ServerIP)

	// Connect to server
	if err := d.Connect(); err != nil {
		return err
	}
	defer d.Disconnect()

	// Check OS and prerequisites
	osInfo, err := d.detectOS()
	if err != nil {
		return fmt.Errorf("failed to detect OS: %v", err)
	}
	log.Info("Detected OS: %s", osInfo)

	// Install dependencies
	if err := d.installDependencies(osInfo); err != nil {
		return fmt.Errorf("failed to install dependencies: %v", err)
	}

	// Create directories
	if err := d.createDirectories(); err != nil {
		return fmt.Errorf("failed to create directories: %v", err)
	}

	// Upload Evilginx binary
	if err := d.uploadBinary(); err != nil {
		return fmt.Errorf("failed to upload binary: %v", err)
	}

	// Configure system
	if err := d.configureSystem(osInfo); err != nil {
		return fmt.Errorf("failed to configure system: %v", err)
	}

	// Setup service
	if err := d.setupService(osInfo); err != nil {
		return fmt.Errorf("failed to setup service: %v", err)
	}

	// Configure firewall
	if d.config.EnableFirewall {
		if err := d.configureFirewall(osInfo); err != nil {
			log.Warning("Failed to configure firewall: %v", err)
		}
	}

	// Start service
	if d.config.EnableAutoStart {
		if err := d.startService(); err != nil {
			return fmt.Errorf("failed to start service: %v", err)
		}
	}

	// Verify deployment
	if err := d.verifyDeployment(); err != nil {
		return fmt.Errorf("deployment verification failed: %v", err)
	}

	log.Info("Deployment completed successfully!")
	return nil
}

// runCommand executes a command on the remote server
func (d *Deployment) runCommand(cmd string) (string, error) {
	session, err := d.sshClient.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	log.Debug("Running command: %s", cmd)
	err = session.Run(cmd)
	
	output := stdout.String()
	errOutput := stderr.String()

	if err != nil {
		return output, fmt.Errorf("command failed: %v\nstderr: %s", err, errOutput)
	}

	return output, nil
}

// detectOS detects the operating system
func (d *Deployment) detectOS() (string, error) {
	output, err := d.runCommand("cat /etc/os-release")
	if err != nil {
		return "", err
	}

	if strings.Contains(output, "Ubuntu") {
		return "ubuntu", nil
	} else if strings.Contains(output, "Debian") {
		return "debian", nil
	} else if strings.Contains(output, "CentOS") {
		return "centos", nil
	} else if strings.Contains(output, "Red Hat") {
		return "redhat", nil
	}

	return "unknown", nil
}

// installDependencies installs required packages
func (d *Deployment) installDependencies(osType string) error {
	log.Info("Installing dependencies...")

	var cmds []string

	switch osType {
	case "ubuntu", "debian":
		cmds = []string{
			"apt-get update",
			"apt-get install -y wget curl git build-essential",
		}
	case "centos", "redhat":
		cmds = []string{
			"yum update -y",
			"yum install -y wget curl git gcc make",
		}
	default:
		return fmt.Errorf("unsupported OS type: %s", osType)
	}

	for _, cmd := range cmds {
		if _, err := d.runCommand(cmd); err != nil {
			return fmt.Errorf("failed to run '%s': %v", cmd, err)
		}
	}

	return nil
}

// createDirectories creates necessary directories
func (d *Deployment) createDirectories() error {
	log.Info("Creating directories...")

	dirs := []string{
		d.config.InstallPath,
		filepath.Join(d.config.InstallPath, "phishlets"),
		filepath.Join(d.config.InstallPath, "redirectors"),
		filepath.Join(d.config.InstallPath, "data"),
		"/etc/evilginx",
	}

	for _, dir := range dirs {
		cmd := fmt.Sprintf("mkdir -p %s", dir)
		if _, err := d.runCommand(cmd); err != nil {
			return fmt.Errorf("failed to create directory %s: %v", dir, err)
		}
	}

	// Set permissions
	cmd := fmt.Sprintf("chown -R %s:%s %s", d.config.SSHUser, d.config.SSHUser, d.config.InstallPath)
	if _, err := d.runCommand(cmd); err != nil {
		log.Warning("Failed to set permissions: %v", err)
	}

	return nil
}

// uploadBinary uploads the Evilginx binary
func (d *Deployment) uploadBinary() error {
	log.Info("Uploading Evilginx binary...")

	// For now, we'll download from GitHub releases
	// In production, this should upload the actual binary
	
	cmd := fmt.Sprintf(`
		cd %s && \
		wget -O evilginx https://github.com/kgretzky/evilginx2/releases/latest/download/evilginx-linux-amd64 && \
		chmod +x evilginx
	`, d.config.InstallPath)

	if _, err := d.runCommand(cmd); err != nil {
		// Try building from source as fallback
		log.Warning("Failed to download binary, trying to build from source...")
		return d.buildFromSource()
	}

	return nil
}

// buildFromSource builds Evilginx from source
func (d *Deployment) buildFromSource() error {
	log.Info("Building Evilginx from source...")

	// Install Go if not present
	goVersion := "1.21.5"
	checkGoCmd := "go version"
	if _, err := d.runCommand(checkGoCmd); err != nil {
		log.Info("Installing Go...")
		installGoCmd := fmt.Sprintf(`
			cd /tmp && \
			wget https://go.dev/dl/go%s.linux-amd64.tar.gz && \
			tar -C /usr/local -xzf go%s.linux-amd64.tar.gz && \
			echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
		`, goVersion, goVersion)
		
		if _, err := d.runCommand(installGoCmd); err != nil {
			return fmt.Errorf("failed to install Go: %v", err)
		}
	}

	// Clone and build
	buildCmd := fmt.Sprintf(`
		export PATH=$PATH:/usr/local/go/bin && \
		cd /tmp && \
		rm -rf evilginx2 && \
		git clone https://github.com/kgretzky/evilginx2 && \
		cd evilginx2 && \
		go build -o %s/evilginx . && \
		cp -r phishlets %s/ && \
		cp -r redirectors %s/
	`, d.config.InstallPath, d.config.InstallPath, d.config.InstallPath)

	if _, err := d.runCommand(buildCmd); err != nil {
		return fmt.Errorf("failed to build from source: %v", err)
	}

	return nil
}

// configureSystem configures system settings
func (d *Deployment) configureSystem(osType string) error {
	log.Info("Configuring system...")

	// Create configuration file
	configContent := fmt.Sprintf(`{
  "general": {
    "domain": "%s",
    "external_ipv4": "%s",
    "bind_ipv4": "0.0.0.0",
    "https_port": %d,
    "dns_port": %d,
    "autocert": true
  }
}`, d.config.Domain, d.config.ServerIP, d.config.HTTPSPort, d.config.DNSPort)

	// Write config file
	configPath := "/etc/evilginx/config.json"
	writeCmd := fmt.Sprintf("echo '%s' > %s", configContent, configPath)
	if _, err := d.runCommand(writeCmd); err != nil {
		return fmt.Errorf("failed to write config: %v", err)
	}

	// Set system limits
	limitsCmd := `
		echo "* soft nofile 65535" >> /etc/security/limits.conf
		echo "* hard nofile 65535" >> /etc/security/limits.conf
		sysctl -w net.ipv4.ip_forward=1
		echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
	`
	if _, err := d.runCommand(limitsCmd); err != nil {
		log.Warning("Failed to set system limits: %v", err)
	}

	return nil
}

// setupService creates and configures the systemd service
func (d *Deployment) setupService(osType string) error {
	log.Info("Setting up systemd service...")

	serviceContent := fmt.Sprintf(`[Unit]
Description=Evilginx2 Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=%s
ExecStart=%s/evilginx -p /etc/evilginx -developer
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`, d.config.InstallPath, d.config.InstallPath)

	// Write service file
	servicePath := fmt.Sprintf("/etc/systemd/system/%s.service", d.config.ServiceName)
	writeCmd := fmt.Sprintf("echo '%s' > %s", serviceContent, servicePath)
	if _, err := d.runCommand(writeCmd); err != nil {
		return fmt.Errorf("failed to write service file: %v", err)
	}

	// Reload systemd
	if _, err := d.runCommand("systemctl daemon-reload"); err != nil {
		return fmt.Errorf("failed to reload systemd: %v", err)
	}

	// Enable service
	if d.config.EnableAutoStart {
		enableCmd := fmt.Sprintf("systemctl enable %s", d.config.ServiceName)
		if _, err := d.runCommand(enableCmd); err != nil {
			return fmt.Errorf("failed to enable service: %v", err)
		}
	}

	return nil
}

// configureFirewall configures the firewall
func (d *Deployment) configureFirewall(osType string) error {
	log.Info("Configuring firewall...")

	switch osType {
	case "ubuntu", "debian":
		// Use ufw
		cmds := []string{
			"apt-get install -y ufw",
			"ufw --force enable",
			"ufw allow 22/tcp",
			fmt.Sprintf("ufw allow %d/tcp", d.config.HTTPSPort),
			fmt.Sprintf("ufw allow %d/udp", d.config.DNSPort),
			fmt.Sprintf("ufw allow %d/tcp", d.config.DNSPort),
			"ufw reload",
		}
		
		for _, cmd := range cmds {
			if _, err := d.runCommand(cmd); err != nil {
				log.Warning("Firewall command failed: %s - %v", cmd, err)
			}
		}

	case "centos", "redhat":
		// Use firewall-cmd
		cmds := []string{
			fmt.Sprintf("firewall-cmd --permanent --add-port=%d/tcp", d.config.HTTPSPort),
			fmt.Sprintf("firewall-cmd --permanent --add-port=%d/udp", d.config.DNSPort),
			fmt.Sprintf("firewall-cmd --permanent --add-port=%d/tcp", d.config.DNSPort),
			"firewall-cmd --reload",
		}
		
		for _, cmd := range cmds {
			if _, err := d.runCommand(cmd); err != nil {
				log.Warning("Firewall command failed: %s - %v", cmd, err)
			}
		}
	}

	return nil
}

// startService starts the Evilginx service
func (d *Deployment) startService() error {
	log.Info("Starting service...")

	startCmd := fmt.Sprintf("systemctl start %s", d.config.ServiceName)
	if _, err := d.runCommand(startCmd); err != nil {
		return fmt.Errorf("failed to start service: %v", err)
	}

	// Wait for service to start
	time.Sleep(5 * time.Second)

	// Check status
	statusCmd := fmt.Sprintf("systemctl is-active %s", d.config.ServiceName)
	status, err := d.runCommand(statusCmd)
	if err != nil || strings.TrimSpace(status) != "active" {
		return fmt.Errorf("service failed to start properly")
	}

	log.Info("Service started successfully")
	return nil
}

// verifyDeployment verifies that the deployment is working
func (d *Deployment) verifyDeployment() error {
	log.Info("Verifying deployment...")

	// Check if service is running
	statusCmd := fmt.Sprintf("systemctl is-active %s", d.config.ServiceName)
	if status, err := d.runCommand(statusCmd); err != nil || strings.TrimSpace(status) != "active" {
		return fmt.Errorf("service is not running")
	}

	// Check if ports are listening
	ports := []struct {
		port  int
		proto string
	}{
		{d.config.HTTPSPort, "tcp"},
		{d.config.DNSPort, "tcp"},
		{d.config.DNSPort, "udp"},
	}

	for _, p := range ports {
		checkCmd := fmt.Sprintf("ss -ln | grep ':%d '", p.port)
		if _, err := d.runCommand(checkCmd); err != nil {
			return fmt.Errorf("port %d/%s is not listening", p.port, p.proto)
		}
	}

	// Try to connect to HTTPS port
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", d.config.ServerIP, d.config.HTTPSPort), 10*time.Second)
	if err != nil {
		return fmt.Errorf("cannot connect to HTTPS port: %v", err)
	}
	conn.Close()

	log.Info("Deployment verification passed")
	return nil
}

// Rollback attempts to rollback a failed deployment
func (d *Deployment) Rollback() error {
	log.Info("Rolling back deployment...")

	if d.sshClient == nil {
		if err := d.Connect(); err != nil {
			return fmt.Errorf("failed to connect for rollback: %v", err)
		}
		defer d.Disconnect()
	}

	// Stop service
	stopCmd := fmt.Sprintf("systemctl stop %s 2>/dev/null || true", d.config.ServiceName)
	d.runCommand(stopCmd)

	// Disable service
	disableCmd := fmt.Sprintf("systemctl disable %s 2>/dev/null || true", d.config.ServiceName)
	d.runCommand(disableCmd)

	// Remove service file
	removeServiceCmd := fmt.Sprintf("rm -f /etc/systemd/system/%s.service", d.config.ServiceName)
	d.runCommand(removeServiceCmd)

	// Remove installation directory
	removeInstallCmd := fmt.Sprintf("rm -rf %s", d.config.InstallPath)
	d.runCommand(removeInstallCmd)

	// Reload systemd
	d.runCommand("systemctl daemon-reload")

	log.Info("Rollback completed")
	return nil
}

// GetLogs retrieves service logs
func (d *Deployment) GetLogs(lines int) (string, error) {
	if d.sshClient == nil {
		if err := d.Connect(); err != nil {
			return "", fmt.Errorf("failed to connect: %v", err)
		}
		defer d.Disconnect()
	}

	cmd := fmt.Sprintf("journalctl -u %s -n %d --no-pager", d.config.ServiceName, lines)
	output, err := d.runCommand(cmd)
	if err != nil {
		return "", fmt.Errorf("failed to get logs: %v", err)
	}

	return output, nil
}

// GetStatus returns the service status
func (d *Deployment) GetStatus() (string, error) {
	if d.sshClient == nil {
		if err := d.Connect(); err != nil {
			return "", fmt.Errorf("failed to connect: %v", err)
		}
		defer d.Disconnect()
	}

	cmd := fmt.Sprintf("systemctl status %s --no-pager", d.config.ServiceName)
	output, err := d.runCommand(cmd)
	if err != nil {
		// Service might not exist
		return "Service not found", nil
	}

	return output, nil
}
