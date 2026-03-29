package core

import (
	"fmt"
	"strings"

	"github.com/kgretzky/evilginx2/log"
	gp_models "github.com/kgretzky/evilginx2/gophish/models"
)

// AutomateCampaignFromLure automatically updates or creates a Gophish campaign
// when a lure URL is generated in Evilginx.
func AutomateCampaignFromLure(baseUrl string, phishletName string, cfg *Config) {
	// Default to admin user (ID 1)
	summary, err := gp_models.GetCampaignSummaries(1)
	if err != nil {
		log.Error("automation: failed to get gophish campaigns: %v", err)
		return
	}

	found := false
	for _, c_sum := range summary.Campaigns {
		if strings.Contains(strings.ToLower(c_sum.Name), strings.ToLower(phishletName)) {
			// Found a potential match, fetch the full campaign to update it
			c, err := gp_models.GetCampaign(c_sum.Id, 1)
			if err != nil {
				log.Error("automation: failed to get campaign %d: %v", c_sum.Id, err)
				continue
			}

			// Update the URL if it's different
			if c.URL != baseUrl {
				log.Info("automation: updating gophish campaign '%s' with new base URL: %s", c.Name, baseUrl)
				c.URL = baseUrl
				err = gp_models.UpdateCampaign(&c)
				if err != nil {
					log.Error("automation: failed to update campaign %d: %v", c_sum.Id, err)
				}
			}
			found = true
		}
	}

	if !found {
		// No existing campaign — try to auto-create one
		if err := autoCreateCampaign(baseUrl, phishletName, cfg); err != nil {
			log.Warning("automation: could not auto-create campaign: %v", err)
		}
	}
}

// autoCreateCampaign creates a GoPhish campaign using configured defaults or
// the first available group/template/SMTP from the database.
func autoCreateCampaign(baseUrl string, phishletName string, cfg *Config) error {
	// Resolve group name
	groupName := ""
	if cfg != nil {
		groupName = cfg.GetGoPhishAutoCampaignGroup()
	}
	if groupName == "" {
		groups, err := gp_models.GetGroups(1)
		if err != nil || len(groups) == 0 {
			return fmt.Errorf("no groups configured in gophish — create one first")
		}
		groupName = groups[0].Name
	}

	// Resolve template name
	templName := ""
	if cfg != nil {
		templName = cfg.GetGoPhishAutoCampaignTemplate()
	}
	if templName == "" {
		templates, err := gp_models.GetTemplates(1)
		if err != nil || len(templates) == 0 {
			return fmt.Errorf("no templates configured in gophish — create one first")
		}
		templName = templates[0].Name
	}

	// Resolve SMTP name
	smtpName := ""
	if cfg != nil {
		smtpName = cfg.GetGoPhishAutoCampaignSMTP()
	}
	if smtpName == "" {
		smtps, err := gp_models.GetSMTPs(1)
		if err != nil || len(smtps) == 0 {
			return fmt.Errorf("no SMTP profiles configured in gophish — create one first")
		}
		smtpName = smtps[0].Name
	}

	// Resolve page name (optional)
	pageName := ""
	if cfg != nil {
		pageName = cfg.GetGoPhishAutoCampaignPage()
	}
	if pageName == "" {
		pages, err := gp_models.GetPages(1)
		if err == nil && len(pages) > 0 {
			pageName = pages[0].Name
		}
	}

	campaignName := fmt.Sprintf("%s-auto", phishletName)

	c := gp_models.Campaign{
		Name:     campaignName,
		Template: gp_models.Template{Name: templName},
		SMTP:     gp_models.SMTP{Name: smtpName},
		Groups:   []gp_models.Group{{Name: groupName}},
		URL:      baseUrl,
	}
	if pageName != "" {
		c.Page = gp_models.Page{Name: pageName}
	}

	if err := gp_models.PostCampaign(&c, 1); err != nil {
		return fmt.Errorf("PostCampaign: %v", err)
	}

	log.Success("auto-created gophish campaign '%s' (id: %d) with URL: %s", campaignName, c.Id, baseUrl)
	return nil
}
