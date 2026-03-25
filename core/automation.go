package core

import (
	"strings"
	"github.com/kgretzky/evilginx2/log"
	gp_models "github.com/kgretzky/evilginx2/gophish/models"
)

// AutomateCampaignFromLure automatically updates a Gophish campaign's base URL
// when a lure is generated in Evilginx.
func AutomateCampaignFromLure(baseUrl string, phishletName string) {
	// Identify campaigns that might be related to this phishlet.
	// We check for campaigns whose name contains the phishlet name (case-insensitive).
	
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
		log.Debug("automation: no matching gophish campaign found for phishlet '%s' - creating scaffolding...", phishletName)
		CreateScaffoldingFromLure(baseUrl, phishletName)
	}
}
