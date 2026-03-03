package signals

// TLSVerdict defines the result of TLS/JA3 evaluation
type TLSVerdict struct {
	Score  float64
	Action string
	Reason string
}

// TLSSignal manages TLS fingerprinting and interception
type TLSSignal struct {
	Fingerprinter *JA3Fingerprinter
	Interceptor   *TLSInterceptor
}

// NewTLSSignal creates the TLS signal module
func NewTLSSignal() *TLSSignal {
	fp := NewJA3Fingerprinter()
	return &TLSSignal{
		Fingerprinter: fp,
		Interceptor:   NewTLSInterceptor(fp),
	}
}

// Evaluate determines the TLS verdict for a request
func (s *TLSSignal) Evaluate(remoteAddr string) TLSVerdict {
	verdict := TLSVerdict{Score: 0.0, Action: "allow", Reason: ""}

	res := s.Interceptor.GetConnectionJA3(remoteAddr)
	if res != nil {
		if res.IsBot {
			verdict.Score = 0.9
			verdict.Action = "block"
			verdict.Reason = "known_bot_ja3_" + res.BotName
		} else {
			// legitimate or unknown JA3
			verdict.Reason = "ja3_ok"
		}
	} else {
		verdict.Reason = "no_ja3_data"
	}

	return verdict
}
