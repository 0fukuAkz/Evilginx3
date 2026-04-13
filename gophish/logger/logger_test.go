package logger

import "testing"

func TestSetup(t *testing.T) {
	configs := []*Config{
		{Level: ""},
		{Level: "debug"},
		{Level: "info"},
		{Level: "error"},
	}
	for _, config := range configs {
		err := Setup(config)
		if err != nil {
			t.Fatalf("error calling Setup with level %q: %v", config.Level, err)
		}
	}
}
