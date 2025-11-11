package core

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"
)

func GenRandomToken() string {
	rdata := make([]byte, 64)
	rand.Read(rdata)
	hash := sha256.Sum256(rdata)
	token := fmt.Sprintf("%x", hash)
	return token
}

func GenRandomString(n int) string {
	const lb = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, n)
	for i := range b {
		t := make([]byte, 1)
		rand.Read(t)
		b[i] = lb[int(t[0])%len(lb)]
	}
	return string(b)
}

func GenRandomAlphanumString(n int) string {
	const lb = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		t := make([]byte, 1)
		rand.Read(t)
		b[i] = lb[int(t[0])%len(lb)]
	}
	return string(b)
}

// GenRandomLureString generates a random string optimized for lure URLs
// with configurable strategy for different levels of randomization
func GenRandomLureString(strategy string) string {
	switch strategy {
	case "short":
		// 12-16 characters, alphanumeric only
		return GenRandomAlphanumString(12 + getRandomInt(5))
	
	case "medium":
		// 16-24 characters with dashes for realism
		return genRealisticPath(16 + getRandomInt(9))
	
	case "long":
		// 24-32 characters with multiple segments
		return genMultiSegmentPath(24 + getRandomInt(9))
	
	case "realistic":
		// Mimics real URL patterns (default)
		return genRealisticUrlPattern()
	
	case "hex":
		// Hexadecimal string (32-40 chars) - looks like session IDs
		return genHexString(32 + getRandomInt(9))
	
	case "base64":
		// Base64-like string (20-28 chars)
		return genBase64LikeString(20 + getRandomInt(9))
	
	case "mixed":
		// Random combination of strategies
		strategies := []string{"short", "medium", "long", "realistic", "hex", "base64"}
		t := make([]byte, 1)
		rand.Read(t)
		return GenRandomLureString(strategies[int(t[0])%len(strategies)])
	
	default:
		// Default: medium strategy
		return genRealisticPath(18 + getRandomInt(8))
	}
}

// getRandomInt returns a random integer between 0 and max-1
func getRandomInt(max int) int {
	t := make([]byte, 1)
	rand.Read(t)
	return int(t[0]) % max
}

// genRealisticPath generates a path that looks like real web URLs
func genRealisticPath(length int) string {
	const alphaLower = "abcdefghijklmnopqrstuvwxyz"
	const alphaNum = "abcdefghijklmnopqrstuvwxyz0123456789"
	const separators = "-_"
	
	b := make([]byte, length)
	lastSeparator := false
	
	for i := range b {
		t := make([]byte, 1)
		rand.Read(t)
		
		// First character must be a letter
		if i == 0 {
			b[i] = alphaLower[int(t[0])%len(alphaLower)]
		} else if i == len(b)-1 {
			// Last character should be alphanumeric, not separator
			b[i] = alphaNum[int(t[0])%len(alphaNum)]
		} else {
			// 15% chance of separator, but not consecutive
			if int(t[0])%100 < 15 && !lastSeparator && i > 2 {
				b[i] = separators[int(t[0])%len(separators)]
				lastSeparator = true
			} else {
				b[i] = alphaNum[int(t[0])%len(alphaNum)]
				lastSeparator = false
			}
		}
	}
	
	return string(b)
}

// genMultiSegmentPath generates a multi-segment path like /path/to/resource
func genMultiSegmentPath(totalLength int) string {
	// Create 2-4 segments
	t := make([]byte, 1)
	rand.Read(t)
	numSegments := 2 + (int(t[0]) % 3)
	
	segmentLength := totalLength / numSegments
	segments := make([]string, numSegments)
	
	for i := 0; i < numSegments; i++ {
		// Vary segment lengths slightly
		t := make([]byte, 1)
		rand.Read(t)
		variation := int(t[0])%5 - 2 // -2 to +2
		length := segmentLength + variation
		if length < 3 {
			length = 3
		}
		segments[i] = GenRandomAlphanumString(length)
	}
	
	return strings.Join(segments, "/")
}

// genRealisticUrlPattern generates patterns that mimic common URL structures
func genRealisticUrlPattern() string {
	patterns := []func() string{
		// Pattern 1: /auth/session-xxxxx (OAuth-like)
		func() string {
			prefixes := []string{"auth", "session", "login", "verify", "confirm", "secure", "access"}
			t := make([]byte, 1)
			rand.Read(t)
			prefix := prefixes[int(t[0])%len(prefixes)]
			return prefix + "/" + genHexString(16+getRandomInt(16))
		},
		// Pattern 2: /s/xxxxxxxxxxxx (Short link style)
		func() string {
			return "s/" + GenRandomAlphanumString(12+getRandomInt(8))
		},
		// Pattern 3: /redirect?code=xxxxx (Redirect with parameter look)
		func() string {
			return "r/" + genBase64LikeString(20+getRandomInt(12))
		},
		// Pattern 4: /api/v1/xxxxxxxx (API endpoint style)
		func() string {
			t := make([]byte, 1)
			rand.Read(t)
			version := 1 + (int(t[0]) % 3) // v1, v2, or v3
			return fmt.Sprintf("api/v%d/%s", version, GenRandomAlphanumString(16+getRandomInt(8)))
		},
		// Pattern 5: UUID-like format
		func() string {
			return genUuidLikeString()
		},
		// Pattern 6: /p/resource-name-xxx (Resource style)
		func() string {
			resources := []string{"doc", "file", "share", "view", "link", "page", "item"}
			t := make([]byte, 1)
			rand.Read(t)
			resource := resources[int(t[0])%len(resources)]
			return "p/" + resource + "-" + GenRandomAlphanumString(8+getRandomInt(6))
		},
	}
	
	t := make([]byte, 1)
	rand.Read(t)
	pattern := patterns[int(t[0])%len(patterns)]
	return pattern()
}

// genHexString generates a hex string (0-9, a-f)
func genHexString(length int) string {
	const hexChars = "0123456789abcdef"
	b := make([]byte, length)
	for i := range b {
		t := make([]byte, 1)
		rand.Read(t)
		b[i] = hexChars[int(t[0])%len(hexChars)]
	}
	return string(b)
}

// genBase64LikeString generates a base64-style string
func genBase64LikeString(length int) string {
	const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	b := make([]byte, length)
	for i := range b {
		t := make([]byte, 1)
		rand.Read(t)
		b[i] = base64Chars[int(t[0])%len(base64Chars)]
	}
	return string(b)
}

// genUuidLikeString generates a UUID-like string (8-4-4-4-12 format)
func genUuidLikeString() string {
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		genHexString(8),
		genHexString(4),
		genHexString(4),
		genHexString(4),
		genHexString(12),
	)
}

func CreateDir(path string, perm os.FileMode) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err = os.Mkdir(path, perm)
		if err != nil {
			return err
		}
	}
	return nil
}

func ReadFromFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0644)
	defer f.Close()
	if err != nil {
		return nil, err
	}
	b, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func SaveToFile(b []byte, fpath string, perm fs.FileMode) error {
	file, err := os.OpenFile(fpath, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, perm)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(b)
	if err != nil {
		return err
	}
	return nil
}

func ParseDurationString(s string) (t_dur time.Duration, err error) {
	const DURATION_TYPES = "dhms"

	t_dur = 0
	err = nil

	var days, hours, minutes, seconds int64
	var last_type_index int = -1
	var s_num string
	for _, c := range s {
		if c >= '0' && c <= '9' {
			s_num += string(c)
		} else {
			if len(s_num) > 0 {
				m_index := strings.Index(DURATION_TYPES, string(c))
				if m_index >= 0 {
					if m_index > last_type_index {
						last_type_index = m_index
						var val int64
						val, err = strconv.ParseInt(s_num, 10, 0)
						if err != nil {
							return
						}
						switch c {
						case 'd':
							days = val
						case 'h':
							hours = val
						case 'm':
							minutes = val
						case 's':
							seconds = val
						}
					} else {
						err = fmt.Errorf("you can only use time duration types in following order: 'd' > 'h' > 'm' > 's'")
						return
					}
				} else {
					err = fmt.Errorf("unknown time duration type: '%s', you can use only 'd', 'h', 'm' or 's'", string(c))
					return
				}
			} else {
				err = fmt.Errorf("time duration value needs to start with a number")
				return
			}
			s_num = ""
		}
	}
	t_dur = time.Duration(days)*24*time.Hour + time.Duration(hours)*time.Hour + time.Duration(minutes)*time.Minute + time.Duration(seconds)*time.Second
	return
}

func GetDurationString(t_now time.Time, t_expire time.Time) (ret string) {
	var days, hours, minutes, seconds int64
	ret = ""

	if t_expire.After(t_now) {
		t_dur := t_expire.Sub(t_now)
		if t_dur > 0 {
			days = int64(t_dur / (24 * time.Hour))
			t_dur -= time.Duration(days) * (24 * time.Hour)

			hours = int64(t_dur / time.Hour)
			t_dur -= time.Duration(hours) * time.Hour

			minutes = int64(t_dur / time.Minute)
			t_dur -= time.Duration(minutes) * time.Minute

			seconds = int64(t_dur / time.Second)

			var forcePrint bool = false
			if days > 0 {
				forcePrint = true
				ret += fmt.Sprintf("%dd", days)
			}
			if hours > 0 || forcePrint {
				forcePrint = true
				ret += fmt.Sprintf("%dh", hours)
			}
			if minutes > 0 || forcePrint {
				forcePrint = true
				ret += fmt.Sprintf("%dm", minutes)
			}
			if seconds > 0 || forcePrint {
				forcePrint = true
				ret += fmt.Sprintf("%ds", seconds)
			}
		}
	}
	return
}
