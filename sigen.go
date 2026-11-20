/*
Package sigen provides a client library for interacting with the reverse-engineered Cloud API for Sigenergy.

Based on the work in https://github.com/solidfox/sigenergy-cloud.
*/
package sigen

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	AustraliaAPI = "https://api-aus.sigencloud.com"
	// TODO: others, like EU, China, APAC, US
)

type Client struct {
	apiBase     string
	username    string
	encPassword string

	authData *authData
}

// NewClient creates a new authenticated client.
// The context is used only for the authentication step.
func NewClient(ctx context.Context, apiBase, username, password string) (*Client, error) {
	c := &Client{
		apiBase:     apiBase,
		username:    username,
		encPassword: encryptPassword(password),
	}

	// Turn username/password into an access token.
	ad, err := c.auth(ctx, url.Values{
		"username":   []string{c.username},
		"password":   []string{c.encPassword},
		"grant_type": []string{"password"},
	})
	if err != nil {
		return nil, fmt.Errorf("authenticating: %w", err)
	}
	c.authData = ad

	return c, nil
}

type Station struct {
	ID int `json:"stationId"`

	Name     string `json:"stationName"`     // often the name of the owner
	ShowName string `json:"stationShowName"` // e.g. "My Home"
	Address  string `json:"addr"`            // postal address

	TimeZone string `json:"timeZoneName"` // e.g. "Australia/Sydney"

	// Lots more other data if we're so inclined.
}

func (c *Client) Station(ctx context.Context) (*Station, error) {
	req, err := c.authedRequest(ctx, "GET", "/device/owner/station/home", nil)
	if err != nil {
		return nil, err
	}
	var payload struct {
		// TODO: check .code == 0, and report .message if not?
		Data Station `json:"data"`
	}
	if err := doJSONRequest(req, &payload); err != nil {
		return nil, err
	}
	return &payload.Data, nil
}

type InstantManualMode int

const (
	ChargingMode        = 0
	DischargingMode     = 1
	HoldBatteryMode     = 2
	SelfConsumptionMode = 3
)

func (c *Client) InstantManualControl(ctx context.Context, stationID int, mode InstantManualMode, dur time.Duration) error {
	var reqb = struct {
		Enable    bool   `json:"enable"`
		StationID int    `json:"stationId"`
		Mode      string `json:"mode"`
		Duration  string `json:"duration"` // in minutes (but why as a string?)

		PowerLim string `json:"powerLimitation"` // kW, %.3f
	}{
		Enable:    true,
		StationID: stationID,
		Mode:      strconv.Itoa(int(mode)),
		Duration:  strconv.Itoa(int(dur.Minutes())),
	}

	// TODO: support power limitation
	if mode == ChargingMode || mode == DischargingMode {
		// Still need to provide a limitation.
		reqb.PowerLim = fmt.Sprintf("%.3f", float64(math.MaxUint32)/1000)
	}

	body, err := json.Marshal(reqb)
	if err != nil {
		return fmt.Errorf("encoding request body: %w", err)
	}
	req, err := c.authedRequest(ctx, "PUT", "/device/energy-profile/instant/manunal", bytes.NewReader(body)) // yes, typo in path!
	if err != nil {
		return err
	}
	var payload struct {
		// TODO: check .code == 0, and report .message if not?
		// Data bool `json:"data"`
	}
	return doJSONRequest(req, &payload)
}

func (c *Client) authedRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	// TODO: auto-refresh tokens?

	req, err := http.NewRequestWithContext(ctx, method, c.apiBase+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.authData.AccessToken)

	return req, nil
}

type authData struct {
	AccessToken  string
	RefreshToken string
	Expires      time.Time
}

func (c *Client) auth(ctx context.Context, data url.Values) (*authData, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", c.apiBase+"/auth/oauth/token", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("sigen", "sigen") // OAuth client ID/secret

	var payload struct {
		// TODO: check .code == 0, and report .message if not?
		Data struct {
			AT string `json:"access_token"`
			RT string `json:"refresh_token"`
			EI int    `json:"expires_in"`
		} `json:"data"`
	}
	if err := doJSONRequest(req, &payload); err != nil {
		return nil, err
	}

	return &authData{
		AccessToken:  payload.Data.AT,
		RefreshToken: payload.Data.RT,
		Expires:      time.Now().Add(time.Duration(payload.Data.EI)),
	}, nil
}

func doJSONRequest(req *http.Request, dst any) error {
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending HTTP request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("received HTTP %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading HTTP response: %w", err)
	}
	//log.Printf("XXX: to %s, raw JSON response:\n%s", req.URL.Path, body)
	if err := json.Unmarshal(body, &dst); err != nil {
		return fmt.Errorf("decoding response body: %w", err)
	}
	return nil
}

func encryptPassword(plain string) string {
	const (
		iv  = "sigensigensigenp"
		key = "sigensigensigenp"
	)
	bc, err := aes.NewCipher([]byte(key))
	if err != nil {
		panic("aes.NewCipher: " + err.Error())
	}

	bm := cipher.NewCBCEncrypter(bc, []byte(iv))
	padded := pkcs7Pad(plain)
	ct := make([]byte, len(padded))
	bm.CryptBlocks(ct, padded)

	return base64.StdEncoding.EncodeToString(ct)
}

// pkcs7Pad constructs a padded version of some plaintext, per PKCS#7 (RFC 5652, section 6.3).
func pkcs7Pad(plain string) []byte {
	j := aes.BlockSize - (len(plain) % aes.BlockSize)
	out := make([]byte, len(plain)+j)
	copy(out, plain)
	for i := 0; i < j; i++ {
		out[len(plain)+i] = byte(j)
	}
	return out
}
