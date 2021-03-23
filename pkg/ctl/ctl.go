/*
Copyright © 2021 Luke Hinds <lhinds@redhat.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package ctl

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	ct "github.com/google/certificate-transparency-go"
	logclient "github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/ctutil"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/x509"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/pkg/errors"
)

type Client struct {
	c   *http.Client
	url string
}

func New(url string) *Client {
	c := &http.Client{Timeout: 30 * time.Second}
	return &Client{
		c:   c,
		url: url,
	}
}

type certChain struct {
	Chain []string `json:"chain"`
}

type ErrorResponse struct {
	StatusCode int    `json:"statusCode"`
	ErrorCode  string `json:"errorCode"`
	Message    string `json:"message"`
}

func (err *ErrorResponse) Error() string {
	if err.ErrorCode == "" {
		return fmt.Sprintf("%d CT API error: %s", err.StatusCode, err.Message)
	}
	return fmt.Sprintf("%d (%s) CT API error: %s", err.StatusCode, err.ErrorCode, err.Message)
}

func (c *Client) TryPre(ctx context.Context, leaf string, chain []string) (*ct.SignedCertificateTimestamp, error) {
	// Build the PEM Chain {root, client}
	tclient, err := logclient.New(c.url, c.c, jsonclient.Options{})
	if err != nil {
		return nil, errors.Wrap(err, "getting client")
	}
	codeChain := buildCodeChain(leaf, chain)

	sct, err := tclient.AddPreChain(ctx, codeChain)
	if err != nil {
		return nil, errors.Wrap(err, "adding pre chain")
	}

	// now verify the sct
	pk, err := CTLogPublicKey()
	if err != nil {
		return nil, errors.Wrap(err, "new public key")
	}
	parsedChain, err := certsFromCodeChain(codeChain)
	if err != nil {
		return nil, errors.Wrap(err, "certs from code chain")
	}
	if err := ctutil.VerifySCT(pk, parsedChain, sct, false); err != nil {
		return nil, errors.Wrap(err, "Verifying SCT")
	}
	return sct, nil
}

func (c *Client) TryAdd(ctx context.Context, leaf string, chain []string, wantSCT *ct.SignedCertificateTimestamp) (*ct.SignedCertificateTimestamp, error) {
	// Build the PEM Chain {root, client}
	tclient, err := logclient.New(c.url, c.c, jsonclient.Options{})
	if err != nil {
		return nil, errors.Wrap(err, "getting client")
	}

	codeChain := buildCodeChain(leaf, chain)

	sct, err := tclient.AddChain(ctx, codeChain)
	if err != nil {
		return nil, errors.Wrap(err, "adding chain")
	}

	// now verify the sct
	pk, err := CTLogPublicKey()
	if err != nil {
		return nil, errors.Wrap(err, "new public key")
	}
	parsedChain, err := certsFromCodeChain(codeChain)
	if err != nil {
		return nil, errors.Wrap(err, "certs from code chain")
	}
	if err := ctutil.VerifySCT(pk, parsedChain, wantSCT, true); err != nil {
		return nil, errors.Wrap(err, "Verifying SCT")
	}
	return sct, nil
}

func buildCodeChain(leaf string, chain []string) []ct.ASN1Cert {
	// Build the PEM Chain {root, client}
	leafblock, _ := pem.Decode([]byte(leaf))
	var codeChain []ct.ASN1Cert
	codeChain = append(codeChain, ct.ASN1Cert{
		Data: leafblock.Bytes,
	})

	for _, c := range chain {
		decoded, _ := pem.Decode([]byte(c))
		codeChain = append(codeChain, ct.ASN1Cert{
			Data: []byte(decoded.Bytes),
		})
	}
	return codeChain
}

func certsFromCodeChain(rawChain []ct.ASN1Cert) ([]*ctx509.Certificate, error) {
	chain := make([]*ctx509.Certificate, len(rawChain))
	for i := range chain {
		cert, err := ctx509.ParseCertificate(rawChain[i].Data)
		if ctx509.IsFatal(err) {
			return nil, fmt.Errorf("failed to parse chain[%d] cert: %v", i, err)
		}

		chain[i] = cert
	}
	return chain, nil
}

func CTLogPublicKey() (*ecdsa.PublicKey, error) {
	pubKeyPEM := `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbbQiLx6GKy6ivhc11wJGbQjc2VX/
mnuk5d670MTXR3p+LIAcxd5MhqIHpLmyYJ5mDKLEoZ/pC0nPuje3JueBcA==
-----END PUBLIC KEY-----`

	block, _ := pem.Decode([]byte(pubKeyPEM))
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pk, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("public key")
	}
	return pk, nil
}

func (c *Client) Add(leaf string, chain []string, apiEndpoint string) (*ct.SignedCertificateTimestamp, error) {
	// Build the PEM Chain {root, client}
	leafblock, _ := pem.Decode([]byte(leaf))

	chainjson := &certChain{Chain: []string{
		base64.StdEncoding.EncodeToString(leafblock.Bytes),
	}}

	for _, c := range chain {
		pb, _ := pem.Decode([]byte(c))
		chainjson.Chain = append(chainjson.Chain, base64.StdEncoding.EncodeToString(pb.Bytes))
	}
	jsonStr, err := json.Marshal(chainjson)
	if err != nil {
		return nil, err
	}

	// Send to correct endpoint on CT log (could be add-chain or add-prechain)
	url := fmt.Sprintf("%s%s", c.url, apiEndpoint)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.c.Do(req)
	if err != nil {
		return nil, err
	}

	switch resp.StatusCode {
	case 200:
		var ctlResp ct.SignedCertificateTimestamp
		if err := json.NewDecoder(resp.Body).Decode(&ctlResp); err != nil {
			return nil, err
		}
		return &ctlResp, nil
	case 400, 401, 403, 500:
		var errRes ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errRes); err != nil {
			return nil, err
		}

		if errRes.StatusCode == 0 {
			errRes.StatusCode = resp.StatusCode
		}
		return nil, &errRes
	default:
		return nil, fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}
}
