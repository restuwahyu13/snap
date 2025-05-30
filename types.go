package snap

import "crypto/rsa"

type (
	CertRequest struct {
		KeyType       string          `json:"key_type,omitempty"`
		KeyRawPrivate []byte          `json:"key_raw_private,omitempty"`
		KeyPrivate    *rsa.PrivateKey `json:"key_private,omitempty"`
		KeyRawPublic  []byte          `json:"key_raw_public,omitempty"`
		KeyPublic     *rsa.PublicKey  `json:"key_public,omitempty"`
		Password      string          `json:"password,omitempty"`
	}

	GeneratePrivateKey struct {
		PrivateKeyType string `json:"private_key_type"`
		PublicKeyType  string `json:"public_key_type"`
		KeySize        uint   `json:"key_size"`
		Password       string `json:"password"`
	}

	PrivateKeyRawToKey struct {
		KeyType       string `json:"key_type,omitempty"`
		KeyRawPrivate []byte `json:"key_raw_private,omitempty"`
		Password      string `json:"password,omitempty"`
	}

	PublicKeyRawToKey struct {
		KeyType      string `json:"key_type,omitempty"`
		KeyRawPublic []byte `json:"key_raw_public,omitempty"`
	}

	PrivateKeyToRaw struct {
		KeyType    string          `json:"key_type,omitempty"`
		KeyPrivate *rsa.PrivateKey `json:"key_private,omitempty"`
	}

	PublicKeyToRaw struct {
		KeyType   string         `json:"key_type,omitempty"`
		KeyPublic *rsa.PublicKey `json:"key_public,omitempty"`
	}

	PrivateKeyBase64ToRaw struct {
		KeyRawPrivate string `json:"key_raw_private,omitempty"`
	}

	PublicKeyBase64ToRaw struct {
		KeyRawPublic string `json:"key_raw_public,omitempty"`
	}

	CertResponse struct {
		KeyType       string          `json:"key_type,omitempty"`
		KeyRawPrivate []byte          `json:"key_raw_private,omitempty"`
		KeyPrivate    *rsa.PrivateKey `json:"key_private,omitempty"`
		KeyRawPublic  []byte          `json:"key_raw_public,omitempty"`
		KeyPublic     *rsa.PublicKey  `json:"key_public,omitempty"`
		Error         error           `json:"error,omitempty"`
	}
)

type (
	Asymmetric struct {
		PrivateKeyType string `json:"private_key_type"`
		PrivateKey     []byte `json:"private_key"`
		PublicKey      string `json:"public_key"`
		TimeStamp      string `json:"time_stamp"`
		ClientKey      string `json:"client_key"`
		Password       string `json:"password,omitempty"`
	}

	Symetric struct {
		Url          string `json:"url"`
		Method       string `json:"method"`
		AccessToken  string `json:"access_token,omitempty"`
		TimeStamp    string `json:"time_stamp,omitempty"`
		ClientSecret string `json:"client_secret"`
		Body         []byte `json:"body"`
	}

	VerifyAsymmetric struct {
		PublicKeyType string `json:"public_key_type,omitempty"`
		PublicKey     []byte `json:"public_key,omitempty"`
		Signature     string `json:"signature,omitempty"`
		ClientId      string `json:"client_id,omitempty"`
		Timestamp     string `json:"timestamp,omitempty"`
	}

	VerifySymetric struct {
		PublicKeyType string `json:"public_key_type,omitempty"`
		PublicKey     []byte `json:"public_key,omitempty"`
		Signature     string `json:"signature"`
		Url           string `json:"url"`
		Method        string `json:"method"`
		AccessToken   string `json:"access_token,omitempty"`
		TimeStamp     string `json:"time_stamp,omitempty"`
		ClientSecret  string `json:"client_secret"`
		Body          []byte `json:"body"`
	}

	SignatureResponse struct {
		Signature string `json:"signature"`
		Error     error  `json:"error,omitempty"`
	}
)

type (
	Sign struct {
		Claim     []byte `json:"claim"`
		SecretKey string `json:"secret_key"`
		Expired   int    `json:"expired"`
		ClientID  string `json:"client_id"`
		Signature string `json:"signature"`
	}

	TokenResponse struct {
		Token   string `json:"token"`
		Expired int    `json:"expired"`
		Error   error  `json:"error,omitempty"`
	}
)
