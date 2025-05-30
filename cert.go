package snap

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
)

type (
	Cert interface {
		GenerateKey(req GeneratePrivateKey) (res CertResponse)
		PrivateKeyRawToKey(req PrivateKeyRawToKey) (res CertResponse)
		PublicKeyRawToKey(req PublicKeyRawToKey) (res CertResponse)
		PrivateKeyToRaw(req PrivateKeyToRaw) (res CertResponse)
		PublicKeyToRaw(req PublicKeyToRaw) (res CertResponse)
		PrivateKeyBase64ToRaw(req PrivateKeyBase64ToRaw) (res CertResponse)
		PublicKeyBase64ToRaw(req PublicKeyBase64ToRaw) (res CertResponse)
	}

	cert struct{}
)

func NewCert() Cert {
	return cert{}
}

func (p cert) GenerateKey(req GeneratePrivateKey) (res CertResponse) {
	privateKey, err := rsa.GenerateKey(rand.Reader, int(req.KeySize))
	if err != nil {
		res.Error = err
		return
	}

	privateKeyRaw := p.PrivateKeyToRaw(PrivateKeyToRaw{KeyType: req.PrivateKeyType, KeyPrivate: privateKey})
	if privateKeyRaw.Error != nil {
		res.Error = err
		return
	}

	if req.Password != "" {
		encryptPemBlock, err := x509.EncryptPEMBlock(rand.Reader, req.PrivateKeyType, []byte(privateKeyRaw.KeyRawPrivate), []byte(req.Password), x509.PEMCipherAES256)
		if err != nil {
			res.Error = err
			return
		}

		res.KeyRawPrivate = pem.EncodeToMemory(encryptPemBlock)

	} else {
		decodePemBlock, _ := pem.Decode([]byte(privateKeyRaw.KeyRawPrivate))
		if decodePemBlock == nil {
			res.Error = errors.New("Invalid GeneratePrivateKey PEM PrivateKey certificate")
			return
		}

		res.KeyRawPrivate = pem.EncodeToMemory(decodePemBlock)

	}

	publicKeyRaw := p.PublicKeyToRaw(PublicKeyToRaw{KeyType: req.PublicKeyType, KeyPublic: &privateKey.PublicKey})
	if publicKeyRaw.Error != nil {
		res.Error = err
		return
	}

	res.KeyRawPublic = publicKeyRaw.KeyRawPublic

	if res.KeyRawPrivate == nil || res.KeyRawPublic == nil {
		res.Error = errors.New("Invalid GeneratePrivateKey PEM PrivateKey certificate | PEM PublicKey certificate")
		return
	}

	return
}

func (p cert) PrivateKeyRawToKey(req PrivateKeyRawToKey) (res CertResponse) {
	decodePemBlock, _ := pem.Decode(req.KeyRawPrivate)
	if decodePemBlock == nil {
		res.Error = errors.New("Invalid PrivateKeyRawToKey PEM PrivateKey certificate")
		return
	}

	if x509.IsEncryptedPEMBlock(decodePemBlock) && req.Password != "" {
		decryptPrivateKey, err := x509.DecryptPEMBlock(decodePemBlock, []byte(req.Password))
		if err != nil {
			res.Error = err
			return
		}

		decodePemBlock, _ = pem.Decode(decryptPrivateKey)
		if decodePemBlock == nil {
			res.Error = errors.New("Invalid PrivateKeyRawToKey PEM PrivateKey certificate")
			return
		}
	}

	if req.KeyType == PRIVPKCS1 {
		privateKey, err := x509.ParsePKCS1PrivateKey(decodePemBlock.Bytes)
		if err != nil {
			res.Error = err
			return
		}

		res.KeyType = req.KeyType
		res.KeyPrivate = privateKey
		return
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(decodePemBlock.Bytes)
	if err != nil {
		res.Error = err
		return
	}

	res.KeyType = req.KeyType
	res.KeyPrivate = privateKey.(*rsa.PrivateKey)
	return
}

func (p cert) PublicKeyRawToKey(req PublicKeyRawToKey) (res CertResponse) {
	decodePemBlock, _ := pem.Decode(req.KeyRawPublic)
	if decodePemBlock == nil {
		res.Error = errors.New("Invalid PublicKeyRawToKey PEM PrivateKey certificate")
		return
	}

	if req.KeyType == PRIVPKCS1 {
		publicKey, err := x509.ParsePKCS1PublicKey(decodePemBlock.Bytes)
		if err != nil {
			res.Error = err
			return
		}

		res.KeyType = req.KeyType
		res.KeyPublic = publicKey
		return
	}

	publicKey, err := x509.ParsePKIXPublicKey(decodePemBlock.Bytes)
	if err != nil {
		res.Error = err
		return
	}

	res.KeyType = req.KeyType
	res.KeyPublic = publicKey.(*rsa.PublicKey)
	return
}

func (p cert) PrivateKeyToRaw(req PrivateKeyToRaw) (res CertResponse) {
	if req.KeyType == PRIVPKCS1 {
		res.KeyRawPrivate = pem.EncodeToMemory(&pem.Block{
			Type:  req.KeyType,
			Bytes: x509.MarshalPKCS1PrivateKey(req.KeyPrivate),
		})

	} else if req.KeyType == PRIVPKCS8 {
		privateKey, err := x509.MarshalPKCS8PrivateKey(req.KeyPrivate)
		if err != nil {
			return
		}

		res.KeyRawPrivate = pem.EncodeToMemory(&pem.Block{
			Type:  req.KeyType,
			Bytes: privateKey,
		})

	} else {
		res.Error = errors.New("Invalid PrivateKeyToRaw PEM PrivateKey certificate")
		return
	}

	if res.KeyRawPrivate == nil {
		res.Error = errors.New("Invalid PrivateKeyToRaw PEM PrivateKey certificate")
		return
	}

	res.KeyType = req.KeyType
	return
}

func (p cert) PublicKeyToRaw(req PublicKeyToRaw) (res CertResponse) {
	if req.KeyType == PUBPKCS1 {
		res.KeyRawPublic = pem.EncodeToMemory(&pem.Block{
			Type:  req.KeyType,
			Bytes: x509.MarshalPKCS1PublicKey(req.KeyPublic),
		})

	} else if req.KeyType == PUBPKCS8 {
		publicKey, err := x509.MarshalPKIXPublicKey(req.KeyPublic)
		if err != nil {
			return
		}

		res.KeyRawPublic = pem.EncodeToMemory(&pem.Block{
			Type:  req.KeyType,
			Bytes: publicKey,
		})

	} else {
		res.Error = errors.New("Invalid PublicKeyToRaw PEM PublicKey certificate")
		return
	}

	if res.KeyRawPublic == nil {
		res.Error = errors.New("Invalid PublicKeyToRaw PEM PublicKey certificate")
		return
	}

	res.KeyType = req.KeyType
	return
}

func (p cert) PrivateKeyBase64ToRaw(req PrivateKeyBase64ToRaw) (res CertResponse) {
	decodeToStr, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.KeyRawPrivate))
	if err != nil {
		res.Error = err
		return
	}

	decodePemBlock, _ := pem.Decode([]byte(decodeToStr))
	if decodePemBlock == nil {
		res.Error = errors.New("Invalid PrivateKeyBase64ToRaw PEM PrivateKey certificate")
		return
	}

	if decodePemBlock.Type == PRIVPKCS1 {
		res.KeyRawPrivate = pem.EncodeToMemory(decodePemBlock)

	} else if decodePemBlock.Type == PRIVPKCS8 {
		res.KeyRawPrivate = pem.EncodeToMemory(decodePemBlock)

	} else if decodePemBlock.Type == CERTIFICATE {
		res.KeyRawPrivate = pem.EncodeToMemory(decodePemBlock)

	} else {
		res.Error = errors.New("Invalid PrivateKeyBase64ToRaw PEM PrivateKey certificate")
		return
	}

	if res.KeyRawPrivate == nil {
		res.Error = errors.New("Invalid PrivateKeyBase64ToRaw PEM PrivateKey certificate")
		return
	}

	res.KeyType = decodePemBlock.Type
	return
}

func (p cert) PublicKeyBase64ToRaw(req PublicKeyBase64ToRaw) (res CertResponse) {
	decodeToStr, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.KeyRawPublic))
	if err != nil {
		res.Error = err
		return
	}

	decodePemBlock, _ := pem.Decode([]byte(decodeToStr))
	if decodePemBlock == nil {
		res.Error = errors.New("Invalid PublicKeyBase64ToRaw  PublicKey certificate")
		return
	}

	if decodePemBlock.Type == PUBPKCS1 {
		res.KeyRawPublic = pem.EncodeToMemory(decodePemBlock)

	} else if decodePemBlock.Type == PUBPKCS8 {
		res.KeyRawPublic = pem.EncodeToMemory(decodePemBlock)

	} else if decodePemBlock.Type == CERTIFICATE {
		res.KeyRawPublic = pem.EncodeToMemory(decodePemBlock)

	} else {
		res.Error = errors.New("Invalid PublicKeyBase64ToRaw PEM PublicKey certificate")
		return
	}

	if res.KeyRawPublic == nil {
		res.Error = errors.New("Invalid PublicKeyBase64ToRaw PEM PublicKey certificate")
		return
	}

	res.KeyType = decodePemBlock.Type
	return
}
