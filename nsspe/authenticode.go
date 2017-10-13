package nsspe

import (
	"bytes"
	"encoding/binary"

	"./crypto"
)

type AuthentInfo struct {
	AnomaliesDetected Anomalies
	Path              string
	Certificate       winCertFormat
	DeptInfo          SignerInfo
}

func (ad *Anomalies) HasExtraPayload() bool {
	return ad.PayloadAfterSignature
}

func (ad *Anomalies) ExtraPayloadSize() int {
	return ad.PayloadAfterSize
}

func (a *AuthentInfo) isSafeToRead(size int, start int, reqSize int) bool {
	if size-start >= reqSize && reqSize >= 0 {
		return true
	}

	return false
}

func (a *AuthentInfo) GetInDeptInfo() *SignerInfo {
	info := crypto.GetInfo(a.Path)
	a.DeptInfo.ProgramName = *info.ProgramName
	a.DeptInfo.Author = *info.MoreInfo
	a.DeptInfo.Subject = *info.Subject
	return &a.DeptInfo
}

func (a *AuthentInfo) performCryptoValidation() bool {
	return crypto.Validate(a.Path)
}

func (a *AuthentInfo) Validate() bool {
	if a.Certificate.Certificate[0] != 0x30 {
		a.AnomaliesDetected.InvalidSignature = true
		return false
	}
	if a.Certificate.Certificate[1] > 0x80 && !a.isSafeToRead(int(a.Certificate.Length), 2, int(a.Certificate.Certificate[1]-0x80)) {
		a.AnomaliesDetected.InvalidSignature = true
		return false
	}
	reader := bytes.NewReader(a.Certificate.Certificate[2:4])
	binary.Read(reader, binary.BigEndian, &a.Certificate.RealLength)
	pkcs7Size := a.Certificate.RealLength
	parsed := 0
	if a.Certificate.Certificate[1] <= 0x80 {
		pkcs7Size = uint16(a.Certificate.Certificate[1])
		parsed = 2
	} else {
		pkcs7Size = a.Certificate.RealLength
		parsed = 2 + int(a.Certificate.Certificate[1]-0x80)
	}
	if !a.isSafeToRead(int(a.Certificate.Length), parsed, int(pkcs7Size)) {
		a.AnomaliesDetected.InvalidSignature = true
		return false
	}

	extraBytes := int(a.Certificate.Length) - (int(a.Certificate.RealLength) + parsed + SIZE_WIN_CERTIFICATE_HDR)
	if extraBytes > 0 {
		a.AnomaliesDetected.PayloadAfterSize = extraBytes * 4
		// If these are 00s then it's just the padding.
		for index := 0; index < extraBytes; index++ {
			fn := int(a.Certificate.RealLength) + index
			if a.Certificate.Certificate[fn] != 0x00 {
				a.AnomaliesDetected.PayloadAfterSignature = true
				break
			}
		}
	}

	return true && a.performCryptoValidation()
}
