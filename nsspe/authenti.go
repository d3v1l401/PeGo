package nsspe

import (
	"github.com/fullsailor/pkcs7"
)

type Authenticode struct {
	Revision int
	Type     int
	Size     int
	Buffer   []byte

	DeptInfo []string
}

func (a *Authenticode) Initialize(revision, encType, size int, buffer []byte) bool {

	//if revision != CERTREVISION_SUPPORTED_V2 || revision != CERTREVISION_SUPPORTED_V1 || size < 1 || encType != CERTYPE_PKCS_SIGNED_DATA {
	//	return false
	//}

	a.Type = encType
	a.Size = size
	a.Revision = revision

	a.Buffer = make([]byte, len(buffer))
	copy(a.Buffer, buffer)

	return true
}

func (a *Authenticode) Parse() bool {
	if a.Buffer != nil && len(a.Buffer) > 0 {
		signer, err := pkcs7.Parse(a.Buffer)
		if err != nil {
			return false
		}

		//for index := 100; index < 100+16; index++ {
		//	fmt.Printf("%02X ", a.Buffer[index])
		//}
		//fmt.Println()

		for _, v := range signer.Signers {
			a.DeptInfo = append(a.DeptInfo, string(v.IssuerAndSerialNumber.IssuerName.Bytes))
		}

		return true
		//for _, v := range signer.Certificates {
		//	a.DeptInfo = append(a.DeptInfo, string(v.CRLDistributionPoints))
		//}
	}

	return false
}
