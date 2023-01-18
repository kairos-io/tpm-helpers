package tpm

import "github.com/google/go-tpm/tpm2"

// This is from github.com/folbricht/tpmk
var stringToKeyAttribute = map[string]tpm2.KeyProp{
	"fixedtpm":            tpm2.FlagFixedTPM,
	"fixedparent":         tpm2.FlagFixedParent,
	"sensitivedataorigin": tpm2.FlagSensitiveDataOrigin,
	"userwithauth":        tpm2.FlagUserWithAuth,
	"adminwithpolicy":     tpm2.FlagAdminWithPolicy,
	"noda":                tpm2.FlagNoDA,
	"restricted":          tpm2.FlagRestricted,
	"decrypt":             tpm2.FlagDecrypt,
	"sign":                tpm2.FlagSign,
}

var stringToNVAttribute = map[string]tpm2.NVAttr{
	"ppwrite":        tpm2.AttrPPWrite,
	"ownerwrite":     tpm2.AttrOwnerWrite,
	"authwrite":      tpm2.AttrAuthWrite,
	"policywrite":    tpm2.AttrPolicyWrite,
	"policydelete":   tpm2.AttrPolicyDelete,
	"writelocked":    tpm2.AttrWriteLocked,
	"writeall":       tpm2.AttrWriteAll,
	"writedefine":    tpm2.AttrWriteDefine,
	"writestclear":   tpm2.AttrWriteSTClear,
	"globallock":     tpm2.AttrGlobalLock,
	"ppread":         tpm2.AttrPPRead,
	"ownerread":      tpm2.AttrOwnerRead,
	"authread":       tpm2.AttrAuthRead,
	"policyread":     tpm2.AttrPolicyRead,
	"noda":           tpm2.AttrNoDA,
	"orderly":        tpm2.AttrOrderly,
	"clearstclear":   tpm2.AttrClearSTClear,
	"readlocked":     tpm2.AttrReadLocked,
	"written":        tpm2.AttrWritten,
	"platformcreate": tpm2.AttrPlatformCreate,
	"readstclear":    tpm2.AttrReadSTClear,
}
