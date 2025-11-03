package tpm

import "github.com/google/go-tpm/tpm2"

// keyAttributeUpdater is a function that updates a TPMAObject attribute
type keyAttributeUpdater func(*tpm2.TPMAObject)

// nvAttributeUpdater is a function that updates a TPMANV attribute
type nvAttributeUpdater func(*tpm2.TPMANV)

// This is from github.com/folbricht/tpmk, updated for go-tpm v0.9.x
var stringToKeyAttribute = map[string]keyAttributeUpdater{
	"fixedtpm":            func(attr *tpm2.TPMAObject) { attr.FixedTPM = true },
	"fixedparent":         func(attr *tpm2.TPMAObject) { attr.FixedParent = true },
	"sensitivedataorigin": func(attr *tpm2.TPMAObject) { attr.SensitiveDataOrigin = true },
	"userwithauth":        func(attr *tpm2.TPMAObject) { attr.UserWithAuth = true },
	"adminwithpolicy":     func(attr *tpm2.TPMAObject) { attr.AdminWithPolicy = true },
	"noda":                func(attr *tpm2.TPMAObject) { attr.NoDA = true },
	"restricted":          func(attr *tpm2.TPMAObject) { attr.Restricted = true },
	"decrypt":             func(attr *tpm2.TPMAObject) { attr.Decrypt = true },
	"sign":                func(attr *tpm2.TPMAObject) { attr.SignEncrypt = true },
}

var stringToNVAttribute = map[string]nvAttributeUpdater{
	"ppwrite":        func(attr *tpm2.TPMANV) { attr.PPWrite = true },
	"ownerwrite":     func(attr *tpm2.TPMANV) { attr.OwnerWrite = true },
	"authwrite":      func(attr *tpm2.TPMANV) { attr.AuthWrite = true },
	"policywrite":    func(attr *tpm2.TPMANV) { attr.PolicyWrite = true },
	"policydelete":   func(attr *tpm2.TPMANV) { attr.PolicyDelete = true },
	"writelocked":    func(attr *tpm2.TPMANV) { attr.WriteLocked = true },
	"writeall":       func(attr *tpm2.TPMANV) { attr.WriteAll = true },
	"writedefine":    func(attr *tpm2.TPMANV) { attr.WriteDefine = true },
	"writestclear":   func(attr *tpm2.TPMANV) { attr.WriteSTClear = true },
	"globallock":     func(attr *tpm2.TPMANV) { attr.GlobalLock = true },
	"ppread":         func(attr *tpm2.TPMANV) { attr.PPRead = true },
	"ownerread":      func(attr *tpm2.TPMANV) { attr.OwnerRead = true },
	"authread":       func(attr *tpm2.TPMANV) { attr.AuthRead = true },
	"policyread":     func(attr *tpm2.TPMANV) { attr.PolicyRead = true },
	"noda":           func(attr *tpm2.TPMANV) { attr.NoDA = true },
	"orderly":        func(attr *tpm2.TPMANV) { attr.Orderly = true },
	"clearstclear":   func(attr *tpm2.TPMANV) { attr.ClearSTClear = true },
	"readlocked":     func(attr *tpm2.TPMANV) { attr.ReadLocked = true },
	"written":        func(attr *tpm2.TPMANV) { attr.Written = true },
	"platformcreate": func(attr *tpm2.TPMANV) { attr.PlatformCreate = true },
	"readstclear":    func(attr *tpm2.TPMANV) { attr.ReadSTClear = true },
}
