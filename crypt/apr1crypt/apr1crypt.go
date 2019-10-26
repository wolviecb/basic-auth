// (C) Copyright 2012, Jeramey Crawford <jeramey@antihe.ro>. All
// rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// (C) Modifications copyright 2019, Tom Andrade <wolvie@gmail.com>

// Package apr1crypt implements the standard Unix MD5-crypt algorithm created
// by Poul-Henning Kamp for FreeBSD, and modified by the Apache project.
//
// The only change from MD5-crypt is the use of the magic constant "$apr1$"
// instead of "$1$". The algorithms are otherwise identical.
package apr1crypt

import (
	"github.com/wolviecb/basic-auth/crypt"
	"github.com/wolviecb/basic-auth/crypt/common"
	"github.com/wolviecb/basic-auth/crypt/md5crypt"
)

func init() {
	crypt.RegisterCrypt(crypt.APR1, New, magicPrefix)
}

const (
	magicPrefix   = "$apr1$"
	saltLenMin    = 1
	saltLenMax    = 8
	roundsDefault = 1000
)

// New returns a new crypt.Crypter computing the variant "apr1" of MD5-crypt
func New() crypt.Crypter {
	crypter := md5crypt.New()
	crypter.SetSalt(common.Salt{
		MagicPrefix:   []byte(magicPrefix),
		SaltLenMin:    saltLenMin,
		SaltLenMax:    saltLenMax,
		RoundsDefault: roundsDefault,
	})
	return crypter
}
