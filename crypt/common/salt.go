// (C) Copyright 2012, Jeramey Crawford <jeramey@antihe.ro>. All
// rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// (C) Modifications copyright 2019, Tom Andrade <wolvie@gmail.com>

package common

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strconv"
)

var (
	errSaltPrefix = errors.New("invalid magic prefix")
	errSaltFormat = errors.New("invalid salt format")
	errSaltRounds = errors.New("invalid rounds")
)

const (
	roundsPrefix = "rounds="
)

// Salt represents a salt.
type Salt struct {
	MagicPrefix []byte

	SaltLenMin int
	SaltLenMax int

	RoundsMin     int
	RoundsMax     int
	RoundsDefault int
}

// Generate generates a random salt of a given length.
//
// The length is set thus:
//
//   length > SaltLenMax: length = SaltLenMax
//   length < SaltLenMin: length = SaltLenMin
func (s *Salt) Generate(length int) []byte {
	if length > s.SaltLenMax {
		length = s.SaltLenMax
	} else if length < s.SaltLenMin {
		length = s.SaltLenMin
	}

	saltLen := (length * 6 / 8)
	if (length*6)%8 != 0 {
		saltLen++
	}
	salt := make([]byte, saltLen)
	rand.Read(salt)

	out := make([]byte, len(s.MagicPrefix)+length)
	copy(out, s.MagicPrefix)
	copy(out[len(s.MagicPrefix):], Base64_24Bit(salt))
	return out
}

// GenerateWRounds creates a random salt with the random bytes being of the
// length provided, and the rounds parameter set as specified.
//
// The parameters are set thus:
//
//   length > SaltLenMax: length = SaltLenMax
//   length < SaltLenMin: length = SaltLenMin
//
//   rounds < 0: rounds = RoundsDefault
//   rounds < RoundsMin: rounds = RoundsMin
//   rounds > RoundsMax: rounds = RoundsMax
//
// If rounds is equal to RoundsDefault, then the "rounds=" part of the salt is
// removed.
func (s *Salt) GenerateWRounds(length, rounds int) []byte {
	if length > s.SaltLenMax {
		length = s.SaltLenMax
	} else if length < s.SaltLenMin {
		length = s.SaltLenMin
	}
	if rounds < 0 {
		rounds = s.RoundsDefault
	} else if rounds < s.RoundsMin {
		rounds = s.RoundsMin
	} else if rounds > s.RoundsMax {
		rounds = s.RoundsMax
	}

	saltLen := (length * 6 / 8)
	if (length*6)%8 != 0 {
		saltLen++
	}
	salt := make([]byte, saltLen)
	rand.Read(salt)

	roundsText := ""
	if rounds != s.RoundsDefault {
		roundsText = roundsPrefix + strconv.Itoa(rounds) + "$"
	}

	out := make([]byte, len(s.MagicPrefix)+len(roundsText)+length)
	copy(out, s.MagicPrefix)
	copy(out[len(s.MagicPrefix):], []byte(roundsText))
	copy(out[len(s.MagicPrefix)+len(roundsText):], Base64_24Bit(salt))
	return out
}

// Decode extracts salt, rounds, hash and error from a secret
func (s *Salt) Decode(raw []byte) (salt []byte, rounds int, isRoundsDef bool, rest []byte, err error) {
	tokens := bytes.SplitN(raw, []byte{'$'}, 4)
	if len(tokens) < 3 {
		err = errSaltFormat
		return
	}
	if !bytes.HasPrefix(raw, s.MagicPrefix) {
		err = errSaltPrefix
		return
	}

	if bytes.HasPrefix(tokens[2], []byte(roundsPrefix)) {
		if len(tokens) < 4 {
			err = errSaltFormat
			return
		}
		salt = tokens[3]

		rounds, err = strconv.Atoi(string(tokens[2][len(roundsPrefix):]))
		if err != nil {
			err = errSaltRounds
			return
		}
		if rounds < s.RoundsMin {
			rounds = s.RoundsMin
		}
		if rounds > s.RoundsMax {
			rounds = s.RoundsMax
		}
		isRoundsDef = true
	} else {
		salt = tokens[2]
		rounds = s.RoundsDefault
	}
	if len(salt) > s.SaltLenMax {
		salt = salt[0:s.SaltLenMax]
	}

	return
}
