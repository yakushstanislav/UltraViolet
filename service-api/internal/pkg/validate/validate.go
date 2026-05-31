// Package validate hosts the shared go-playground validator instance plus
// project-wide custom validators. validator caches reflection metadata per
// instance, so reusing one instance avoids redundant work and keeps custom
// validators registered in a single place.
package validate

import (
	"strings"
	"time"

	"gopkg.in/go-playground/validator.v9"
)

// V is the shared validator instance.
var V = validator.New()

func init() {
	mustRegister("uppercase", func(fl validator.FieldLevel) bool {
		s := fl.Field().String()

		return s == strings.ToUpper(s)
	})

	// datetime is a v10 built-in; v9 needs manual registration.
	mustRegister("datetime", func(fl validator.FieldLevel) bool {
		_, err := time.Parse(fl.Param(), fl.Field().String())

		return err == nil
	})

	// noctrl rejects strings that contain CR, LF, or NUL bytes — guards against
	// header/log injection through user-supplied fields.
	mustRegister("noctrl", func(fl validator.FieldLevel) bool {
		return !strings.ContainsAny(fl.Field().String(), "\r\n\x00")
	})

	// iso3166_1_alpha2 accepts exactly two uppercase ASCII letters (ISO 3166-1
	// alpha-2 country codes as used by country-strategy scans).
	mustRegister("iso3166_1_alpha2", func(fl validator.FieldLevel) bool {
		s := fl.Field().String()
		if len(s) != 2 {
			return false
		}

		for i := 0; i < 2; i++ {
			c := s[i]
			if c < 'A' || c > 'Z' {
				return false
			}
		}

		return true
	})
}

func mustRegister(tag string, fn validator.Func) {
	if err := V.RegisterValidation(tag, fn); err != nil {
		panic("validate: register " + tag + ": " + err.Error())
	}
}

// Struct validates the given struct against its `validate` tags.
func Struct(s any) error {
	return V.Struct(s)
}
