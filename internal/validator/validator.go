// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

package validator

type Validator struct{}

func NewValidator() (*Validator, error) {
	v := &Validator{}
	return v, nil
}
