/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2021 The LibreGraph Authors.
 */

package serve

const (
	ExitCodeStartupError = 64
)

type ErrorWithExitCode struct {
	Code int
	Err  error
}

func (e *ErrorWithExitCode) Error() string {
	return e.Err.Error()
}

func (e *ErrorWithExitCode) Unwrap() error {
	return e.Err
}

func WrapErrorWithExitCode(err error, code int) error {
	return &ErrorWithExitCode{
		Err:  err,
		Code: code,
	}
}

func StartupError(err error) error {
	return WrapErrorWithExitCode(err, ExitCodeStartupError)
}
