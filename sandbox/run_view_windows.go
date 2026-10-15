//go:build windows

package sandbox

import "errors"

func openDemandRunView(string, string, string, Emit) (demandRunView, error) {
	return nil, errors.New("Windows demand file view backend is not ready")
}
