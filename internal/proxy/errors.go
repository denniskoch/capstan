// Copyright (C) 2026 Dennis Koch
// SPDX-License-Identifier: AGPL-3.0-or-later

package proxy

import (
	"encoding/json"
	"net/http"
)

// dockerError is the Engine API's error shape: {"message": "..."}.
//
// capstan's own refusals are the one place it must emit a body the daemon did
// not produce. Emitting it in the daemon's shape keeps a standard client's
// error handling working, which is the closest thing to "no divergence" that a
// proxy-generated error can manage.
type dockerError struct {
	Message string `json:"message"`
}

// WriteDockerError writes an Engine-API-shaped error response.
func WriteDockerError(w http.ResponseWriter, status int, msg string) {
	writeDockerError(w, status, msg)
}

func writeDockerError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(dockerError{Message: msg})
}
