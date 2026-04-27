package awsproto

import (
	"encoding/xml"
	"net/http"
)

// WriteXMLResponse marshals payload as XML and writes it with the
// status code. Used by S3 and Route53 (the two pure XML-REST
// services). Caller passes an XMLName-tagged struct.
//
// The XML declaration (<?xml version="1.0" ...?>) is emitted
// unconditionally — terraform-provider-aws's XML decoder handles its
// presence either way, but emitting it matches what real S3/Route53
// do and keeps wire-shape parity tight.
func WriteXMLResponse(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(xml.Header))
	if payload == nil {
		return
	}
	body, err := xml.MarshalIndent(payload, "", "  ")
	if err != nil {
		return
	}
	_, _ = w.Write(body)
}
