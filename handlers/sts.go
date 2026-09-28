package handlers

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/redscaresu/fakeaws/handlers/awsproto"
	"github.com/redscaresu/fakeaws/models"
)

// Every caller is one fixed IAM user. Real AWS answers the user's
// AIDA-prefixed unique id as UserId; that shape trips the gitleaks
// access-key rule and the provider never parses it, so it is plain.
const (
	stsCallerUserName = "fakeaws"
	stsCallerUserID   = "fakeaws-caller"
)

// registerSTSRoutes attaches the STS Query-RPC dispatcher. Real STS is
// sts.amazonaws.com (or a regional host); terraform-provider-aws is
// pointed here via `endpoints { sts = ... }` or AWS_ENDPOINT_URL_STS.
// Its credential-validation client posts to the trailing-slash form.
func (app *Application) registerSTSRoutes(r chi.Router) {
	r.Post("/sts", app.handleSTS)
	r.Post("/sts/", app.handleSTS)
}

// handleSTS models GetCallerIdentity only. Every other action answers
// 501 with an UNIMPLEMENTED log line naming it.
func (app *Application) handleSTS(w http.ResponseWriter, r *http.Request) {
	req, err := awsproto.ParseQueryRPC(r)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, fmt.Errorf("%w: %v", models.ErrConflict, err))
		return
	}
	switch req.Action {
	case "GetCallerIdentity":
		stsGetCallerIdentity(w)
	default:
		writeUnimplemented(w, "POST /sts Action="+req.Action)
	}
}

type stsGetCallerIdentityResult struct {
	Arn     string `xml:"Arn"`
	UserId  string `xml:"UserId"`
	Account string `xml:"Account"`
}

// CRITICAL[sts-caller-identity-fake-account]: GetCallerIdentity answers
// Account awsproto.FakeAccountID (000000000000) and an Arn in that
// account. Configs pin allowed_account_ids = ["000000000000"], so the
// provider refuses to apply against any other account.
func stsGetCallerIdentity(w http.ResponseWriter) {
	awsproto.WriteQueryRPCResponse(w, "GetCallerIdentity", &stsGetCallerIdentityResult{
		Arn:     awsproto.BuildIAMUserARN(stsCallerUserName),
		UserId:  stsCallerUserID,
		Account: awsproto.FakeAccountID,
	})
}
