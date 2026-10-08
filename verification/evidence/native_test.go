//go:build evidence

package evidence

// These test-only symbol references call the committed private entry points.
// There are no copied serializers, production exports, or source overlays.
// Signatures use the owning packages' types; symbol renames fail at linkage.
// As go:linkname bypasses Go visibility/type checking, signature changes require
// review against the owning methods. These calls are never in a shipped binary.
import (
	"context"
	aws "github.com/aidotmarket/aim-data-gateway/internal/awsverification"
	cf "github.com/aidotmarket/aim-data-gateway/internal/cloudflareverification"
	gw "github.com/aidotmarket/aim-data-gateway/internal/verification"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	_ "unsafe" // required by go:linkname; only built in the evidence test binary
)

//go:linkname gatewayRun github.com/aidotmarket/aim-data-gateway/internal/verification.(*Runner).run
func gatewayRun(*gw.Runner, context.Context, wire.ScanJob, wire.Snapshot) error

//go:linkname gatewaySnapshot github.com/aidotmarket/aim-data-gateway/internal/verification.(*Runner).fetchSnapshot
func gatewaySnapshot(*gw.Runner, context.Context, wire.ScanJob) (string, error)

//go:linkname awsScan github.com/aidotmarket/aim-data-gateway/internal/awsverification.Handler.scan
func awsScan(aws.Handler, context.Context, *aws.Secret, wire.ScanJob, *aws.Source) ([]byte, error)

//go:linkname cfScan github.com/aidotmarket/aim-data-gateway/internal/cloudflareverification.Handler.scan
func cfScan(cf.Handler, context.Context, *cf.Secret, wire.ScanJob, *cf.Source) ([]byte, error)
