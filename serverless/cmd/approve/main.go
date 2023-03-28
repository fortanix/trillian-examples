// Program for approving DSM crypto requests.

package main
import (
	"context"
	"encoding/json"
	"flag"
	"net/http"
	"os"

	"github.com/fortanix/sdkms-client-go/sdkms"
	"github.com/golang/glog"
)

var (
	dsmApiKey   = flag.String("dsm_api_key", "", "API key for accessing smartkey")
	dsmEndpoint = flag.String("dsm_endpoint", "https://www.smartkey.io", "DSM instance to use when signing with DSM")
	state       = flag.String("state", "", "State file for the request to approve")
)

type QuorumSigningState struct {
	Msg []byte
	RequestID sdkms.UUID
}

func main() {
	flag.Parse()

	data, err := os.ReadFile(*state)
	if err != nil {
		glog.Exitf("Unable to read state file: %q", err)
	}
	var request QuorumSigningState
	err = json.Unmarshal(data, &request)
	if err != nil {
		glog.Exitf("Unable to deserialize request data: %q", err)
	}

	if len(*dsmApiKey) == 0 {
		glog.Exitf("dsm_api_key is required")
	}

	if len(*dsmEndpoint) == 0 {
		glog.Exitf("dsm_endpoint is required")
	}

	client := sdkms.Client{
		HTTPClient: http.DefaultClient,
		Auth: sdkms.APIKey(*dsmApiKey),
		Endpoint: *dsmEndpoint,
	}
	body := sdkms.ApproveRequest{}
	_, err = client.ApproveRequest(context.Background(), request.RequestID, body)
	if err != nil {
		glog.Exitf("Error approving request: %q", err)
	}
}
