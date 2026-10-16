package terabox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ExecutableAndroidAnalyticsBridge invokes an explicitly selected execution
// adapter without a shell. It sends one AndroidAnalyticsRequest as JSON stdin
// and requires one matching AndroidAnalyticsReceipt as JSON stdout. Stderr is
// discarded; command output/error text is never returned to a log. The shipped
// tools/android_analytics_bridge.py adapter executes the actual native SDK calls
// in an already running APK process through Frida.
type ExecutableAndroidAnalyticsBridge struct {
	Command string
	Args    []string
	Timeout time.Duration // default 30s; maximum 2 minutes
}

type boundedAnalyticsOutput struct{ bytes.Buffer }

func (b *boundedAnalyticsOutput) Write(data []byte) (int, error) {
	if b.Len()+len(data) > 16<<10 {
		return 0, errors.New("analytics adapter output exceeded its limit")
	}
	return b.Buffer.Write(data)
}

func (bridge ExecutableAndroidAnalyticsBridge) ExecuteAndroidAnalytics(ctx context.Context, request AndroidAnalyticsRequest) (*AndroidAnalyticsReceipt, error) {
	if !validAnalyticsRequest(request) {
		return nil, errors.New("analytics requires a valid request and an explicit absolute executable path")
	}
	var receipt AndroidAnalyticsReceipt
	if err := executeAndroidAdapter(ctx, bridge.Command, bridge.Args, bridge.Timeout, request, &receipt); err != nil {
		return nil, err
	}
	if !validAnalyticsReceipt(request, &receipt) {
		return nil, errors.New("analytics adapter returned invalid or mismatched execution evidence")
	}
	return &receipt, nil
}

// ExecutableAndroidDeviceActivationSigner invokes the shipped
// tools/android_device_activation_signer.py (or another explicitly selected
// native adapter) with the exact same-installation signing request.
type ExecutableAndroidDeviceActivationSigner ExecutableAndroidAnalyticsBridge

func (signer ExecutableAndroidDeviceActivationSigner) SignAndroidDeviceActivation(ctx context.Context, request AndroidDeviceActivationSignRequest) (*AndroidDeviceActivationSignature, error) {
	var signature AndroidDeviceActivationSignature
	if err := executeAndroidAdapter(ctx, signer.Command, signer.Args, signer.Timeout, request, &signature); err != nil {
		return nil, err
	}
	if signature.DeviceID != request.DeviceID || signature.Channel != request.Channel || signature.ClientType != request.ClientType ||
		signature.TimestampMS != request.TimestampMS || signature.Signature == "" || !attributionStringValid(signature.Signature) {
		return nil, errors.New("native signer returned mismatched installation evidence")
	}
	return &signature, nil
}

func executeAndroidAdapter(ctx context.Context, executable string, args []string, timeout time.Duration, input, outputValue any) error {
	if !filepath.IsAbs(executable) || len(args) > 64 {
		return errors.New("native adapter requires an explicit absolute executable path")
	}
	for _, arg := range args {
		if len(arg) > 4096 || strings.ContainsRune(arg, 0) {
			return errors.New("invalid native adapter argument")
		}
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if timeout > 2*time.Minute {
		return errors.New("native adapter timeout exceeds two minutes")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	payload, err := json.Marshal(input)
	if err != nil {
		return errors.New("native adapter input could not be encoded")
	}
	command := exec.CommandContext(ctx, executable, args...)
	command.Stdin = bytes.NewReader(payload)
	output := &boundedAnalyticsOutput{}
	command.Stdout = output
	command.Stderr = io.Discard
	command.WaitDelay = time.Second
	if err := command.Run(); err != nil {
		return errors.New("native adapter failed or timed out; runtime outcome may be partial")
	}
	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(outputValue); err != nil {
		return errors.New("native adapter returned invalid execution evidence")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("native adapter returned extra output")
	}
	return nil
}
