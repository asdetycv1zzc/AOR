package toolchain

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"time"

	"github.com/akimisaka/aor/pkg/contracts"
	"github.com/google/uuid"
)

var ErrProvisionerUnavailable = errors.New("toolchain provisioner unavailable")

const (
	installationLeaseDuration  = time.Hour
	installationLeaseHeartbeat = 10 * time.Minute
)

type Provisioner struct {
	store        *InstallStore
	installer    *ArchiveInstaller
	pollInterval time.Duration
	clock        func() time.Time
	running      atomic.Bool
	failingSince atomic.Int64
}

func NewProvisioner(store *InstallStore, installer *ArchiveInstaller, pollInterval time.Duration, clock func() time.Time) (*Provisioner, error) {
	if store == nil || installer == nil || pollInterval < 100*time.Millisecond || pollInterval > time.Minute {
		return nil, ErrProvisionerUnavailable
	}
	if clock == nil {
		clock = time.Now
	}
	return &Provisioner{store: store, installer: installer, pollInterval: pollInterval, clock: clock}, nil
}

func (provisioner *Provisioner) Run(ctx context.Context) {
	if provisioner == nil || ctx == nil || !provisioner.running.CompareAndSwap(false, true) {
		return
	}
	defer provisioner.running.Store(false)

	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			dispatchErr := provisioner.DispatchOnce(ctx)
			now := provisioner.clock().UTC()
			if dispatchErr == nil {
				provisioner.failingSince.Store(0)
			} else {
				provisioner.failingSince.CompareAndSwap(0, now.UnixNano())
			}
			timer.Reset(provisioner.pollInterval)
		}
	}
}

func (provisioner *Provisioner) Ready() error {
	if provisioner == nil || !provisioner.running.Load() {
		return ErrProvisionerUnavailable
	}
	if failingSince := provisioner.failingSince.Load(); failingSince > 0 && provisioner.clock().UTC().Sub(time.Unix(0, failingSince)) > 30*time.Second {
		return ErrProvisionerUnavailable
	}
	return nil
}

func (provisioner *Provisioner) DispatchOnce(ctx context.Context) error {
	if provisioner == nil || ctx == nil {
		return ErrProvisionerUnavailable
	}
	leaseID, err := uuid.NewV7()
	if err != nil {
		return err
	}
	installations, err := provisioner.store.ClaimQueued(ctx, 1, leaseID.String(), installationLeaseDuration)
	if err != nil {
		return err
	}
	if len(installations) == 0 {
		return nil
	}
	installation := installations[0]
	if !validProvisioningRequest(installation.Tool) {
		return provisioner.store.Fail(ctx, installation.ID, installation.LeaseToken, installation.Attempt, false,
			"AOR_TOOLCHAIN_INSTALL_UNSUPPORTED", "only authorized non-GCC USER_ARCHIVE installations can be provisioned", provisioner.clock().UTC())
	}
	installContext, cancelInstall := context.WithCancel(ctx)
	heartbeatDone := make(chan error, 1)
	go provisioner.renewInstallationLease(installContext, cancelInstall, installation, heartbeatDone)
	installed, installErr := provisioner.installer.Install(installContext, installation.Tool, nil)
	cancelInstall()
	heartbeatErr := <-heartbeatDone
	if heartbeatErr != nil {
		installErr = errors.Join(installErr, heartbeatErr)
	}
	if installErr == nil {
		return provisioner.store.Complete(ctx, installation.ID, installation.LeaseToken, installed.ID, installation.Attempt, provisioner.clock().UTC())
	}
	errorCode := provisioningErrorCode(installErr)
	errorMessage := provisioningErrorMessage(installErr)
	return provisioner.store.Fail(ctx, installation.ID, installation.LeaseToken, installation.Attempt,
		provisioningErrorRetryable(installErr), errorCode, errorMessage, provisioner.clock().UTC())
}

func (provisioner *Provisioner) renewInstallationLease(ctx context.Context, cancel context.CancelFunc, installation Installation, done chan<- error) {
	ticker := time.NewTicker(installationLeaseHeartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			done <- nil
			return
		case <-ticker.C:
			extendContext, extendCancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
			err := provisioner.store.ExtendClaim(extendContext, installation.ID, installation.LeaseToken, installation.Attempt, installationLeaseDuration)
			extendCancel()
			if err != nil {
				cancel()
				done <- err
				return
			}
		}
	}
}

func validProvisioningRequest(tool contracts.VersionedTool) bool {
	return tool.ReadyToProvision() && tool.Install != nil && tool.Install.Method == contracts.ToolchainInstallUserArchive && SupportsPortableArchive(tool)
}

func provisioningErrorRetryable(err error) bool {
	for _, permanent := range []error{
		ErrUnsupportedArchive,
		ErrUnsupportedTool,
		ErrArchiveLimit,
		ErrToolchainConflict,
		ErrToolchainDigest,
		ErrToolchainVersion,
		ErrToolchainNotPortable,
		ErrInvalidInventory,
	} {
		if errors.Is(err, permanent) {
			return false
		}
	}
	return true
}

func provisioningErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrArchiveLimit):
		return "AOR_TOOLCHAIN_ARCHIVE_LIMIT"
	case errors.Is(err, ErrToolchainVersion):
		return "AOR_TOOLCHAIN_VERSION_MISMATCH"
	case errors.Is(err, ErrToolchainConflict):
		return "AOR_TOOLCHAIN_INVENTORY_CONFLICT"
	case errors.Is(err, ErrToolchainDigest):
		return "AOR_TOOLCHAIN_ARCHIVE_DIGEST_MISMATCH"
	case errors.Is(err, ErrToolchainNotPortable):
		return "AOR_TOOLCHAIN_ARCHIVE_NOT_PORTABLE"
	case errors.Is(err, ErrUnsupportedArchive), errors.Is(err, ErrUnsupportedTool), errors.Is(err, ErrInvalidInventory):
		return "AOR_TOOLCHAIN_INSTALL_UNSUPPORTED"
	default:
		return "AOR_TOOLCHAIN_INSTALL_FAILED"
	}
}

func provisioningErrorMessage(err error) string {
	message := strings.TrimSpace(strings.NewReplacer("\r", " ", "\n", " ", "\x00", " ").Replace(err.Error()))
	if message == "" {
		message = "toolchain installation failed"
	}
	if len(message) > 4096 {
		message = message[:4096]
	}
	return message
}
