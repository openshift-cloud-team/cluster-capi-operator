/*
Copyright 2026 Red Hat, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package commoncmdoptions

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/spf13/pflag"
	capiflags "sigs.k8s.io/cluster-api/util/flags"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/component-base/config"
	"k8s.io/component-base/config/options"
	"k8s.io/klog/v2"
	"k8s.io/klog/v2/textlogger"

	configv1 "github.com/openshift/api/config/v1"
	libgocrypto "github.com/openshift/library-go/pkg/crypto"

	"github.com/openshift/cluster-capi-operator/pkg/controllers"
	"github.com/openshift/cluster-capi-operator/pkg/operatorstatus"
	"github.com/openshift/cluster-capi-operator/pkg/util"
)

// The default durations for the leader election operations.
//
//nolint:gochecknoglobals
var (
	// LeaseDuration is the default duration for the leader election lease.
	LeaseDuration = metav1.Duration{Duration: 137 * time.Second}
	// RenewDeadline is the default duration for the leader renewal.
	RenewDeadline = metav1.Duration{Duration: 107 * time.Second}
	// RetryPeriod is the default duration for the leader election retrial.
	RetryPeriod = metav1.Duration{Duration: 26 * time.Second}
)

// OperatorConfig contains configuration options common to all CAPI operator managers.
type OperatorConfig struct {
	CAPINamespace     *string
	MAPINamespace     *string
	OperatorNamespace *string

	// TLSOptions are the TLS options functions used by the manager.  It
	// defaults to the cluster-wide TLS profile, but can be overridden on the
	// command line. Metrics and webhooks will use these.
	TLSOptions []func(config *tls.Config)

	managerName string
}

// InitOperatorConfig configures command line flags for options common to all managers.
//
//nolint:funlen
func InitOperatorConfig(ctx context.Context, cfg *rest.Config, scheme *runtime.Scheme, managerName, defaultManagerNamespace string) (
	logr.Logger, OperatorConfig, ctrl.Options,
	func(ctx context.Context, cancel context.CancelFunc, mgrOpts ctrl.Options) (ctrl.Manager, error),
	error,
) {
	goFlagSet := flag.NewFlagSet("operator", flag.ContinueOnError)
	operatorConfig := OperatorConfig{
		CAPINamespace:     goFlagSet.String("capi-namespace", controllers.DefaultCAPINamespace, "The namespace where CAPI components are installed."),
		MAPINamespace:     goFlagSet.String("mapi-namespace", controllers.DefaultMAPINamespace, "The namespace where MAPI components are installed."),
		OperatorNamespace: goFlagSet.String("operator-namespace", controllers.DefaultOperatorNamespace, "The namespace where the operator will run."),

		managerName: managerName,
	}

	healthAddr := goFlagSet.String("health-addr", ":9440", "The address for health checking.")
	logToStderr := goFlagSet.Bool("logtostderr", true, "log to standard error instead of files")
	capiManagerOptions := capiflags.ManagerOptions{}
	textLoggerConfig := textlogger.NewConfig()
	leaderElectionConfig := config.LeaderElectionConfiguration{
		LeaderElect:       true,
		LeaseDuration:     LeaseDuration,
		RenewDeadline:     RenewDeadline,
		RetryPeriod:       RetryPeriod,
		ResourceName:      managerName + "-leader",
		ResourceNamespace: defaultManagerNamespace,
	}

	textLoggerConfig.AddFlags(goFlagSet)

	fs := pflag.NewFlagSet("operator", pflag.ContinueOnError)
	capiflags.AddManagerOptions(fs, &capiManagerOptions)
	fs.AddGoFlagSet(goFlagSet)
	options.BindLeaderElectionFlags(&leaderElectionConfig, fs)

	if err := fs.Parse(os.Args[1:]); err != nil {
		return logr.Logger{}, OperatorConfig{}, ctrl.Options{}, nil, fmt.Errorf("failed to parse flags: %w", err)
	}

	if logToStderr != nil {
		klog.LogToStderr(*logToStderr)
	}

	log := textlogger.NewLogger(textLoggerConfig).WithName(managerName)
	ctrl.SetLogger(log)

	clusterTLSProfileSpec, setupSecurityProfileWatcher, err := resolveTLSProfile(ctx, cfg, scheme, log)
	if err != nil {
		return log, OperatorConfig{}, ctrl.Options{}, nil, fmt.Errorf("unable to resolve cluster TLS profile: %w", err)
	}

	// Use the cluster-wide default TLS profile if --tls-min-version or
	// --tls-cipher-suites were not set on the command line. Production
	// deployments are expected to omit these flags and use the cluster-wide
	// default.
	if !fs.Changed("tls-min-version") {
		capiManagerOptions.TLSMinVersion = libgocrypto.TLSVersionToNameOrDie(libgocrypto.TLSVersionOrDie(string(clusterTLSProfileSpec.MinTLSVersion)))
	}

	if !fs.Changed("tls-cipher-suites") {
		capiManagerOptions.TLSCipherSuites = libgocrypto.OpenSSLToIANACipherSuites(clusterTLSProfileSpec.Ciphers)
	}

	tlsOptions, diagnosticsOpts, err := capiflags.GetManagerOptions(capiManagerOptions)
	if err != nil {
		return log, OperatorConfig{}, ctrl.Options{}, nil, fmt.Errorf("unable to get CAPI manager options: %w", err)
	}

	log.Info("Cluster TLS profile spec", "min_version", clusterTLSProfileSpec.MinTLSVersion, "ciphers", strings.Join(clusterTLSProfileSpec.Ciphers, ","))
	log.Info("Operator TLS options", "min_version", capiManagerOptions.TLSMinVersion, "ciphers", strings.Join(capiManagerOptions.TLSCipherSuites, ","))

	operatorConfig.TLSOptions = tlsOptions

	return log, operatorConfig, ctrl.Options{
		Metrics:                       *diagnosticsOpts,
		HealthProbeBindAddress:        *healthAddr,
		LeaderElectionNamespace:       leaderElectionConfig.ResourceNamespace,
		LeaderElection:                leaderElectionConfig.LeaderElect,
		LeaderElectionReleaseOnCancel: true,
		LeaseDuration:                 &leaderElectionConfig.LeaseDuration.Duration,
		LeaderElectionID:              leaderElectionConfig.ResourceName,
		RetryPeriod:                   &leaderElectionConfig.RetryPeriod.Duration,
		RenewDeadline:                 &leaderElectionConfig.RenewDeadline.Duration,
		Scheme:                        scheme,
		Logger:                        log,
	}, initManager(cfg, setupSecurityProfileWatcher), nil
}

// GetClusterOperatorStatusClient returns a ClusterOperatorStatusClient struct which has been
// initialised with values from the command line.
func (opts *OperatorConfig) GetClusterOperatorStatusClient(mgr ctrl.Manager, platform configv1.PlatformType, controllerName string) operatorstatus.ClusterOperatorStatusClient {
	return operatorstatus.ClusterOperatorStatusClient{
		Client:            mgr.GetClient(),
		Recorder:          mgr.GetEventRecorderFor(opts.managerName + "-" + controllerName),
		ReleaseVersion:    util.GetReleaseVersion(),
		ManagedNamespace:  *opts.CAPINamespace,
		OperatorNamespace: *opts.OperatorNamespace,
		Platform:          platform,
	}
}

func initManager(cfg *rest.Config, securityProfileWatcher func(ctrl.Manager, context.CancelFunc) error) func(ctx context.Context, cancel context.CancelFunc, mgrOpts ctrl.Options) (ctrl.Manager, error) {
	return func(ctx context.Context, cancel context.CancelFunc, mgrOpts ctrl.Options) (ctrl.Manager, error) {
		mgr, err := ctrl.NewManager(cfg, mgrOpts)
		if err != nil {
			return nil, fmt.Errorf("unable to create manager: %w", err)
		}

		if err := errors.Join(
			mgr.AddHealthzCheck("health", healthz.Ping),
			mgr.AddReadyzCheck("check", healthz.Ping),
		); err != nil {
			return nil, fmt.Errorf("unable to add common checks: %w", err)
		}

		if err := securityProfileWatcher(mgr, cancel); err != nil {
			return nil, fmt.Errorf("unable to set up security profile watcher: %w", err)
		}

		return mgr, nil
	}
}
