// Copyright 2026 Red Hat, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"
	operatorv1alpha1 "github.com/openshift/api/operator/v1alpha1"

	"github.com/openshift/cluster-capi-operator/e2e/framework"
	"github.com/openshift/cluster-capi-operator/pkg/test"
	"github.com/openshift/cluster-capi-operator/pkg/util"
	utiltls "github.com/openshift/controller-runtime-common/pkg/tls"
)

// tlsEndpoint describes a TLS-secured endpoint exposed by a CAPI operator component.
type tlsEndpoint struct {
	name       string            // human-readable label, e.g. "capi-operator metrics"
	namespace  string            // pod namespace
	labels     map[string]string // pod label selector
	port       int               // container port to connect to
	serverName string            // TLS ServerName for cert validation (service DNS name)
}

// Core endpoints are present on all clusters where CAPI is enabled.
var coreEndpoints = []tlsEndpoint{
	{
		name:       "capi-operator metrics",
		namespace:  framework.CAPIOperatorNamespace,
		labels:     map[string]string{"k8s-app": "capi-operator"},
		port:       8443,
		serverName: "capi-operator-metrics.openshift-cluster-api-operator.svc",
	},
	{
		name:       "capi-controllers metrics",
		namespace:  framework.CAPINamespace,
		labels:     map[string]string{"k8s-app": "capi-controllers"},
		port:       8443,
		serverName: "capi-controllers-metrics.openshift-cluster-api.svc",
	},
	{
		name:       "capi-controllers webhook",
		namespace:  framework.CAPINamespace,
		labels:     map[string]string{"k8s-app": "capi-controllers"},
		port:       9443,
		serverName: "capi-controllers-webhook-service.openshift-cluster-api.svc",
	},
	{
		name:       "machine-api-migration metrics",
		namespace:  framework.CAPINamespace,
		labels:     map[string]string{"k8s-app": "capi-controllers"},
		port:       8442,
		serverName: "capi-controllers-metrics.openshift-cluster-api.svc",
	},
	{
		name:       "compatibility-requirements metrics",
		namespace:  framework.CompatibilityRequirementsNamespace,
		labels:     map[string]string{"k8s-app": "compatibility-requirements-controllers"},
		port:       8443,
		serverName: "compatibility-requirements-controllers-metrics.openshift-compatibility-requirements-operator.svc",
	},
	{
		name:       "compatibility-requirements webhook",
		namespace:  framework.CompatibilityRequirementsNamespace,
		labels:     map[string]string{"k8s-app": "compatibility-requirements-controllers"},
		port:       9443,
		serverName: "compatibility-requirements-controllers-webhook-service.openshift-compatibility-requirements-operator.svc",
	},
}

// AWS-specific endpoints.
var awsEndpoints = []tlsEndpoint{
	{
		name:      "capa-controller-manager metrics",
		namespace: framework.CAPINamespace,
		labels:    map[string]string{"control-plane": "capa-controller-manager"},
		port:      8443,
		// CAPA metrics endpoint uses a self-signed cert
	},
	{
		name:       "capa-controller-manager webhook",
		namespace:  framework.CAPINamespace,
		labels:     map[string]string{"control-plane": "capa-controller-manager"},
		port:       9443,
		serverName: "capa-webhook-service.openshift-cluster-api.svc",
	},
}

// tlsTestCase defines a TLS version probe and its expected outcome.
type tlsTestCase struct {
	version       uint16
	versionName   string
	shouldSucceed bool
}

var _ = Describe("TLS Security Profile", Ordered, func() {
	var (
		caCertPool *x509.CertPool
	)

	BeforeAll(func(ctx context.Context) {
		By("Checking that required feature gates are enabled")
		if !framework.IsFeatureGateEnabled(ctx, cl, features.FeatureGateClusterAPIMachineManagement) {
			Skip("ClusterAPIMachineManagement feature gate is not enabled")
		}
		if !framework.IsFeatureGateEnabled(ctx, cl, features.FeatureGateTLSAdherence) {
			Skip("TLSAdherence feature gate is not enabled")
		}

		By("Saving original APIServer TLS configuration")
		apiServer := &configv1.APIServer{}
		Expect(cl.Get(ctx, client.ObjectKey{Name: "cluster"}, apiServer)).To(Succeed())

		DeferCleanup(func(ctx context.Context) {
			By("Restoring original APIServer TLS configuration")
			restoreAdherence := apiServer.Spec.TLSAdherence
			// tlsAdherence cannot be removed once set, so if the original was
			// empty (unset), restore to LegacyAdheringComponentsOnly which is
			// the behavioral equivalent.
			if restoreAdherence == configv1.TLSAdherencePolicyNoOpinion {
				restoreAdherence = configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly
			}
			setTLSConfig(ctx, restoreAdherence, apiServer.Spec.TLSSecurityProfile)
		}, NodeTimeout(framework.WaitShort))

		By("Loading service-ca CA certificate")
		caCertPool = loadServiceCACert(ctx)
	}, NodeTimeout(framework.WaitShort))

	// intermediateTests defines TLS version assertions for the Intermediate profile.
	// Intermediate has MinTLSVersion=1.2, so TLS 1.0 must be rejected while 1.2 and 1.3 must be accepted.
	intermediateTests := []tlsTestCase{
		{tls.VersionTLS10, "TLS 1.0", false},
		{tls.VersionTLS12, "TLS 1.2", true},
		{tls.VersionTLS13, "TLS 1.3", true},
	}

	// modernTests defines TLS version assertions for the Modern profile.
	// Modern has MinTLSVersion=1.3, so TLS 1.0 and 1.2 must be rejected while 1.3 must be accepted.
	modernTests := []tlsTestCase{
		{tls.VersionTLS10, "TLS 1.0", false},
		{tls.VersionTLS12, "TLS 1.2", false},
		{tls.VersionTLS13, "TLS 1.3", true},
	}

	Context("with LegacyAdheringComponentsOnly and Intermediate profile", Ordered, func() {
		var (
			configChangedAt      metav1.Time
			previousCAPIRevision operatorv1alpha1.RevisionName
			rolloutExpected      bool
		)

		BeforeAll(func(ctx context.Context) {
			previousCAPIRevision = waitForCAPIRollout(ctx)

			By("Setting TLS configuration to LegacyAdheringComponentsOnly + Intermediate")
			configChangedAt, rolloutExpected = setTLSConfig(ctx,
				configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly,
				&configv1.TLSSecurityProfile{
					Type:         configv1.TLSProfileIntermediateType,
					Intermediate: &configv1.IntermediateTLSProfile{},
				},
			)
		}, NodeTimeout(framework.WaitShort))

		Context("core endpoints", func() {
			DescribeTable("TLS version negotiation",
				func(ctx context.Context, ep tlsEndpoint, tlsVersion uint16, shouldSucceed bool) {
					if rolloutExpected {
						waitForPodRestart(ctx, ep, configChangedAt)
					}
					assertTLSVersion(ctx, ep, tlsVersion, shouldSucceed, caCertPool)
				},
				tlsVersionEntries(coreEndpoints, intermediateTests),
			)
		})

		Context("AWS endpoints", func() {
			BeforeAll(func(ctx context.Context) {
				if platform != configv1.AWSPlatformType {
					Skip("Skipping AWS TLS tests")
				}

				if rolloutExpected {
					waitForCAPIRollout(ctx, previousCAPIRevision)
				}
			}, NodeTimeout(framework.WaitMedium))

			DescribeTable("TLS version negotiation",
				func(ctx context.Context, ep tlsEndpoint, tlsVersion uint16, shouldSucceed bool) {
					assertTLSVersion(ctx, ep, tlsVersion, shouldSucceed, caCertPool)
				},
				tlsVersionEntries(awsEndpoints, intermediateTests),
			)
		})
	})

	Context("with StrictAllComponents and Modern profile", Ordered, func() {
		var (
			configChangedAt      metav1.Time
			previousCAPIRevision operatorv1alpha1.RevisionName
			rolloutExpected      bool
		)

		BeforeAll(func(ctx context.Context) {
			previousCAPIRevision = waitForCAPIRollout(ctx)

			By("Setting TLS configuration to StrictAllComponents + Modern")
			configChangedAt, rolloutExpected = setTLSConfig(ctx,
				configv1.TLSAdherencePolicyStrictAllComponents,
				&configv1.TLSSecurityProfile{
					Type:   configv1.TLSProfileModernType,
					Modern: &configv1.ModernTLSProfile{},
				},
			)
		}, NodeTimeout(framework.WaitShort))

		Context("core endpoints", func() {
			DescribeTable("TLS version negotiation",
				func(ctx context.Context, ep tlsEndpoint, tlsVersion uint16, shouldSucceed bool) {
					if rolloutExpected {
						waitForPodRestart(ctx, ep, configChangedAt)
					}
					assertTLSVersion(ctx, ep, tlsVersion, shouldSucceed, caCertPool)
				},
				tlsVersionEntries(coreEndpoints, modernTests),
			)
		})

		Context("AWS endpoints", func() {
			BeforeAll(func(ctx context.Context) {
				if platform != configv1.AWSPlatformType {
					Skip("Skipping AWS TLS tests")
				}

				if rolloutExpected {
					waitForCAPIRollout(ctx, previousCAPIRevision)
				}
			}, NodeTimeout(framework.WaitMedium))

			DescribeTable("TLS version negotiation",
				func(ctx context.Context, ep tlsEndpoint, tlsVersion uint16, shouldSucceed bool) {
					assertTLSVersion(ctx, ep, tlsVersion, shouldSucceed, caCertPool)
				},
				tlsVersionEntries(awsEndpoints, modernTests),
			)
		})
	})
})

// tlsVersionEntries generates DescribeTable entries for all combinations of
// endpoints and TLS test cases.
func tlsVersionEntries(endpoints []tlsEndpoint, tests []tlsTestCase) []TableEntry {
	var entries []TableEntry
	for _, ep := range endpoints {
		for _, tc := range tests {
			action := "reject"
			if tc.shouldSucceed {
				action = "accept"
			}
			desc := fmt.Sprintf("should %s %s on %s", action, tc.versionName, ep.name)
			entries = append(entries, Entry(desc, ep, tc.version, tc.shouldSucceed, NodeTimeout(framework.WaitShort)))
		}
	}
	return entries
}

// waitForPodRestart waits for the target pod to be Ready with a lastTransitionTime no earlier than
// configChangedAt, ensuring the pod has restarted since the TLS config change.
func waitForPodRestart(ctx context.Context, ep tlsEndpoint, configChangedAt metav1.Time) {
	GinkgoHelper()

	By(fmt.Sprintf("Waiting for %s pod to have restarted since the TLS config change", ep.name), func() {
		Eventually(func() ([][]corev1.PodCondition, error) {
			pods := &corev1.PodList{}
			err := cl.List(ctx, pods,
				client.InNamespace(ep.namespace),
				client.MatchingLabels(ep.labels),
			)
			return util.SliceMap(pods.Items, func(pod corev1.Pod) []corev1.PodCondition {
				// Trimmed for error reporting
				return pod.Status.Conditions
			}), err
		}).WithContext(ctx).
			WithTimeout(framework.WaitShort).WithPolling(5*time.Second).
			Should(
				ContainElement(
					test.HaveCondition(corev1.PodReady).
						WithStatus(corev1.ConditionTrue).
						WithLastTransitionTime(Satisfy(func(t metav1.Time) bool {
							return !t.Before(&configChangedAt)
						})),
				),
				fmt.Sprintf("pod should have restarted since the TLS config change. namespace: %s, labels: %v", ep.namespace, ep.labels),
			)
	})
}

// waitForCAPIRollout waits for the CAPI operator to roll out the latest revision.
// If a rollout is expected, passing the previous revision will wait until the current revision is different.
func waitForCAPIRollout(ctx context.Context, previousCAPIRevisionOpt ...operatorv1alpha1.RevisionName) operatorv1alpha1.RevisionName {
	GinkgoHelper()

	var msg string
	if len(previousCAPIRevisionOpt) > 0 {
		msg = fmt.Sprintf("Waiting for CAPI operator to roll out the latest revision, different from %s", previousCAPIRevisionOpt[0])
	} else {
		msg = "Waiting for CAPI operator to roll out the latest revision"
	}

	clusterAPI := &operatorv1alpha1.ClusterAPI{}

	By(msg, func() {
		Eventually(func(g Gomega) {
			g.Expect(cl.Get(ctx, client.ObjectKey{Name: "cluster"}, clusterAPI)).To(Succeed())

			g.Expect(clusterAPI.Status.ObservedRevisionGeneration).To(Equal(clusterAPI.Generation),
				"observedRevisionGeneration should match generation")
			g.Expect(clusterAPI.Status.CurrentRevision).To(Equal(clusterAPI.Status.DesiredRevision),
				"currentRevision should match desiredRevision")

			// If we were passed a previous revision, wait until the current revision is different.
			if len(previousCAPIRevisionOpt) > 0 {
				g.Expect(clusterAPI.Status.CurrentRevision).NotTo(Equal(previousCAPIRevisionOpt[0]))
			}
		}).WithContext(ctx).
			WithTimeout(framework.WaitMedium).WithPolling(5 * time.Second).
			Should(Succeed())
	})

	return clusterAPI.Status.CurrentRevision
}

// assertTLSVersion tests that a TLS connection to the given endpoint either
// succeeds or fails at the specified TLS version.
func assertTLSVersion(ctx context.Context, ep tlsEndpoint, tlsVersion uint16, shouldSucceed bool, caCertPool *x509.CertPool) {
	GinkgoHelper()

	var expectation types.GomegaMatcher
	var message string
	if shouldSucceed {
		expectation = Not(HaveOccurred())
		message = fmt.Sprintf("TLS connection should succeed on %s at version 0x%04x", ep.name, tlsVersion)
	} else {
		expectation = MatchError("remote error: tls: protocol version not supported")
		message = fmt.Sprintf("connection to %s at version 0x%04x should be rejected with a TLS protocol version error", ep.name, tlsVersion)
	}

	Eventually(func(g Gomega) error {
		podName := findRunningPodName(g, ctx, ep.namespace, ep.labels)

		localPort, err := portForwardToPod(ctx, restConfig, ep.namespace, podName, ep.port)
		g.Expect(err).NotTo(HaveOccurred(), "port-forward to %s/%s:%d should succeed", ep.namespace, podName, ep.port)

		addr := fmt.Sprintf("127.0.0.1:%d", localPort)
		return tryTLSConnect(ctx, addr, tlsVersion, caCertPool, ep.serverName)
	}).WithContext(ctx).
		WithTimeout(framework.WaitShort).WithPolling(5*time.Second).
		Should(expectation, message)
}

// tryTLSConnect attempts a TLS handshake to addr forcing the given TLS version.
// Both MinVersion and MaxVersion are set to tlsVersion to test exactly that version.
func tryTLSConnect(ctx context.Context, addr string, tlsVersion uint16, caCertPool *x509.CertPool, serverName string) error {
	tlsCfg := &tls.Config{
		MinVersion: tlsVersion,
		MaxVersion: tlsVersion,
	}

	// Some endpoints use self-signed certs, so skip verification.
	if serverName != "" {
		tlsCfg.RootCAs = caCertPool
		tlsCfg.ServerName = serverName
	} else {
		tlsCfg.InsecureSkipVerify = true //nolint:gosec
	}

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config:    tlsCfg,
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

// loadServiceCACert loads the service-ca CA certificate from the
// kube-public/openshift-service-ca.crt ConfigMap.
func loadServiceCACert(ctx context.Context) *x509.CertPool {
	GinkgoHelper()

	cm := &corev1.ConfigMap{}
	Expect(cl.Get(ctx, client.ObjectKey{
		Namespace: "kube-public",
		Name:      "openshift-service-ca.crt",
	}, cm)).To(Succeed(), "should be able to read service-ca CA ConfigMap")

	caPEM, ok := cm.Data["service-ca.crt"]
	Expect(ok).To(BeTrue(), "service-ca.crt key should exist in ConfigMap")

	pool := x509.NewCertPool()
	Expect(pool.AppendCertsFromPEM([]byte(caPEM))).To(BeTrue(),
		"service-ca CA certificate should parse successfully")

	return pool
}

// setTLSConfig updates the APIServer CR with the given TLS adherence policy
// and security profile. It returns the server-side timestamp of the update
// from the managed fields entry, which can be used to verify that pods have
// restarted since the configuration change, and a bool indicating whether the
// change is expected to trigger a rollout. The rollout detection mirrors the
// SecurityProfileWatcher logic: a rollout is expected when either the resolved
// TLS profile spec changes or the adherence policy changes.
func setTLSConfig(ctx context.Context, adherence configv1.TLSAdherencePolicy, profile *configv1.TLSSecurityProfile) (metav1.Time, bool) {
	GinkgoHelper()

	apiServer := &configv1.APIServer{}
	Expect(cl.Get(ctx, client.ObjectKey{Name: "cluster"}, apiServer)).To(Succeed())

	// Resolve the current and new TLS profile specs to determine whether the
	// SecurityProfileWatcher will detect a change and trigger a restart.
	currentProfileSpec, err := utiltls.GetTLSProfileSpec(apiServer.Spec.TLSSecurityProfile)
	Expect(err).NotTo(HaveOccurred(), "should resolve current TLS profile spec")
	newProfileSpec, err := utiltls.GetTLSProfileSpec(profile)
	Expect(err).NotTo(HaveOccurred(), "should resolve new TLS profile spec")

	rolloutExpected := !reflect.DeepEqual(currentProfileSpec, newProfileSpec) ||
		apiServer.Spec.TLSAdherence != adherence

	apiServer.Spec.TLSAdherence = adherence
	apiServer.Spec.TLSSecurityProfile = profile

	Expect(cl.Update(ctx, apiServer, client.FieldOwner("tls-e2e-test"))).To(Succeed(),
		"should update APIServer TLS configuration")

	for _, mf := range apiServer.GetManagedFields() {
		if mf.Manager == "tls-e2e-test" && mf.Time != nil {
			return *mf.Time, rolloutExpected
		}
	}

	Fail("managed fields entry for tls-e2e-test not found after update")
	return metav1.Time{}, false
}

// findRunningPodName returns the name of a Running pod matching the given
// labels in the specified namespace. Fails the test if no such pod is found.
func findRunningPodName(g Gomega, ctx context.Context, namespace string, labels map[string]string) string {
	GinkgoHelper()

	pods := &corev1.PodList{}
	g.Expect(cl.List(ctx, pods,
		client.InNamespace(namespace),
		client.MatchingLabels(labels),
	)).To(Succeed())

	for i := range pods.Items {
		if pods.Items[i].Status.Phase == corev1.PodRunning {
			return pods.Items[i].Name
		}
	}

	Fail(fmt.Sprintf("no Running pod found with labels %v in namespace %s", labels, namespace))
	return ""
}

// portForwardToPod establishes a port-forward to the specified pod's container
// port. It returns the local port and a cancel function. Call the cancel
// function to tear down the port-forward. The port-forward is also
// automatically stopped when the context is cancelled.
func portForwardToPod(ctx context.Context, cfg *rest.Config, namespace, podName string, remotePort int) (int, error) {
	roundTripper, upgrader, err := spdy.RoundTripperFor(cfg)
	if err != nil {
		return 0, fmt.Errorf("creating SPDY round tripper: %w", err)
	}

	serverURL, err := url.Parse(cfg.Host)
	if err != nil {
		return 0, fmt.Errorf("parsing API server URL: %w", err)
	}
	serverURL.Path = fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/portforward", namespace, podName)

	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: roundTripper}, http.MethodPost, serverURL)

	stopCh := make(chan struct{})
	context.AfterFunc(ctx, func() { close(stopCh) })
	readyCh := make(chan struct{})

	pf, err := portforward.New(dialer, []string{fmt.Sprintf("0:%d", remotePort)}, stopCh, readyCh, io.Discard, io.Discard)
	if err != nil {
		return 0, fmt.Errorf("creating port forwarder: %w", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- pf.ForwardPorts()
	}()

	select {
	case <-readyCh:
	case err := <-errCh:
		return 0, fmt.Errorf("port forwarding failed: %w", err)
	case <-ctx.Done():
		return 0, ctx.Err()
	}

	ports, err := pf.GetPorts()
	if err != nil {
		return 0, fmt.Errorf("getting forwarded ports: %w", err)
	}

	return int(ports[0].Local), nil
}
