# kubelet

kubelet有很多xxxManager，用于处理不同事情

podManager：保存的是 kubelet 期望（应当）运行的 Pod 集合，包括已接纳（admitted）的普通 Pod 和 mirror Pod。

podWorkers：真正正在运行的 Pod 集合 则存储在 podWorkers 中。



```go
// Kubelet is the main kubelet implementation.
type Kubelet struct {
	kubeletConfiguration kubeletconfiginternal.KubeletConfiguration

	// hostname is the hostname the kubelet detected or was given via flag/config
	hostname string
	// hostnameOverridden indicates the hostname was overridden via flag/config
	hostnameOverridden bool

	nodeName        types.NodeName
	runtimeCache    kubecontainer.RuntimeCache
	kubeClient      clientset.Interface
	heartbeatClient clientset.Interface
	// mirrorPodClient is used to create and delete mirror pods in the API for static
	// pods.
	mirrorPodClient kubepod.MirrorClient

	rootDirectory string

	lastObservedNodeAddressesMux sync.RWMutex
	lastObservedNodeAddresses    []v1.NodeAddress

	// onRepeatedHeartbeatFailure is called when a heartbeat operation fails more than once. optional.
	onRepeatedHeartbeatFailure func()

	// podManager stores the desired set of admitted pods and mirror pods that the kubelet should be
	// running. The actual set of running pods is stored on the podWorkers. The manager is populated
	// by the kubelet config loops which abstracts receiving configuration from many different sources
	// (api for regular pods, local filesystem or http for static pods). The manager may be consulted
	// by other components that need to see the set of desired pods. Note that not all desired pods are
	// running, and not all running pods are in the podManager - for instance, force deleting a pod
	// from the apiserver will remove it from the podManager, but the pod may still be terminating and
	// tracked by the podWorkers. Components that need to know the actual consumed resources of the
	// node or are driven by podWorkers and the sync*Pod methods (status, volume, stats) should also
	// consult the podWorkers when reconciling.
	//
	// TODO: review all kubelet components that need the actual set of pods (vs the desired set)
	// and update them to use podWorkers instead of podManager. This may introduce latency in some
	// methods, but avoids race conditions and correctly accounts for terminating pods that have
	// been force deleted or static pods that have been updated.
	// https://github.com/kubernetes/kubernetes/issues/116970
	podManager kubepod.Manager

	// podWorkers is responsible for driving the lifecycle state machine of each pod. The worker is
	// notified of config changes, updates, periodic reconciliation, container runtime updates, and
	// evictions of all desired pods and will invoke reconciliation methods per pod in separate
	// goroutines. The podWorkers are authoritative in the kubelet for what pods are actually being
	// run and their current state:
	//
	// * syncing: pod should be running (syncPod)
	// * terminating: pod should be stopped (syncTerminatingPod)
	// * terminated: pod should have all resources cleaned up (syncTerminatedPod)
	//
	// and invoke the handler methods that correspond to each state. Components within the
	// kubelet that need to know the phase of the pod in order to correctly set up or tear down
	// resources must consult the podWorkers.
	//
	// Once a pod has been accepted by the pod workers, no other pod with that same UID (and
	// name+namespace, for static pods) will be started until the first pod has fully terminated
	// and been cleaned up by SyncKnownPods. This means a pod may be desired (in API), admitted
	// (in pod manager), and requested (by invoking UpdatePod) but not start for an arbitrarily
	// long interval because a prior pod is still terminating.
	//
	// As an event-driven (by UpdatePod) controller, the podWorkers must periodically be resynced
	// by the kubelet invoking SyncKnownPods with the desired state (admitted pods in podManager).
	// Since the podManager may be unaware of some running pods due to force deletion, the
	// podWorkers are responsible for triggering a sync of pods that are no longer desired but
	// must still run to completion.
	podWorkers PodWorkers

	// evictionManager observes the state of the node for situations that could impact node stability
	// and evicts pods (sets to phase Failed with reason Evicted) to reduce resource pressure. The
	// eviction manager acts on the actual state of the node and considers the podWorker to be
	// authoritative.
	evictionManager eviction.Manager

	// probeManager tracks the set of running pods and ensures any user-defined periodic checks are
	// run to introspect the state of each pod.  The probe manager acts on the actual state of the node
	// and is notified of pods by the podWorker. The probe manager is the authoritative source of the
	// most recent probe status and is responsible for notifying the status manager, which
	// synthesizes them into the overall pod status.
	probeManager prober.Manager

	// secretManager caches the set of secrets used by running pods on this node. The podWorkers
	// notify the secretManager when pods are started and terminated, and the secretManager must
	// then keep the needed secrets up-to-date as they change.
	secretManager secret.Manager

	// configMapManager caches the set of config maps used by running pods on this node. The
	// podWorkers notify the configMapManager when pods are started and terminated, and the
	// configMapManager must then keep the needed config maps up-to-date as they change.
	configMapManager configmap.Manager

	// volumeManager observes the set of running pods and is responsible for attaching, mounting,
	// unmounting, and detaching as those pods move through their lifecycle. It periodically
	// synchronizes the set of known volumes to the set of actually desired volumes and cleans up
	// any orphaned volumes. The volume manager considers the podWorker to be authoritative for
	// which pods are running.
	volumeManager volumemanager.VolumeManager

	// statusManager receives updated pod status updates from the podWorker and updates the API
	// status of those pods to match. The statusManager is authoritative for the synthesized
	// status of the pod from the kubelet's perspective (other components own the individual
	// elements of status) and should be consulted by components in preference to assembling
	// that status themselves. Note that the status manager is downstream of the pod worker
	// and components that need to check whether a pod is still running should instead directly
	// consult the pod worker.
	statusManager status.Manager

	// resyncInterval is the interval between periodic full reconciliations of
	// pods on this node.
	resyncInterval time.Duration

	// sourcesReady records the sources seen by the kubelet, it is thread-safe.
	sourcesReady config.SourcesReady

	// Optional, defaults to /logs/ from /var/log
	logServer http.Handler
	// Optional, defaults to simple Docker implementation
	runner kubecontainer.CommandRunner

	// cAdvisor used for container information.
	cadvisor cadvisor.Interface

	// Set to true to have the node register itself with the apiserver.
	registerNode bool
	// List of taints to add to a node object when the kubelet registers itself.
	registerWithTaints []v1.Taint
	// Set to true to have the node register itself as schedulable.
	registerSchedulable bool
	// for internal book keeping; access only from within registerWithApiserver
	registrationCompleted bool

	// dnsConfigurer is used for setting up DNS resolver configuration when launching pods.
	dnsConfigurer *dns.Configurer

	// serviceLister knows how to list services
	serviceLister serviceLister
	// serviceHasSynced indicates whether services have been sync'd at least once.
	// Check this before trusting a response from the lister.
	serviceHasSynced cache.InformerSynced
	// nodeLister knows how to list nodes
	nodeLister corelisters.NodeLister
	// nodeHasSynced indicates whether nodes have been sync'd at least once.
	// Check this before trusting a response from the node lister.
	nodeHasSynced cache.InformerSynced
	// a list of node labels to register
	nodeLabels map[string]string

	// Last timestamp when runtime responded on ping.
	// Mutex is used to protect this value.
	runtimeState *runtimeState

	// Volume plugins.
	volumePluginMgr *volume.VolumePluginMgr

	// Manages container health check results.
	livenessManager  proberesults.Manager
	readinessManager proberesults.Manager
	startupManager   proberesults.Manager

	// How long to keep idle streaming command execution/port forwarding
	// connections open before terminating them
	streamingConnectionIdleTimeout time.Duration

	// The EventRecorder to use
	recorder record.EventRecorder

	// Policy for handling garbage collection of dead containers.
	containerGC kubecontainer.GC

	// Manager for image garbage collection.
	imageManager images.ImageGCManager

	// Manager for container logs.
	containerLogManager logs.ContainerLogManager

	// Cached MachineInfo returned by cadvisor.
	machineInfoLock sync.RWMutex
	machineInfo     *cadvisorapi.MachineInfo

	// Handles certificate rotations.
	serverCertificateManager certificate.Manager

	// Cloud provider interface.
	cloud cloudprovider.Interface
	// Handles requests to cloud provider with timeout
	cloudResourceSyncManager cloudresource.SyncManager

	// Indicates that the node initialization happens in an external cloud controller
	externalCloudProvider bool
	// Reference to this node.
	nodeRef *v1.ObjectReference

	// Container runtime.
	containerRuntime kubecontainer.Runtime

	// Streaming runtime handles container streaming.
	streamingRuntime kubecontainer.StreamingRuntime

	// Container runtime service (needed by container runtime Start()).
	runtimeService internalapi.RuntimeService

	// reasonCache caches the failure reason of the last creation of all containers, which is
	// used for generating ContainerStatus.
	reasonCache *ReasonCache

	// containerRuntimeReadyExpected indicates whether container runtime being ready is expected
	// so errors are logged without verbosity guard, to avoid excessive error logs at node startup.
	// It's false during the node initialization period of nodeReadyGracePeriod, and after that
	// it's set to true by fastStatusUpdateOnce when it exits.
	containerRuntimeReadyExpected bool

	// nodeStatusUpdateFrequency specifies how often kubelet computes node status. If node lease
	// feature is not enabled, it is also the frequency that kubelet posts node status to master.
	// In that case, be cautious when changing the constant, it must work with nodeMonitorGracePeriod
	// in nodecontroller. There are several constraints:
	// 1. nodeMonitorGracePeriod must be N times more than nodeStatusUpdateFrequency, where
	//    N means number of retries allowed for kubelet to post node status. It is pointless
	//    to make nodeMonitorGracePeriod be less than nodeStatusUpdateFrequency, since there
	//    will only be fresh values from Kubelet at an interval of nodeStatusUpdateFrequency.
	//    The constant must be less than podEvictionTimeout.
	// 2. nodeStatusUpdateFrequency needs to be large enough for kubelet to generate node
	//    status. Kubelet may fail to update node status reliably if the value is too small,
	//    as it takes time to gather all necessary node information.
	nodeStatusUpdateFrequency time.Duration

	// nodeStatusReportFrequency is the frequency that kubelet posts node
	// status to master. It is only used when node lease feature is enabled.
	nodeStatusReportFrequency time.Duration

	// lastStatusReportTime is the time when node status was last reported.
	lastStatusReportTime time.Time

	// syncNodeStatusMux is a lock on updating the node status, because this path is not thread-safe.
	// This lock is used by Kubelet.syncNodeStatus and Kubelet.fastNodeStatusUpdate functions and shouldn't be used anywhere else.
	syncNodeStatusMux sync.Mutex

	// updatePodCIDRMux is a lock on updating pod CIDR, because this path is not thread-safe.
	// This lock is used by Kubelet.updatePodCIDR function and shouldn't be used anywhere else.
	updatePodCIDRMux sync.Mutex

	// updateRuntimeMux is a lock on updating runtime, because this path is not thread-safe.
	// This lock is used by Kubelet.updateRuntimeUp and Kubelet.fastNodeStatusUpdate functions and shouldn't be used anywhere else.
	updateRuntimeMux sync.Mutex

	// nodeLeaseController claims and renews the node lease for this Kubelet
	nodeLeaseController lease.Controller

	// pleg observes the state of the container runtime and notifies the kubelet of changes to containers, which
	// notifies the podWorkers to reconcile the state of the pod (for instance, if a container dies and needs to
	// be restarted).
	pleg pleg.PodLifecycleEventGenerator

	// eventedPleg supplements the pleg to deliver edge-driven container changes with low-latency.
	eventedPleg pleg.PodLifecycleEventGenerator

	// Store kubecontainer.PodStatus for all pods.
	podCache kubecontainer.Cache

	// os is a facade for various syscalls that need to be mocked during testing.
	os kubecontainer.OSInterface

	// Watcher of out of memory events.
	oomWatcher oomwatcher.Watcher

	// Monitor resource usage
	resourceAnalyzer serverstats.ResourceAnalyzer

	// Whether or not we should have the QOS cgroup hierarchy for resource management
	cgroupsPerQOS bool

	// If non-empty, pass this to the container runtime as the root cgroup.
	cgroupRoot string

	// Mounter to use for volumes.
	mounter mount.Interface

	// hostutil to interact with filesystems
	hostutil hostutil.HostUtils

	// subpather to execute subpath actions
	subpather subpath.Interface

	// Manager of non-Runtime containers.
	containerManager cm.ContainerManager

	// Maximum Number of Pods which can be run by this Kubelet
	maxPods int

	// Monitor Kubelet's sync loop
	syncLoopMonitor atomic.Value

	// Container restart Backoff
	backOff *flowcontrol.Backoff

	// Information about the ports which are opened by daemons on Node running this Kubelet server.
	daemonEndpoints *v1.NodeDaemonEndpoints

	// A queue used to trigger pod workers.
	workQueue queue.WorkQueue

	// oneTimeInitializer is used to initialize modules that are dependent on the runtime to be up.
	oneTimeInitializer sync.Once

	// If set, use this IP address or addresses for the node
	nodeIPs []net.IP

	// use this function to validate the kubelet nodeIP
	nodeIPValidator func(net.IP) error

	// If non-nil, this is a unique identifier for the node in an external database, eg. cloudprovider
	providerID string

	// clock is an interface that provides time related functionality in a way that makes it
	// easy to test the code.
	clock clock.WithTicker

	// handlers called during the tryUpdateNodeStatus cycle
	setNodeStatusFuncs []func(context.Context, *v1.Node) error

	lastNodeUnschedulableLock sync.Mutex
	// maintains Node.Spec.Unschedulable value from previous run of tryUpdateNodeStatus()
	lastNodeUnschedulable bool

	// the list of handlers to call during pod admission.
	admitHandlers lifecycle.PodAdmitHandlers

	// softAdmithandlers are applied to the pod after it is admitted by the Kubelet, but before it is
	// run. A pod rejected by a softAdmitHandler will be left in a Pending state indefinitely. If a
	// rejected pod should not be recreated, or the scheduler is not aware of the rejection rule, the
	// admission rule should be applied by a softAdmitHandler.
	softAdmitHandlers lifecycle.PodAdmitHandlers

	// the list of handlers to call during pod sync loop.
	lifecycle.PodSyncLoopHandlers

	// the list of handlers to call during pod sync.
	lifecycle.PodSyncHandlers

	// the number of allowed pods per core
	podsPerCore int

	// enableControllerAttachDetach indicates the Attach/Detach controller
	// should manage attachment/detachment of volumes scheduled to this node,
	// and disable kubelet from executing any attach/detach operations
	enableControllerAttachDetach bool

	// trigger deleting containers in a pod
	containerDeletor *podContainerDeletor

	// config iptables util rules
	makeIPTablesUtilChains bool

	// The AppArmor validator for checking whether AppArmor is supported.
	appArmorValidator apparmor.Validator

	// StatsProvider provides the node and the container stats.
	StatsProvider *stats.Provider

	// This flag, if set, instructs the kubelet to keep volumes from terminated pods mounted to the node.
	// This can be useful for debugging volume related issues.
	keepTerminatedPodVolumes bool // DEPRECATED

	// pluginmanager runs a set of asynchronous loops that figure out which
	// plugins need to be registered/unregistered based on this node and makes it so.
	pluginManager pluginmanager.PluginManager

	// This flag sets a maximum number of images to report in the node status.
	nodeStatusMaxImages int32

	// Handles RuntimeClass objects for the Kubelet.
	runtimeClassManager *runtimeclass.Manager

	// Handles node shutdown events for the Node.
	shutdownManager nodeshutdown.Manager

	// Manage user namespaces
	usernsManager *userns.UsernsManager

	// Mutex to serialize new pod admission and existing pod resizing
	podResizeMutex sync.Mutex

	// OpenTelemetry Tracer
	tracer trace.Tracer
}


```