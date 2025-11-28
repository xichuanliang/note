# Device Manager 
Device Mnager用于注册和调用外部device

## 创建Device Manager

cmd/kubelet/app/server.go
创建各种管理外部Device的manager
```go
func run(ctx context.Context, s *options.KubeletServer, kubeDeps *kubelet.Dependencies, featureGate featuregate.FeatureGate) (err error) {

    ......
    //  创建一个NewContainerManager，为container添加request的资源
		kubeDeps.ContainerManager, err = cm.NewContainerManager(
			kubeDeps.Mounter,
			kubeDeps.CAdvisorInterface,
			cm.NodeConfig{
				RuntimeCgroupsName:    s.RuntimeCgroups,
				SystemCgroupsName:     s.SystemCgroups,
				KubeletCgroupsName:    s.KubeletCgroups,
				KubeletOOMScoreAdj:    s.OOMScoreAdj,
				CgroupsPerQOS:         s.CgroupsPerQOS,
				CgroupRoot:            s.CgroupRoot,
				CgroupDriver:          s.CgroupDriver,
				KubeletRootDir:        s.RootDirectory,
				ProtectKernelDefaults: s.ProtectKernelDefaults,
				NodeAllocatableConfig: cm.NodeAllocatableConfig{
					KubeReservedCgroupName:   s.KubeReservedCgroup,
					SystemReservedCgroupName: s.SystemReservedCgroup,
					EnforceNodeAllocatable:   sets.NewString(s.EnforceNodeAllocatable...),
					KubeReserved:             kubeReserved,
					SystemReserved:           systemReserved,
					ReservedSystemCPUs:       reservedSystemCPUs,
					HardEvictionThresholds:   hardEvictionThresholds,
				},
				QOSReserved:                             *experimentalQOSReserved,
				CPUManagerPolicy:                        s.CPUManagerPolicy,
				CPUManagerPolicyOptions:                 cpuManagerPolicyOptions,
				CPUManagerReconcilePeriod:               s.CPUManagerReconcilePeriod.Duration,
				ExperimentalMemoryManagerPolicy:         s.MemoryManagerPolicy,
				ExperimentalMemoryManagerReservedMemory: s.ReservedMemory,
				PodPidsLimit:                            s.PodPidsLimit,
				EnforceCPULimits:                        s.CPUCFSQuota,
				CPUCFSQuotaPeriod:                       s.CPUCFSQuotaPeriod.Duration,
				TopologyManagerPolicy:                   s.TopologyManagerPolicy,
				TopologyManagerScope:                    s.TopologyManagerScope,
				TopologyManagerPolicyOptions:            topologyManagerPolicyOptions,
			},
			s.FailSwapOn,
			kubeDeps.Recorder,
			kubeDeps.KubeClient,
		)

		if err != nil {
			return err
		}
	}

	if kubeDeps.PodStartupLatencyTracker == nil {
		kubeDeps.PodStartupLatencyTracker = kubeletutil.NewPodStartupLatencyTracker()
	}

	// TODO(vmarmol): Do this through container config.
	oomAdjuster := kubeDeps.OOMAdjuster
	if err := oomAdjuster.ApplyOOMScoreAdj(0, int(s.OOMScoreAdj)); err != nil {
		klog.InfoS("Failed to ApplyOOMScoreAdj", "err", err)
	}
    // 在初始化各种模块的实例之后，启动各种模块，包括Device Manager
    // kubelet运行各种模块从这里开始
	if err := RunKubelet(s, kubeDeps, s.RunOnce); err != nil {
		return err
	}
    ......

	// If systemd is used, notify it that we have started
	go daemon.SdNotify(false, "READY=1")

	select {
	case <-done:
		break
	case <-ctx.Done():
		break
	}

	return nil
}

// 创建一个容器管理的Mangaer
func NewContainerManager(mountUtil mount.Interface, cadvisorInterface cadvisor.Interface, nodeConfig NodeConfig, failSwapOn bool, recorder record.EventRecorder, kubeClient clientset.Interface) (ContainerManager, error) {
    
    ......
	cm := &containerManagerImpl{
		cadvisorInterface:   cadvisorInterface,
		mountUtil:           mountUtil,
		NodeConfig:          nodeConfig,
		subsystems:          subsystems,
		cgroupManager:       cgroupManager,
		capacity:            capacity,
		internalCapacity:    internalCapacity,
		cgroupRoot:          cgroupRoot,
		recorder:            recorder,
		qosContainerManager: qosContainerManager,
	}
    ......

	klog.InfoS("Creating device plugin manager")
    // 创建ManagerImpl，用于记录每个容器中记录的device
	cm.deviceManager, err = devicemanager.NewManagerImpl(machineInfo.Topology, cm.topologyManager)
	if err != nil {
		return nil, err
	}
    ......
	return cm, nil
}

// NewManagerImpl 创建一个manager管理Device.
func NewManagerImpl(topology []cadvisorapi.Node, topologyAffinityStore topologymanager.Store) (*ManagerImpl, error) {
    // socketPath: /var/lib/kubelet/device-plugins/kubelet.sock
    socketPath := pluginapi.KubeletSocket
	if runtime.GOOS == "windows" {
		socketPath = os.Getenv("SYSTEMDRIVE") + pluginapi.KubeletSocketWindows
	}
	return newManagerImpl(socketPath, topology, topologyAffinityStore)
}

// newManagerImpl 创建一个管理Device Plugin的结构体
func newManagerImpl(socketPath string, topology []cadvisorapi.Node, topologyAffinityStore topologymanager.Store) (*ManagerImpl, error) {
	klog.V(2).InfoS("Creating Device Plugin manager", "path", socketPath)

	var numaNodes []int
	for _, node := range topology {
		numaNodes = append(numaNodes, node.Id)
	}
    // 创建ManagerImpl
	manager := &ManagerImpl{
		endpoints: make(map[string]endpointInfo),

		allDevices:            NewResourceDeviceInstances(),
		healthyDevices:        make(map[string]sets.String),
		unhealthyDevices:      make(map[string]sets.String),
		allocatedDevices:      make(map[string]sets.String),
		podDevices:            newPodDevices(),
		numaNodes:             numaNodes,
		topologyAffinityStore: topologyAffinityStore,
		devicesToReuse:        make(PodReusableDevices),
	}
    // 创建一个与device plugin通信的server
	server, err := plugin.NewServer(socketPath, manager, manager)
	if err != nil {
		return nil, fmt.Errorf("failed to create plugin server: %v", err)
	}

	manager.server = server
    // checkpointdir /var/lib/kubelet/device-plugins/
	manager.checkpointdir, _ = filepath.Split(server.SocketPath())

	// The following structures are populated with real implementations in manager.Start()
	// Before that, initializes them to perform no-op operations.
	manager.activePods = func() []*v1.Pod { return []*v1.Pod{} }
	manager.sourcesReady = &sourcesReadyStub{}
    // 创建一个checkpoint 的manager
	checkpointManager, err := checkpointmanager.NewCheckpointManager(manager.checkpointdir)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize checkpoint manager: %v", err)
	}
	manager.checkpointManager = checkpointManager

	return manager, nil
}
```

## 启动Device Manager
cmd/kubelet/app/server.go

```go
// RunKubelet 启动kubelet的所有功能模块
func RunKubelet(kubeServer *options.KubeletServer, kubeDeps *kubelet.Dependencies, runOnce bool) error {
	hostname, err := nodeutil.GetHostname(kubeServer.HostnameOverride)
	if err != nil {
		return err
	}
	// Query the cloud provider for our node name, default to hostname if kubeDeps.Cloud == nil
	nodeName, err := getNodeName(kubeDeps.Cloud, hostname)
	if err != nil {
		return err
	}
    ......

	// process pods and exit.
    // 运行kubelet
	if runOnce {
		if _, err := k.RunOnce(podCfg.Updates()); err != nil {
			return fmt.Errorf("runonce failed: %w", err)
		}
		klog.InfoS("Started kubelet as runonce")
	} else {
		startKubelet(k, podCfg, &kubeServer.KubeletConfiguration, kubeDeps, kubeServer.EnableServer)
		klog.InfoS("Started kubelet")
	}
	return nil
}

// startKubelet 
func startKubelet(k kubelet.Bootstrap, podCfg *config.PodConfig, kubeCfg *kubeletconfiginternal.KubeletConfiguration, kubeDeps *kubelet.Dependencies, enableServer bool) {
	// start the kubelet
	go k.Run(podCfg.Updates())

	// start the kubelet server
	if enableServer {
		go k.ListenAndServe(kubeCfg, kubeDeps.TLSOptions, kubeDeps.Auth, kubeDeps.TracerProvider)
	}
	if kubeCfg.ReadOnlyPort > 0 {
		go k.ListenAndServeReadOnly(netutils.ParseIPSloppy(kubeCfg.Address), uint(kubeCfg.ReadOnlyPort))
	}
	go k.ListenAndServePodResources()
}


// Run starts the kubelet reacting to config updates
func (kl *Kubelet) Run(updates <-chan kubetypes.PodUpdate) {
	ctx := context.Background()
    ......
	if kl.kubeClient == nil {
		klog.InfoS("No API server defined - no node status update will be sent")
	}

	// Start the cloud provider sync manager
	if kl.cloudResourceSyncManager != nil {
		go kl.cloudResourceSyncManager.Run(wait.NeverStop)
	}

	// Start volume manager
	go kl.volumeManager.Run(kl.sourcesReady, wait.NeverStop)
    ......
    // 调用updateRuntimeUp
    // 初始化所有依赖运行时的模块
	go wait.Until(kl.updateRuntimeUp, 5*time.Second, wait.NeverStop)

	// Set up iptables util rules
	if kl.makeIPTablesUtilChains {
		kl.initNetworkUtil()
	}

	// Start component sync loops.
	kl.statusManager.Start()

	// Start syncing RuntimeClasses if enabled.
	if kl.runtimeClassManager != nil {
		kl.runtimeClassManager.Start(wait.NeverStop)
	}

	// Start the pod lifecycle event generator.
	kl.pleg.Start()

	// Start eventedPLEG only if EventedPLEG feature gate is enabled.
	if utilfeature.DefaultFeatureGate.Enabled(features.EventedPLEG) {
		kl.eventedPleg.Start()
	}

	kl.syncLoop(ctx, updates, kl)
}

func (kl *Kubelet) updateRuntimeUp() {
    ......
	networkReady := s.GetRuntimeCondition(kubecontainer.NetworkReady)
	if networkReady == nil || !networkReady.Status {
		klogErrorS(nil, "Container runtime network not ready", "networkReady", networkReady)
		kl.runtimeState.setNetworkState(fmt.Errorf("container runtime network not ready: %v", networkReady))
	} else {
		// Set nil if the container runtime network is ready.
		kl.runtimeState.setNetworkState(nil)
	}
	// information in RuntimeReady condition will be propagated to NodeReady condition.
	runtimeReady := s.GetRuntimeCondition(kubecontainer.RuntimeReady)
	// If RuntimeReady is not set or is false, report an error.
	if runtimeReady == nil || !runtimeReady.Status {
		klogErrorS(nil, "Container runtime not ready", "runtimeReady", runtimeReady)
		kl.runtimeState.setRuntimeState(fmt.Errorf("container runtime not ready: %v", runtimeReady))
		return
	}
	kl.runtimeState.setRuntimeState(nil)
	kl.oneTimeInitializer.Do(kl.initializeRuntimeDependentModules)
	kl.runtimeState.setRuntimeSync(kl.clock.Now())
}

// initializeRuntimeDependentModules will initialize internal modules that require the container runtime to be up.
func (kl *Kubelet) initializeRuntimeDependentModules() {
	// containerManager must start after cAdvisor because it needs filesystem capacity information
    ......
    // 开启服务containerManager
	if err := kl.containerManager.Start(node, kl.GetActivePods, kl.sourcesReady, 
}

func (cm *containerManagerImpl) Start(node *v1.Node,
	activePods ActivePodsFunc,
	sourcesReady config.SourcesReady,
	podStatusProvider status.PodStatusProvider,
	runtimeService internalapi.RuntimeService,
	localStorageCapacityIsolation bool) error {
	ctx := context.Background()

	// 真正开启Device Manager
	if err := cm.deviceManager.Start(devicemanager.ActivePodsFunc(activePods), sourcesReady, containerMap, containerRunningSet); err != nil {
		return err
	}

	return nil
}

// Start 启动设备插件（Device Plugin）管理器，并根据已保存的检查点状态
// 初始化 podDevices 和 allocatedDevices 信息，同时启动设备插件的注册服务。
func (m *ManagerImpl) Start(activePods ActivePodsFunc, sourcesReady config.SourcesReady, initialContainers containermap.ContainerMap, initialContainerRunningSet sets.String) error {
	klog.V(2).InfoS("Starting Device Plugin manager")

	m.activePods = activePods
	m.sourcesReady = sourcesReady
	m.containerMap = initialContainers
	m.containerRunningSet = initialContainerRunningSet

	// Loads in allocatedDevices information from disk.
	err := m.readCheckpoint()
	if err != nil {
		klog.InfoS("Continue after failing to read checkpoint file. Device allocation info may NOT be up-to-date", "err", err)
	}
    // 注册kubelet.sock并开启监听服务
    // 通过kubelet.sock与device plugin通信，实现Device的注册与发现
	return m.server.Start()
}

// 
func (s *server) Start() error {
	klog.V(2).InfoS("Starting device plugin registration server")

	if err := os.MkdirAll(s.socketDir, 0750); err != nil {
		klog.ErrorS(err, "Failed to create the device plugin socket directory", "directory", s.socketDir)
		return err
	}

	if selinux.GetEnabled() {
		if err := selinux.SetFileLabel(s.socketDir, config.KubeletPluginsDirSELinuxLabel); err != nil {
			klog.InfoS("Unprivileged containerized plugins might not work. Could not set selinux context on socket dir", "path", s.socketDir, "err", err)
		}
	}

	// For now we leave cleanup of the *entire* directory up to the Handler
	// (even though we should in theory be able to just wipe the whole directory)
	// because the Handler stores its checkpoint file (amongst others) in here.
	if err := s.rhandler.CleanupPluginDirectory(s.socketDir); err != nil {
		klog.ErrorS(err, "Failed to cleanup the device plugin directory", "directory", s.socketDir)
		return err
	}

    // 创建kubelet.sock同device plugin通信
	ln, err := net.Listen("unix", s.SocketPath())
	if err != nil {
		klog.ErrorS(err, "Failed to listen to socket while starting device plugin registry")
		return err
	}

	s.wg.Add(1)
	s.grpc = grpc.NewServer([]grpc.ServerOption{}...)

	api.RegisterRegistrationServer(s.grpc, s)
	go func() {
		defer s.wg.Done()
		s.grpc.Serve(ln)
	}()

	return nil
}

```


## ManagerImpl
ManagerImpl用于实现Device Manager
```go
type ManagerImpl struct {
    // 默认 /var/lib/kubelet/device-plugins
	checkpointdir string 

    // Key是资源名称（sriov_net_A、GPU）endpointInfo是DevicePlugin的接口
    // allocate()、getPreferredAllocation()、preStartContainer()
	endpoints map[string]endpointInfo
	mutex     sync.Mutex

    // Register服务暴露的gRPC Server
	server plugin.Server

	// activePods 是一个用于列出节点上正在运行的 Pod 的方法，
    // 以便在更新已分配设备时，能够统计现有 Pod 请求的 pluginResources 数量。
	activePods ActivePodsFunc

	// 用于提供 kubelet 配置源（例如 apiserver 更新）是否已就绪的信息。
    // 我们使用该信息来判断何时可以从 checkpoint 状态中清理不再活跃的 Pod。
	sourcesReady config.SourcesReady

	// allDevices 保存当前所有已向设备管理器注册的设备。
	allDevices ResourceDeviceInstances

	// healthyDevices 包含所有已注册且处于健康状态的资源名称及其对应导出的Device ID。
    // 对于sriov来说，Device ID是pci地址
	healthyDevices map[string]sets.String

	// unhealthyDevices 包含所有不健康的Device及其导出的Device ID。
	unhealthyDevices map[string]sets.String

	// allocatedDevices 包含已分配的Device ID，通过 resourceName 作为键进行索引。
	allocatedDevices map[string]sets.String

	// podDevices 保存 Pod 与其分配到的Device之间的映射关系。
	podDevices        *podDevices
    // CheckpointManager用于管理kubelet_internal_checkpoint
    // kubelet_internal_checkpoint中存储的是当前节点device的分配信息
	checkpointManager checkpointmanager.CheckpointManager

	// numaNodes 是底层机器中可用 NUMA 节点的列表。
	numaNodes []int

	// topologyAffinityStore 存储设备拓扑亲和性信息，供设备管理器查询。
	topologyAffinityStore topologymanager.Store

	// devicesToReuse 包含可复用的设备，即已分配给 init 容器、可再次使用的设备。
	devicesToReuse PodReusableDevices

	// pendingAdmissionPod 包含正在进行准入（admission）过程中的 Pod 信息。
	pendingAdmissionPod *v1.Pod

	// containerMap 提供 Pod 中所有容器的 (pod, container) → containerID 映射，用于检测节点重启后仍在运行的 Pod。
	containerMap containermap.ContainerMap

	// containerRunningSet identifies which container among those present in `containerMap`
	// was reported running by the container runtime when `containerMap` was computed.
	// Used to detect pods running across a restart
	containerRunningSet sets.String
}
```

