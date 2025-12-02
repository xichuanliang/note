# Device Manager 
Device Mnager用于注册和调用外部device

## Device Plugin相关接口
k8s提供了一个device plugin框架。实现一个新的device plugin，就是要实现kubelet提供的接口

首先，kubelet提供了一个Registration的grpc服务，用于注册device plugin：
```go
service Registration {
	rpc Register(RegisterRequest) returns (Empty) {}
}
```
device plugin可以通过上述grpc服务在Kubelet中注册。在注册时会返回device plugin的相关信息：

1. device plugin的 UNIX 套接字
2. device plugin的 API 版本
3. ResourceName

成功注册后，device plugin就向kubelet发送它所管理的设备列表

device plugin使用节点中的/var/lib/kubelet/device-plugins/xxx.sock启动一个grpc服务，该服务需要实现Kubelet提供的以下接口：
```go
service DevicePlugin {
   // GetDevicePluginOptions 返回与设备管理器沟通的选项。
   rpc GetDevicePluginOptions(Empty) returns (DevicePluginOptions) {}

   // ListAndWatch 返回 Device 列表构成的数据流。
   // 当 Device 状态发生变化或者 Device 消失时，ListAndWatch
   // 会返回新的列表。
   rpc ListAndWatch(Empty) returns (stream ListAndWatchResponse) {}

   // Allocate 在容器创建期间调用，这样设备插件可以运行一些特定于设备的操作，
   // 并告诉 kubelet 如何令 Device 可在容器中访问的所需执行的具体步骤
   rpc Allocate(AllocateRequest) returns (AllocateResponse) {}

   // GetPreferredAllocation 从一组可用的设备中返回一些优选的设备用来分配，
   // 所返回的优选分配结果不一定会是设备管理器的最终分配方案。
   // 此接口的设计仅是为了让设备管理器能够在可能的情况下做出更有意义的决定。
   rpc GetPreferredAllocation(PreferredAllocationRequest) returns (PreferredAllocationResponse) {}

   // PreStartContainer 在设备插件注册阶段根据需要被调用，调用发生在容器启动之前。
   // 在将设备提供给容器使用之前，设备插件可以运行一些诸如重置设备之类的特定于
   // 具体设备的操作，
   rpc PreStartContainer(PreStartContainerRequest) returns (PreStartContainerResponse) {}
}
```
以上接口在DeviceManager中的接口在/k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1/api.pb.go
```go
type DevicePluginClient interface {
	// GetDevicePluginOptions returns options to be communicated with Device
	// Manager
	GetDevicePluginOptions(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*DevicePluginOptions, error)
	// ListAndWatch returns a stream of List of Devices
	// Whenever a Device state change or a Device disappears, ListAndWatch
	// returns the new list
	ListAndWatch(ctx context.Context, in *Empty, opts ...grpc.CallOption) (DevicePlugin_ListAndWatchClient, error)
	// GetPreferredAllocation returns a preferred set of devices to allocate
	// from a list of available ones. The resulting preferred allocation is not
	// guaranteed to be the allocation ultimately performed by the
	// devicemanager. It is only designed to help the devicemanager make a more
	// informed allocation decision when possible.
	GetPreferredAllocation(ctx context.Context, in *PreferredAllocationRequest, opts ...grpc.CallOption) (*PreferredAllocationResponse, error)
	// Allocate is called during container creation so that the Device
	// Plugin can run device specific operations and instruct Kubelet
	// of the steps to make the Device available in the container
	Allocate(ctx context.Context, in *AllocateRequest, opts ...grpc.CallOption) (*AllocateResponse, error)
	// PreStartContainer is called, if indicated by Device Plugin during registeration phase,
	// before each container start. Device plugin can run device specific operations
	// such as resetting the device before making devices available to the container
	PreStartContainer(ctx context.Context, in *PreStartContainerRequest, opts ...grpc.CallOption) (*PreStartContainerResponse, error)
}
```

## 创建Device Manager

在结构体中都是大结构体套小结构体。

ContainerManger->deviceManger->managerImpl->checkpointManager

cmd/kubelet/app/server.go
创建各种manager管理device、cpu等等
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
	// 开启pleg
	kl.pleg.Start()

	// Start eventedPLEG only if EventedPLEG feature gate is enabled.
	if utilfeature.DefaultFeatureGate.Enabled(features.EventedPLEG) {
		kl.eventedPleg.Start()
	}
	// 开启syncLoop主循环，监听pod的状态（创建、删除等等）
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
    ......
    // 创建client，运行pluginManger，同device plugin建立连接
	klog.V(4).InfoS("Starting plugin manager")
	go kl.pluginManager.Run(kl.sourcesReady, wait.NeverStop)

	err = kl.shutdownManager.Start()
	if err != nil {
		// The shutdown manager is not critical for kubelet, so log failure, but don't block Kubelet startup if there was a failure starting it.
		klog.ErrorS(err, "Failed to start node shutdown manager")
	}
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

// 创建Kubelet.sock，启动Device Manger服务，通过grpc与Device Plugin通信
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
    // 注册Device Plugin与Device Manger之间的grpc接口
	api.RegisterRegistrationServer(s.grpc, s)
	go func() {
		defer s.wg.Done()
		s.grpc.Serve(ln)
	}()

	return nil
}

// 开启pluginManger的reconcile
func (pm *pluginManager) Run(sourcesReady config.SourcesReady, stopCh <-chan struct{}) {
	defer runtime.HandleCrash()

	if err := pm.desiredStateOfWorldPopulator.Start(stopCh); err != nil {
		klog.ErrorS(err, "The desired_state_of_world populator (plugin watcher) starts failed!")
		return
	}

	klog.V(2).InfoS("The desired_state_of_world populator (plugin watcher) starts")
    // plugin Manger开启reconciler过程，调用Listwatch与device plugin建立连接
	klog.InfoS("Starting Kubelet Plugin Manager")
	go pm.reconciler.Run(stopCh)

	metrics.Register(pm.actualStateOfWorld, pm.desiredStateOfWorld)
	<-stopCh
	klog.InfoS("Shutting down Kubelet Plugin Manager")
}

// 每隔loopSleepDuration（1s）就调用一次reconcile()
func (rc *reconciler) Run(stopCh <-chan struct{}) {
	wait.Until(func() {
		rc.reconcile()
	},
		rc.loopSleepDuration,
		stopCh)
}

// 没秒调用一次reconcile，注册或者卸载device plugin 
func (rc *reconciler) reconcile() {
	// Unregisterations are triggered before registrations

	// Ensure plugins that should be unregistered are unregistered.
	for _, registeredPlugin := range rc.actualStateOfWorld.GetRegisteredPlugins() {
		unregisterPlugin := false
		if !rc.desiredStateOfWorld.PluginExists(registeredPlugin.SocketPath) {
			unregisterPlugin = true
		} else {
			// We also need to unregister the plugins that exist in both actual state of world
			// and desired state of world cache, but the timestamps don't match.
			// Iterate through desired state of world plugins and see if there's any plugin
			// with the same socket path but different timestamp.
			for _, dswPlugin := range rc.desiredStateOfWorld.GetPluginsToRegister() {
				if dswPlugin.SocketPath == registeredPlugin.SocketPath && dswPlugin.Timestamp != registeredPlugin.Timestamp {
					klog.V(5).InfoS("An updated version of plugin has been found, unregistering the plugin first before reregistering", "plugin", registeredPlugin)
					unregisterPlugin = true
					break
				}
			}
		}

		if unregisterPlugin {
			klog.V(5).InfoS("Starting operationExecutor.UnregisterPlugin", "plugin", registeredPlugin)
			err := rc.operationExecutor.UnregisterPlugin(registeredPlugin, rc.actualStateOfWorld)
			if err != nil &&
				!goroutinemap.IsAlreadyExists(err) &&
				!exponentialbackoff.IsExponentialBackoff(err) {
				// Ignore goroutinemap.IsAlreadyExists and exponentialbackoff.IsExponentialBackoff errors, they are expected.
				// Log all other errors.
				klog.ErrorS(err, "OperationExecutor.UnregisterPlugin failed", "plugin", registeredPlugin)
			}
			if err == nil {
				klog.V(1).InfoS("OperationExecutor.UnregisterPlugin started", "plugin", registeredPlugin)
			}
		}
	}

	// Ensure plugins that should be registered are registered
	for _, pluginToRegister := range rc.desiredStateOfWorld.GetPluginsToRegister() {
		if !rc.actualStateOfWorld.PluginExistsWithCorrectTimestamp(pluginToRegister) {
			klog.V(5).InfoS("Starting operationExecutor.RegisterPlugin", "plugin", pluginToRegister)
            // 使用已有的插件处理器（handler）去注册指定的插件。
			err := rc.operationExecutor.RegisterPlugin(pluginToRegister.SocketPath, pluginToRegister.Timestamp, rc.getHandlers(), rc.actualStateOfWorld)
			if err != nil &&
				!goroutinemap.IsAlreadyExists(err) &&
				!exponentialbackoff.IsExponentialBackoff(err) {
				// Ignore goroutinemap.IsAlreadyExists and exponentialbackoff.IsExponentialBackoff errors, they are expected.
				klog.ErrorS(err, "OperationExecutor.RegisterPlugin failed", "plugin", pluginToRegister)
			}
			if err == nil {
				klog.V(1).InfoS("OperationExecutor.RegisterPlugin started", "plugin", pluginToRegister)
			}
		}
	}
}

// 在GenerateRegisterPluginFunc中获取注册函数，调用注册函数注册device plugin
func (oe *operationExecutor) RegisterPlugin(
	socketPath string,
	timestamp time.Time,
	pluginHandlers map[string]cache.PluginHandler,
	actualStateOfWorld ActualStateOfWorldUpdater) error {
	generatedOperation :=
		oe.operationGenerator.GenerateRegisterPluginFunc(socketPath, timestamp, pluginHandlers, actualStateOfWorld)

	return oe.pendingOperations.Run(
		socketPath, generatedOperation)
}

// 返回设备注册的函数，注册的函数中包含一系列流程
// 调用listwatch接口获取device的stream
func (og *operationGenerator) GenerateRegisterPluginFunc(
	socketPath string,
	timestamp time.Time,
	pluginHandlers map[string]cache.PluginHandler,
	actualStateOfWorldUpdater ActualStateOfWorldUpdater) func() error {

	registerPluginFunc := func() error {
        // 与选定的device plugin 建立 gRPC 通信
		client, conn, err := dial(socketPath, dialTimeoutDuration)
		if err != nil {
			return fmt.Errorf("RegisterPlugin error -- dial failed at socket %s, err: %v", socketPath, err)
		}
		defer conn.Close()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

        // 获取指定device的信息
		infoResp, err := client.GetInfo(ctx, &registerapi.InfoRequest{})
		if err != nil {
			return fmt.Errorf("RegisterPlugin error -- failed to get plugin info using RPC GetInfo at socket %s, err: %v", socketPath, err)
		}

        // 使用指定device plugin的Handler进行device处理
		handler, ok := pluginHandlers[infoResp.Type]
		if !ok {
			if err := og.notifyPlugin(client, false, fmt.Sprintf("RegisterPlugin error -- no handler registered for plugin type: %s at socket %s", infoResp.Type, socketPath)); err != nil {
				return fmt.Errorf("RegisterPlugin error -- failed to send error at socket %s, err: %v", socketPath, err)
			}
			return fmt.Errorf("RegisterPlugin error -- no handler registered for plugin type: %s at socket %s", infoResp.Type, socketPath)
		}

		if infoResp.Endpoint == "" {
			infoResp.Endpoint = socketPath
		}
		if err := handler.ValidatePlugin(infoResp.Name, infoResp.Endpoint, infoResp.SupportedVersions); err != nil {
			if err = og.notifyPlugin(client, false, fmt.Sprintf("RegisterPlugin error -- plugin validation failed with err: %v", err)); err != nil {
				return fmt.Errorf("RegisterPlugin error -- failed to send error at socket %s, err: %v", socketPath, err)
			}
			return fmt.Errorf("RegisterPlugin error -- pluginHandler.ValidatePluginFunc failed")
		}
		// We add the plugin to the actual state of world cache before calling a plugin consumer's Register handle
		// so that if we receive a delete event during Register Plugin, we can process it as a DeRegister call.
		err = actualStateOfWorldUpdater.AddPlugin(cache.PluginInfo{
			SocketPath: socketPath,
			Timestamp:  timestamp,
			Handler:    handler,
			Name:       infoResp.Name,
		})
		if err != nil {
			klog.ErrorS(err, "RegisterPlugin error -- failed to add plugin", "path", socketPath)
		}
        // 调用plugin的注册函数进行register
		if err := handler.RegisterPlugin(infoResp.Name, infoResp.Endpoint, infoResp.SupportedVersions); err != nil {
			return og.notifyPlugin(client, false, fmt.Sprintf("RegisterPlugin error -- plugin registration failed with err: %v", err))
		}

		// Notify is called after register to guarantee that even if notify throws an error Register will always be called after validate
        // 
		if err := og.notifyPlugin(client, true, ""); err != nil {
			return fmt.Errorf("RegisterPlugin error -- failed to send registration status at socket %s, err: %v", socketPath, err)
		}
		return nil
	}
	return registerPluginFunc
}

// 注册device plugin
func (s *server) RegisterPlugin(pluginName string, endpoint string, versions []string) error {
	klog.V(2).InfoS("Registering plugin at endpoint", "plugin", pluginName, "endpoint", endpoint)
	return s.connectClient(pluginName, endpoint)
}

// 与device plugin.socket建立连接
func (s *server) connectClient(name string, socketPath string) error {
	c := NewPluginClient(name, socketPath, s.chandler)

	s.registerClient(name, c)
    // Connect 用于在设备管理器（device manager）和设备插件（device plugin）之间建立 gRPC 连接
	if err := c.Connect(); err != nil {
		s.deregisterClient(name)
		klog.ErrorS(err, "Failed to connect to new client", "resource", name)
		return err
	}

	go func() {
        // 每一秒都会reconcile一次，会出现goroutine泄露吗？
		s.runClient(name, c)
	}()

	return nil
}

// Connect 用于在设备管理器（device manager）和设备插件（device plugin）之间建立 gRPC 连接
func (c *client) Connect() error {
	client, conn, err := dial(c.socket)
	if err != nil {
		klog.ErrorS(err, "Unable to connect to device plugin client with socket path", "path", c.socket)
		return err
	}
	c.grpc = conn
	c.client = client
	return c.handler.PluginConnected(c.resource, c)
}

// PluginConnected测试连接状态和endpoint
func (m *ManagerImpl) PluginConnected(resourceName string, p plugin.DevicePlugin) error {
	options, err := p.API().GetDevicePluginOptions(context.Background(), &pluginapi.Empty{})
	if err != nil {
		return fmt.Errorf("failed to get device plugin options: %v", err)
	}
    // endpoint为各种Device Plugin的接口，通过endpoint调用device plugin的grpc接口进行交互
	e := newEndpointImpl(p)

	m.mutex.Lock()
	defer m.mutex.Unlock()
    // 将endpoint加入到map中
	m.endpoints[resourceName] = endpointInfo{e, options}

	klog.V(2).InfoS("Device plugin connected", "resourceName", resourceName)
	return nil
}

func (s *server) runClient(name string, c Client) {
	c.Run()

	c = s.getClient(name)
	if c == nil {
		return
	}

	if err := s.disconnectClient(name, c); err != nil {
		klog.V(2).InfoS("Unable to disconnect client", "resource", name, "client", c, "err", err)
	}
}

// Run is for running the device plugin gRPC client.
func (c *client) Run() {
    // 持续监听 plugin 发送的设备列表和状态变化。
	stream, err := c.client.ListAndWatch(context.Background(), &api.Empty{})
	if err != nil {
		klog.ErrorS(err, "ListAndWatch ended unexpectedly for device plugin", "resource", c.resource)
		return
	}

	for {
        // 以stream的方式收到包
		response, err := stream.Recv()
		if err != nil {
			klog.ErrorS(err, "ListAndWatch ended unexpectedly for device plugin", "resource", c.resource)
			return
		}
		klog.V(2).InfoS("State pushed for device plugin", "resource", c.resource, "resourceCapacity", len(response.Devices))
        // 将设备状态更新推送到 handler，更新 device的实际设备状态
		c.handler.PluginListAndWatchReceiver(c.resource, response)
	}
}

// 接收到所有device
func (m *ManagerImpl) PluginListAndWatchReceiver(resourceName string, resp *pluginapi.ListAndWatchResponse) {
	var devices []pluginapi.Device
	for _, d := range resp.Devices {
		devices = append(devices, *d)
	}
	m.genericDeviceUpdateCallback(resourceName, devices)
}

// 将devices注册到ManagerImpl中。device都是在内存中，同时写进checkpoint中
func (m *ManagerImpl) genericDeviceUpdateCallback(resourceName string, devices []pluginapi.Device) {
	healthyCount := 0
	m.mutex.Lock()
	m.healthyDevices[resourceName] = sets.NewString()
	m.unhealthyDevices[resourceName] = sets.NewString()
	m.allDevices[resourceName] = make(map[string]pluginapi.Device)
    // 遍历所有device
	for _, dev := range devices {
		m.allDevices[resourceName][dev.ID] = dev
        // 将device分为health device以及unhealthy Device
		if dev.Health == pluginapi.Healthy {
			m.healthyDevices[resourceName].Insert(dev.ID)
			healthyCount++
		} else {
			m.unhealthyDevices[resourceName].Insert(dev.ID)
		}
	}
	m.mutex.Unlock()
    // 将device信息写入/var/lib/kubelet/device-plugins/kubelet_internal_checkpoint
	if err := m.writeCheckpoint(); err != nil {
		klog.ErrorS(err, "Writing checkpoint encountered")
	}
	klog.V(2).InfoS("Processed device updates for resource", "resourceName", resourceName, "totalCount", len(devices), "healthyCount", healthyCount)
}

```


## ManagerImpl
pkg/kubelet/cm/devicemanager/manager.goManagerImpl 用于实现Device Manager
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

