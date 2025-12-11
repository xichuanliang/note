# pod的创建过程

## 开启kubelet的syncLoop

```go
// Run starts the kubelet reacting to config updates
// pkg/kubelet/kubelet.go
func (kl *Kubelet) Run(updates <-chan kubetypes.PodUpdate) {
	......
	ctx := context.Background()
	if kl.kubeClient == nil {
		klog.InfoS("No API server defined - no node status update will be sent")
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
    // 开启kubelet的reconcile，开启监听pod的创建等等
	kl.syncLoop(ctx, updates, kl)
}

// syncLoop is the main loop for processing changes. It watches for changes from
// three channels (file, apiserver, and http) and creates a union of them. For
// any new change seen, will run a sync against desired state and running state. If
// no changes are seen to the configuration, will synchronize the last known desired
// state every sync-frequency seconds. Never returns.
func (kl *Kubelet) syncLoop(ctx context.Context, updates <-chan kubetypes.PodUpdate, handler SyncHandler) {
	klog.InfoS("Starting kubelet main sync loop")
	// The syncTicker wakes up kubelet to checks if there are any pod workers
	// that need to be sync'd. A one-second period is sufficient because the
	// sync interval is defaulted to 10s.
	syncTicker := time.NewTicker(time.Second)
	defer syncTicker.Stop()
	housekeepingTicker := time.NewTicker(housekeepingPeriod)
	defer housekeepingTicker.Stop()
	plegCh := kl.pleg.Watch()
	const (
		base   = 100 * time.Millisecond
		max    = 5 * time.Second
		factor = 2
	)
	duration := base
	// Responsible for checking limits in resolv.conf
	// The limits do not have anything to do with individual pods
	// Since this is called in syncLoop, we don't need to call it anywhere else
	if kl.dnsConfigurer != nil && kl.dnsConfigurer.ResolverConfig != "" {
		kl.dnsConfigurer.CheckLimitsForResolvConf()
	}

	for {
		// 判断容器运行时（containerd、docker）是否能够正常工作
		if err := kl.runtimeState.runtimeErrors(); err != nil {
			klog.ErrorS(err, "Skipping pod synchronization")
			// exponential backoff
			time.Sleep(duration)
			duration = time.Duration(math.Min(float64(max), factor*float64(duration)))
			continue
		}
		// reset backoff if we have a success
		duration = base

		kl.syncLoopMonitor.Store(kl.clock.Now())
		if !kl.syncLoopIteration(ctx, updates, handler, syncTicker.C, housekeepingTicker.C, plegCh) {
			break
		}
		kl.syncLoopMonitor.Store(kl.clock.Now())
	}
}


// 从多个通道读取事件，并将 pod 分发给指定的处理器
// configCh：将配置变更事件中的 pod 分发给处理器对应的回调函数
// handler：用于分发 pod 的 SyncHandler
// syncCh：同步所有待同步的 pod
// housekeepingCh：触发 pod 清理
// plegCh：更新容器运行时缓存；同步该 pod
func (kl *Kubelet) syncLoopIteration(ctx context.Context, configCh <-chan kubetypes.PodUpdate, handler SyncHandler,
	syncCh <-chan time.Time, housekeepingCh <-chan time.Time, plegCh <-chan *pleg.PodLifecycleEvent) bool {
	select {
	case u, open := <-configCh:
		// watch3个config的改动（file,http,apiServer）
		// 一旦Pod经过上面3个config发生变化，configCh就会收到相应的事件
		if !open {
			klog.ErrorS(nil, "Update channel is closed, exiting the sync loop")
			return false
		}

		switch u.Op {
		case kubetypes.ADD:
			klog.V(2).InfoS("SyncLoop ADD", "source", u.Source, "pods", klog.KObjSlice(u.Pods))
			// 处理Add event的函数
			// 重启kubelet之后，kubelet会收到所有现有 Pod 的 ADD 事件
			// 事实上，Pod并不会重启，但是会经过admission流程
			handler.HandlePodAdditions(u.Pods)
		case kubetypes.UPDATE:
			klog.V(2).InfoS("SyncLoop UPDATE", "source", u.Source, "pods", klog.KObjSlice(u.Pods))
			handler.HandlePodUpdates(u.Pods)
		case kubetypes.REMOVE:
			klog.V(2).InfoS("SyncLoop REMOVE", "source", u.Source, "pods", klog.KObjSlice(u.Pods))
			handler.HandlePodRemoves(u.Pods)
		case kubetypes.RECONCILE:
			klog.V(4).InfoS("SyncLoop RECONCILE", "source", u.Source, "pods", klog.KObjSlice(u.Pods))
			handler.HandlePodReconcile(u.Pods)
		case kubetypes.DELETE:
			klog.V(2).InfoS("SyncLoop DELETE", "source", u.Source, "pods", klog.KObjSlice(u.Pods))
			// DELETE is treated as a UPDATE because of graceful deletion.
			handler.HandlePodUpdates(u.Pods)
		case kubetypes.SET:
			// TODO: Do we want to support this?
			klog.ErrorS(nil, "Kubelet does not support snapshot update")
		default:
			klog.ErrorS(nil, "Invalid operation type received", "operation", u.Op)
		}

		kl.sourcesReady.AddSource(u.Source)
	......
	return true
}


// HandlePodAdditions is the callback in SyncHandler for pods being added from
// a config source.
func (kl *Kubelet) HandlePodAdditions(pods []*v1.Pod) {
	start := kl.clock.Now()
	// 以pod的创建时间排序，确保Pod以时间顺序处理
	sort.Sort(sliceutils.PodsByCreationTime(pods))
	if utilfeature.DefaultFeatureGate.Enabled(features.InPlacePodVerticalScaling) {
		kl.podResizeMutex.Lock()
		defer kl.podResizeMutex.Unlock()
	}
	for _, pod := range pods {
		// podManager中保存的是期望存在的pod信息
		existingPods := kl.podManager.GetPods()
		kl.podManager.AddPod(pod)
		// 依据pod中的Annotations，查看是否是mirror pod
		// mirror pod是指保存在/etc/kubernetes/manifests/的静态pod
		pod, mirrorPod, wasMirror := kl.podManager.GetPodAndMirrorPod(pod)
		if wasMirror {
			if pod == nil {
				klog.V(2).InfoS("Unable to find pod for mirror pod, skipping", "mirrorPod", klog.KObj(mirrorPod), "mirrorPodUID", mirrorPod.UID)
				continue
			}
			kl.podWorkers.UpdatePod(UpdatePodOptions{
				Pod:        pod,
				MirrorPod:  mirrorPod,
				UpdateType: kubetypes.SyncPodUpdate,
				StartTime:  start,
			})
			continue
		}

		// 仅在 Pod 没有被 kubelet 的其他部分请求终止时，才进行准入处理
		if !kl.podWorkers.IsPodTerminationRequested(pod.UID) {
			// activePods 列表中只包含那些已经通过准入流程并且当前仍在运行的 Pod，
			// 而被拒绝的 Pod 已经被标记为失败，不会计入其中
			activePods := kl.filterOutInactivePods(existingPods)
			// 判断是否开启InPlacePodVerticalScaling功能
			// 这个功能是pod在不重启的情况下，修改request的值
			if utilfeature.DefaultFeatureGate.Enabled(features.InPlacePodVerticalScaling) {
				// To handle kubelet restarts, test pod admissibility using AllocatedResources values
				// (for cpu & memory) from checkpoint store. If found, that is the source of truth.
				podCopy := pod.DeepCopy()
				for _, c := range podCopy.Spec.Containers {
					allocatedResources, found := kl.statusManager.GetContainerResourceAllocation(string(pod.UID), c.Name)
					if c.Resources.Requests != nil && found {
						c.Resources.Requests[v1.ResourceCPU] = allocatedResources[v1.ResourceCPU]
						c.Resources.Requests[v1.ResourceMemory] = allocatedResources[v1.ResourceMemory]
					}
				}
				// Check if we can admit the pod; if not, reject it.
				if ok, reason, message := kl.canAdmitPod(activePods, podCopy); !ok {
					kl.rejectPod(pod, reason, message)
					continue
				}
				// For new pod, checkpoint the resource values at which the Pod has been admitted
				if err := kl.statusManager.SetPodAllocation(podCopy); err != nil {
					//TODO(vinaykul,InPlacePodVerticalScaling): Can we recover from this in some way? Investigate
					klog.ErrorS(err, "SetPodAllocation failed", "pod", klog.KObj(pod))
				}
			} else {
				// 检查是否pod是否能够准入
				if ok, reason, message := kl.canAdmitPod(activePods, pod); !ok {
					kl.rejectPod(pod, reason, message)
					continue
				}
			}
		}
		// 创建pod
		kl.podWorkers.UpdatePod(UpdatePodOptions{
			Pod:        pod,
			MirrorPod:  mirrorPod,
			UpdateType: kubetypes.SyncPodCreate,
			StartTime:  start,
		})
	}
}

func (p *podWorkers) UpdatePod(options UpdatePodOptions) {

	var isRuntimePod bool
	var uid types.UID
	var name, ns string
	// pod第一次创建的时候，不会是runningPod
	if runningPod := options.RunningPod; runningPod != nil {
		if options.Pod == nil {
			// the sythetic pod created here is used only as a placeholder and not tracked
			if options.UpdateType != kubetypes.SyncPodKill {
				klog.InfoS("Pod update is ignored, runtime pods can only be killed", "pod", klog.KRef(runningPod.Namespace, runningPod.Name), "podUID", runningPod.ID, "updateType", options.UpdateType)
				return
			}
			uid, ns, name = runningPod.ID, runningPod.Namespace, runningPod.Name
			isRuntimePod = true
		} else {
			options.RunningPod = nil
			uid, ns, name = options.Pod.UID, options.Pod.Namespace, options.Pod.Name
			klog.InfoS("Pod update included RunningPod which is only valid when Pod is not specified", "pod", klog.KRef(ns, name), "podUID", uid, "updateType", options.UpdateType)
		}
	} else {
		// 此处获取pod.UID等等
		uid, ns, name = options.Pod.UID, options.Pod.Namespace, options.Pod.Name
	}

	p.podLock.Lock()
	defer p.podLock.Unlock()

	// decide what to do with this pod - we are either setting it up, tearing it down, or ignoring it
	var firstTime bool
	now := p.clock.Now()
	// 首次创建podSyncStatuses[uid]中的值是空的
	status, ok := p.podSyncStatuses[uid]
	if !ok {
		klog.V(4).InfoS("Pod is being synced for the first time", "pod", klog.KRef(ns, name), "podUID", uid, "updateType", options.UpdateType)
		firstTime = true
		status = &podSyncStatus{
			syncedAt: now,
			fullname: kubecontainer.BuildPodFullName(name, ns),
		}
		// if this pod is being synced for the first time, we need to make sure it is an active pod
		if options.Pod != nil && (options.Pod.Status.Phase == v1.PodFailed || options.Pod.Status.Phase == v1.PodSucceeded) {
			......
		}
		// 直接在这里设置
		p.podSyncStatuses[uid] = status
	}

	pod := options.Pod
	......
	// 起一个goroutine进行pod创建
	podUpdates, exists := p.podUpdates[uid]
	if !exists {
		// buffer the channel to avoid blocking this method
		podUpdates = make(chan struct{}, 1)
		p.podUpdates[uid] = podUpdates

		// ensure that static pods start in the order they are received by UpdatePod
		if kubetypes.IsStaticPod(pod) {
			p.waitingToStartStaticPodsByFullname[status.fullname] =
				append(p.waitingToStartStaticPodsByFullname[status.fullname], uid)
		}

		// allow testing of delays in the pod update channel
		// workerChannelFn 在这里的作用是允许对 Pod worker 的更新通道进行自定义处理或包装
		// 如果 workerChannelFn 为 nil，则直接使用 podUpdates 通道作为 Pod worker 接收通知的通道。
		var outCh <-chan struct{}
		if p.workerChannelFn != nil {
			outCh = p.workerChannelFn(uid, podUpdates)
		} else {
			outCh = podUpdates
		}

		// 启动一个pod Worker
		go func() {
			// TODO: this should be a wait.Until with backoff to handle panics, and
			// accept a context for shutdown
			defer runtime.HandleCrash()
			defer klog.V(3).InfoS("Pod worker has stopped", "podUID", uid)
			p.podWorkerLoop(uid, outCh)
		}()
	}

	// measure the maximum latency between a call to UpdatePod and when the pod worker reacts to it
	// by preserving the oldest StartTime
	if status.pendingUpdate != nil && !status.pendingUpdate.StartTime.IsZero() && status.pendingUpdate.StartTime.Before(options.StartTime) {
		options.StartTime = status.pendingUpdate.StartTime
	}

	// notify the pod worker there is a pending update
	status.pendingUpdate = &options
	status.working = true
	klog.V(4).InfoS("Notifying pod of pending update", "pod", klog.KRef(ns, name), "podUID", uid, "workType", status.WorkType())
	select {
	case podUpdates <- struct{}{}:
	default:
	}

	if (becameTerminating || wasGracePeriodShortened) && status.cancelFn != nil {
		klog.V(3).InfoS("Cancelling current pod sync", "pod", klog.KRef(ns, name), "podUID", uid, "workType", status.WorkType())
		status.cancelFn()
		return
	}
}


// podWorkerLoop manages sequential state updates to a pod in a goroutine, exiting once the final
// state is reached. The loop is responsible for driving the pod through four main phases:
//
// 1. Wait to start, guaranteeing no two pods with the same UID or same fullname are running at the same time
// 2. Sync, orchestrating pod setup by reconciling the desired pod spec with the runtime state of the pod
// 3. Terminating, ensuring all running containers in the pod are stopped
// 4. Terminated, cleaning up any resources that must be released before the pod can be deleted
//
// The podWorkerLoop is driven by updates delivered to UpdatePod and by SyncKnownPods. If a particular
// sync method fails, p.workerQueue is updated with backoff but it is the responsibility of the kubelet
// to trigger new UpdatePod calls. SyncKnownPods will only retry pods that are no longer known to the
// caller. When a pod transitions working->terminating or terminating->terminated, the next update is
// queued immediately and no kubelet action is required.
// 顺序处理 Pod 生命周期的每个阶段，从启动、同步到终止和清理，确保 Pod 状态更新可靠且互不冲突
func (p *podWorkers) podWorkerLoop(podUID types.UID, podUpdates <-chan struct{}) {
	var lastSyncTime time.Time
	for range podUpdates {
		ctx, update, canStart, canEverStart, ok := p.startPodSync(podUID)
		// If we had no update waiting, it means someone initialized the channel without filling out pendingUpdate.
		if !ok {
			continue
		}
		// If the pod was terminated prior to the pod being allowed to start, we exit the loop.
		if !canEverStart {
			return
		}
		// If the pod is not yet ready to start, continue and wait for more updates.
		if !canStart {
			continue
		}

		podUID, podRef := podUIDAndRefForUpdate(update.Options)

		klog.V(4).InfoS("Processing pod event", "pod", podRef, "podUID", podUID, "updateType", update.WorkType)
		var isTerminal bool
		err := func() error {
			// The worker is responsible for ensuring the sync method sees the appropriate
			// status updates on resyncs (the result of the last sync), transitions to
			// terminating (no wait), or on terminated (whatever the most recent state is).
			// Only syncing and terminating can generate pod status changes, while terminated
			// pods ensure the most recent status makes it to the api server.
			var status *kubecontainer.PodStatus
			var err error
			switch {
			case update.Options.RunningPod != nil:
				// when we receive a running pod, we don't need status at all because we are
				// guaranteed to be terminating and we skip updates to the pod
			default:
				// wait until we see the next refresh from the PLEG via the cache (max 2s)
				// TODO: this adds ~1s of latency on all transitions from sync to terminating
				//  to terminated, and on all termination retries (including evictions). We should
				//  improve latency by making the pleg continuous and by allowing pod status
				//  changes to be refreshed when key events happen (killPod, sync->terminating).
				//  Improving this latency also reduces the possibility that a terminated
				//  container's status is garbage collected before we have a chance to update the
				//  API server (thus losing the exit code).
				status, err = p.podCache.GetNewerThan(update.Options.Pod.UID, lastSyncTime)

				if err != nil {
					// This is the legacy event thrown by manage pod loop all other events are now dispatched
					// from syncPodFn
					p.recorder.Eventf(update.Options.Pod, v1.EventTypeWarning, events.FailedSync, "error determining status: %v", err)
					return err
				}
			}

			// Take the appropriate action (illegal phases are prevented by UpdatePod)
			switch {
			case update.WorkType == TerminatedPod:
				err = p.podSyncer.SyncTerminatedPod(ctx, update.Options.Pod, status)

			case update.WorkType == TerminatingPod:
				var gracePeriod *int64
				if opt := update.Options.KillPodOptions; opt != nil {
					gracePeriod = opt.PodTerminationGracePeriodSecondsOverride
				}
				podStatusFn := p.acknowledgeTerminating(podUID)

				// if we only have a running pod, terminate it directly
				if update.Options.RunningPod != nil {
					err = p.podSyncer.SyncTerminatingRuntimePod(ctx, update.Options.RunningPod)
				} else {
					err = p.podSyncer.SyncTerminatingPod(ctx, update.Options.Pod, status, gracePeriod, podStatusFn)
				}

			default:
				isTerminal, err = p.podSyncer.SyncPod(ctx, update.Options.UpdateType, update.Options.Pod, update.Options.MirrorPod, status)
			}

			lastSyncTime = p.clock.Now()
			return err
		}()

		var phaseTransition bool
		switch {
		case err == context.Canceled:
			// when the context is cancelled we expect an update to already be queued
			klog.V(2).InfoS("Sync exited with context cancellation error", "pod", podRef, "podUID", podUID, "updateType", update.WorkType)

		case err != nil:
			// we will queue a retry
			klog.ErrorS(err, "Error syncing pod, skipping", "pod", podRef, "podUID", podUID)

		case update.WorkType == TerminatedPod:
			// we can shut down the worker
			p.completeTerminated(podUID)
			if start := update.Options.StartTime; !start.IsZero() {
				metrics.PodWorkerDuration.WithLabelValues("terminated").Observe(metrics.SinceInSeconds(start))
			}
			klog.V(4).InfoS("Processing pod event done", "pod", podRef, "podUID", podUID, "updateType", update.WorkType)
			return

		case update.WorkType == TerminatingPod:
			// pods that don't exist in config don't need to be terminated, other loops will clean them up
			if update.Options.RunningPod != nil {
				p.completeTerminatingRuntimePod(podUID)
				if start := update.Options.StartTime; !start.IsZero() {
					metrics.PodWorkerDuration.WithLabelValues(update.Options.UpdateType.String()).Observe(metrics.SinceInSeconds(start))
				}
				klog.V(4).InfoS("Processing pod event done", "pod", podRef, "podUID", podUID, "updateType", update.WorkType)
				return
			}
			// otherwise we move to the terminating phase
			p.completeTerminating(podUID)
			phaseTransition = true

		case isTerminal:
			// if syncPod indicated we are now terminal, set the appropriate pod status to move to terminating
			klog.V(4).InfoS("Pod is terminal", "pod", podRef, "podUID", podUID, "updateType", update.WorkType)
			p.completeSync(podUID)
			phaseTransition = true
		}

		// queue a retry if necessary, then put the next event in the channel if any
		p.completeWork(podUID, phaseTransition, err)
		if start := update.Options.StartTime; !start.IsZero() {
			metrics.PodWorkerDuration.WithLabelValues(update.Options.UpdateType.String()).Observe(metrics.SinceInSeconds(start))
		}
		klog.V(4).InfoS("Processing pod event done", "pod", podRef, "podUID", podUID, "updateType", update.WorkType)
	}
}


```



