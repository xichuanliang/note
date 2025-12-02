# pod的创建过程

## 开启kubelet的syncLoop

```go
// Run starts the kubelet reacting to config updates
func (kl *Kubelet) Run(updates <-chan kubetypes.PodUpdate) {
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

```



