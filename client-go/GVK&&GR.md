## GVK与GVR

### GVK和GVR是什么？
- GVK：group、version、kind
- GVR：group、version、resource

### 为什么有 kind 和 resouce 两个相似概念？
- 在编码过程中，资源数据的存储都是以结构体存储(称为 Go type)
  -   由于多版本version的存在（alpha1，beta1，v1等），不同版本中存储结构体的存在着差异，但是我们都会给其相同的 Kind 名字（比如 Deployment）。因此，我们编码中只用 Kind 名（如 Deployment），并不能准确获取到其使用哪个版本结构体。所以，采用 GVK 获取到一个具体的 存储结构体，也就是 GVK 的三个信息（group/verion/kind) 确定一个 Go type（结构体）
- 如何获取？
  - 通过Scheme，Scheme存储了GVK和Go type的映射关系

- 在创建资源过程中，我们编写yaml，提交请求
  - 编写yaml过程中，我们会写apiversion和kind，就是GVK。客户端与apiserver通信时http形式，就是将请求发送到某一http path中
  - 发送到那个http path呢？
    - http path就是GVR
      - /apis/batch/v1/namespaces/default/job 这个就是表示 default 命名空间的 job 资源
      - kubectl get po 时 也是请求的路径 也可以称之为 GVR
    - 其实 GVR 是由 GVK 转化而来 —— 通过REST映射的RESTMappers实现

### 总结
- 同 Kind 由于多版本会存在 多个数据结构（Go type）
- GVK 可以确定一个具体的 Go Type（映射关系由 Scheme 维护）
- GVK 可以转换 http path 请求路径（也就是 GVR）（映射由RESTMappers实现）
- GVK和GVR是相关的。GVK在GVR标识的HTTP路径下提供服务。将GVK映射到GVR的过程称为REST映射。我们将在“ REST Mapping”中看到在Golang中实现REST映射的RESTMappers。
- GVK = 对象类型
- GVR = API资源路径
- RESTMapper = 类型 → 资源
- Scheme = 类型 ↔ Go Struct