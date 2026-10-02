# Kubernetes example

Kong Gateway in DB-less mode, installed with the `kong/kong` Helm chart, with the Kong Ingress
Controller, the plugin loaded from a ConfigMap and databases on pod-local storage.

```sh
# 1. The plugin: its modules are in one directory, so one ConfigMap carries it.
kubectl create namespace kong
kubectl create configmap kong-plugin-ipgeolocation -n kong --from-file=kong/plugins/ipgeolocation

# 2. The updater image (curl, unzip, openssl and examples/updater/ipgeolocation-update.sh).
docker build -t registry.example.com/ipgeolocation-updater:0.1.0 examples/updater
docker push registry.example.com/ipgeolocation-updater:0.1.0

# 3. Download links (edit secret.yaml first: the links contain your API key).
kubectl apply -f examples/kubernetes/secret.yaml

# 4. Kong.
helm repo add kong https://charts.konghq.com
helm upgrade --install kong kong/kong -n kong -f examples/kubernetes/values.yaml

# 5. Plugin instances and an Ingress that uses one.
kubectl apply -f examples/kubernetes/kongplugin.yaml -f examples/kubernetes/ingress.yaml
```

Notes:

- **Storage.** Each pod keeps its own copy of the databases in an `emptyDir`. The init container blocks
  startup until the downloads succeed; remove it if Kong should start without databases and rely on the
  sidecar and the plugin's retry. Size the volume for your databases plus one archive and one extracted
  copy during an update.
- **Shared volumes.** Avoid replacing files on a network filesystem shared across nodes while Kong maps
  them; a file replaced from another node can become a stale handle. If you use a shared
  `ReadOnlyMany` volume, roll the Kong pods (`kubectl rollout restart`) after each update instead of using
  `database_refresh_interval`.
- **Client addresses.** Set `env.trusted_ips` to the range your load balancer connects from. With a
  layer-4 load balancer, `proxy.externalTrafficPolicy: Local` keeps client addresses visible; behind a
  layer-7 load balancer, Kong reads `X-Forwarded-For` from trusted peers.
- **Updating the plugin.** Recreate the ConfigMap and restart the Kong pods.
- **Enterprise.** Use a `kong/kong-gateway` image tag of your licensed version in `image`.
