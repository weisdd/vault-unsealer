# vault-unsealer

## Description

Helps to automatically init (optional) and unseal a Vault cluster in environments where keeping unseal keys in Kubernetes secrets is not a security concern (e.g. in dev).

## Limitations

* Suitable only for HA-installations with `service_registration "kubernetes" {}`;
* Might not be reliable enough for production use.

## Variables

| Parameter |  Description | Default |
|--|--|--|
| `KUBERNETES_SERVICE_HOST` | Kubernetes endpoint | `127.0.0.1` |
| `KUBERNETES_SERVICE_PORT_HTTPS` | HTTPS port for Kubernetes endpoint | `16443` |
| `VERIFY_SSL` | Whether to verify TLS connection against CA | `True` |
| `SSL_CA_CERT` | Path to a CA certificate | `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt` |
| `TOKEN` | Kubernetes Token | `None` (The actual value is read from `/var/run/secrets/kubernetes.io/serviceaccount/token`) |
| `NAMESPACE` | Kubernetes Namespace | `None` (The actual value is read from `/var/run/secrets/kubernetes.io/serviceaccount/namespace`)|
| `KEY1`..`KEYX` | Vault keys | `None` (Not used if VAULT_KEYS_PATH is defined) |
| `VAULT_KEYS_PATH` | Path to a folder with Vault keys (KEY1..KEYX). Useful if keys are mounted from a Secret or a ConfigMap | `None` |
| `VAULT_INIT` | Whether to automatically init Vault cluster | `False` |
| `SECRETS_PREFIX` | Prefix for the secrets where a root token and keys will be stored | `vault` |
| `REPLACE_SECRETS` | Whether to replace secrets (vault-root-token and vault-keys) after the init process is completed (requires `VAULT_INIT=True`) | `False` |
| `LOGGING_LEVEL` | Logging level. Be careful, some sensitive data like root token or vault keys might be exposed in console if set to DEBUG. | `INFO` |

## How to run

### microk8s

```bash
export VAULT_UNSEALER_VERSION=0.3.3
docker build . -t localhost:32000/vault-unsealer:${VAULT_UNSEALER_VERSION}
docker push localhost:32000/vault-unsealer:${VAULT_UNSEALER_VERSION}
k apply -f manifests
k run vault-unsealer --image localhost:32000/vault-unsealer:${VAULT_UNSEALER_VERSION} --serviceaccount=vault-unseal --image-pull-policy=Always --env="KEY1=8zRaxizK9UkIoUC7GJWNNMmlgz5urDOfI4wokSTkdfGL" --env="KEY2=pCXYEaqYutJWxAso3+5V5Mxl8JH4lOyBpAhuppDgLUCp" --env="KEY3=UnOf2Ulhc6qdvYJOo6XabzC9dO80zZcBTQqOhBu40mSn" --env="VAULT_INIT=True" --env="REPLACE_SECRETS=True"
```

### Local environment

1. Import environment variables (adjust appropriately) directly or through an .env file:

    ```bash
    export KUBERNETES_SERVICE_HOST=255.255.255.254
    export KUBERNETES_SERVICE_PORT_HTTPS=16443
    export TOKEN=eyJhbGciOiJSUzI1NiIsImtpZCI6ImdqLTBIS3UyR2ZYUFNlYlppV3VRbUlBS1lleTlXZkVjVnk5bjBfWTlvZmsifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJ2YXVsdCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJ2YXVsdC11bnNlYWwtdG9rZW4tOWc1czQiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoidmF1bHQtdW5zZWFsIiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQudWlkIjoiZjdlY2VhM2ItYTFlMS00NzgxLWJiYTUtNTU3ZGExMjRmNGU2Iiwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OnZhdWx0OnZhdWx0LXVuc2VhbCJ9.jxNDw4WnqDE-yNJIrg5GaG1RY1HDk2THgKZ7LICrQgNtLKffv5awHZFnr_naBwAxeVzeOSXQBXdsMxibxOEpkJ8ezWNq2cg0jt0fSAuyQGAxMoB9qyPx8b7e4oLmiyQ3XXoKhFoEUw44vdPI8piaIZHJzxVRRHuSRxGRQROuAKtn1POM0bmbjwUaoXrmAgN3aXUJ17dpWU3-sPjTkan-DZ8oRwI5nZXu7Rlf0gkfQINYYPFZYTBGmLo6O4rUMM18pQUNn0cQBbQaupPbCyDBtveAzfw1j5YGwK23hAYFrnqiOIcSR9J-uxOfppBC-5Nh12tWixCwjBEd0brEl0RiSg
    export NAMESPACE=vault
    export KEY1=8zRaxizK9UkIoUC7GJWNNMmlgz5urDOfI4wokSTkdfGL
    export KEY2=pCXYEaqYutJWxAso3+5V5Mxl8JH4lOyBpAhuppDgLUCp
    export KEY3=UnOf2Ulhc6qdvYJOo6XabzC9dO80zZcBTQqOhBu40mSn
    export VERIFY_SSL=False
    export VAULT_INIT=True
    export LOGGING_LEVEL=DEBUG
    export REPLACE_SECRETS=True
    export VAULT_KEYS_PATH=''
    ```

2. Install python requirements in a virtual or global environment:

    ```bash
    pip3 install -r requirements.txt
    ```

3. Run the app:

    ```bash
    chmod +x main.py
    ./main.py
    ```
