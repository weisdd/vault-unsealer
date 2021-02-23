#!/usr/bin/env python3
import base64
import glob
import logging
import os
import re
import signal
import decouple
import hvac
from typing import Dict
from kubernetes import client, watch
from kubernetes.client.rest import ApiException


class VaultUnsealer:
    def __init__(self):
        self.config = self._load_config()
        self.logger = self._configure_logging(self.config["logging"])

    # TODO: refactor
    def _load_config(self) -> Dict:
        """Loads all the configuration needed for the vault unsealer.

        Returns:
            Dict: Configuration for k8s, vault/hvac, and logging.
        """

        config = {"k8s": {}, "vault": {}, "logger": {}}

        ##
        # k8s config
        ##
        config["k8s"]["client"] = client.Configuration()
        config["k8s"]["client"].host = "https://{}:{}".format(
            decouple.config("KUBERNETES_SERVICE_HOST", "127.0.0.1"),
            decouple.config("KUBERNETES_SERVICE_PORT_HTTPS", "16443"),
        )
        config["k8s"]["client"].verify_ssl = decouple.config(
            "VERIFY_SSL", default=True, cast=bool
        )
        if config["k8s"]["client"].verify_ssl:
            config["k8s"]["client"].ssl_ca_cert = decouple.config(
                "SSL_CA_CERT", "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
            )
        token = self._get_env_or_file(
            "TOKEN", "/var/run/secrets/kubernetes.io/serviceaccount/token"
        )  # temp
        config["k8s"]["client"].api_key = {"authorization": f"Bearer {token}"}

        config["k8s"]["namespace"] = self._get_env_or_file(
            "NAMESPACE", "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
        )

        ##
        # vault config
        ##
        config["vault"]["init"] = decouple.config(
            "VAULT_INIT", default=False, cast=bool
        )
        config["k8s"]["replace_secrets"] = decouple.config(
            "REPLACE_SECRETS", default=False, cast=bool
        )
        # for init process
        secrets_prefix = decouple.config("SECRETS_PREFIX", default="vault")
        config["vault"]["root_token_secret"] = f"{secrets_prefix}-root-token"
        config["vault"]["keys_secret"] = f"{secrets_prefix}-keys"

        config["vault"]["keys"] = []
        config["vault"]["keys_path"] = decouple.config("VAULT_KEYS_PATH", default="")

        # Get Vault keys.
        # Note: The keys stored here will change should the unsealer initialize a new Vault cluster.

        # Useful if the keys are mounted to a folder from a secret or a configmap
        if config["vault"]["keys_path"]:
            for file in glob.glob(f"{config['vault']['keys_path']}/KEY*"):
                with open(file, "r", encoding="utf-8") as f:
                    config["vault"]["keys"].append(f.read().strip())

        # Get keys (KEYx) from environment variables
        else:
            for env in os.environ:
                if re.search(r"^KEY\d+$", env):
                    config["vault"]["keys"].append(decouple.config(env))

        ##
        # logging level
        ##
        config["logging"] = decouple.config("LOGGING_LEVEL", default="INFO")

        return config

    @staticmethod
    def _configure_logging(logging_level: str) -> logging.Logger:
        """Prepares a logging instance.

        Returns:
            logging.Logger: A logging instance.
        """
        logger = logging.getLogger(__name__)
        c_handler = logging.StreamHandler()
        c_format = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        c_handler.setFormatter(c_format)
        logger.addHandler(c_handler)

        # Set logging level
        logging_levels = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"}
        if logging_level not in logging_levels:
            logger.setLevel("INFO")
            logger.warning(
                f"{logging_level} is not a valid logging level, failing back to INFO"
            )
        else:
            logger.setLevel(logging_level)

        return logger

    @staticmethod
    def _get_env_or_file(env: str, path: str) -> str:
        """Helps to override things like a k8s token or a namespace.

        Args:
            env (str): A name of an environment variable.
            path (str): A filepath.

        Returns:
            str: Either a value of an environment variable or a path to the file containing the value.
        """
        if env in os.environ:
            value = decouple.config(env)
        else:
            with open(path, "r", encoding="utf-8") as f:
                value = f.readline().strip()
        return value

    def _check_if_k8s_secret_exists(self, name: str) -> bool:
        """Verifies whether a secret exists.

        Args:
            name (str): A secret's name.

        Raises:
            ApiException: Kubernetes API exception.

        Returns:
            bool: True if the secret exists.
        """
        v1 = self.config["k8s"]["v1"]
        logger = self.logger
        namespace = self.config["k8s"]["namespace"]

        try:
            api_response = v1.list_namespaced_secret(namespace=namespace, watch=False)
            if name in [item.metadata.name for item in api_response.items]:
                return True

        except ApiException as e:
            logger.critical(f"{type(e).__name__}: {e}")
            raise e

        return False

    @staticmethod
    def _encode_base64(data):
        """Returns data encoded in base64.

        Args:
            data (str): Plain-text.

        Returns:
            str: Base64-encoded text.
        """
        return base64.b64encode(data.encode("utf-8")).decode("utf-8")

    def _save_k8s_secret(self, name: str, keys: Dict) -> bool:
        """Saves a dict into a Kubernetes secret.

        Args:
            name (str): Name of the secret.
            keys (Dict): A dict with the data to be saved.

        Raises:
            ApiException: Kubernetes API exception.

        Returns:
            bool: True if the secret has been saved.
        """

        v1 = self.config["k8s"]["v1"]
        logger = self.logger
        namespace = self.config["k8s"]["namespace"]

        # Preparing the secret object
        body = client.V1Secret()
        body.api_version = "v1"
        body.kind = "Secret"
        body.metadata = {"name": name}
        # Encoding the secrets
        encoded_keys = {k: self._encode_base64(v) for k, v in keys.items()}
        body.data = encoded_keys

        try:
            # Three options:
            # 1. The secret exists, we need to replace it (REPLACE_SECRET=True);
            # 2. The secret exists, we have to retain it (REPLACE_SECRET=False) => ApiException (automatic)
            # 3. The secret does not exist, we need to create it.
            logger.info(
                f"REPLACE_SECRETS is set to {self.config['k8s']['replace_secrets']}"
            )
            if (
                self._check_if_k8s_secret_exists(name)
                and self.config["k8s"]["replace_secrets"]
            ):
                logger.warning(f"Replacing the secret {name} (REPLACE_SECRETS=True)")
                v1.replace_namespaced_secret(name=name, namespace=namespace, body=body)
            else:
                logger.info(f"Creating the secret {name}")
                v1.create_namespaced_secret(namespace=namespace, body=body)

        except ApiException as e:
            logger.error(f"Failed to save {name}.")
            logger.error(f"{type(e).__name__}: {e}")
            logger.debug(body.metadata, body.data)
            raise e

        return True

    def _vault_init(self, hvac_client: hvac.v1.Client) -> bool:
        """Initializes a Vault cluster and saves the resulting keys and a root token into a Kubernetes secret.

        Args:
            hvac_client (hvac.v1.Client): An hvac client instance.

        Raises:
            SystemExit: The exception is raised in case the process fails at something important.

        Returns:
            bool: True if the cluster has been initialized and the credentials saved.
        """
        logger = self.logger

        # Default values taken from Vault itself
        shares = 5
        threshold = 3

        # In case the function was called by mistake
        if hvac_client.sys.is_initialized():
            logger.info("The Vault cluster is already initialized.")
            return True

        logger.warning("The Vault cluster is not initialized yet.")

        # In case automatic cluster init is forbidden
        if not self.config["vault"]["init"]:
            logger.critical("VAULT_INIT is set to False. Shutting down the unsealer.")
            raise SystemExit(1)

        # Raising an exception if at least one of the secrets exists, and it's not allowed to replace it.
        try:
            if not self.config["k8s"]["replace_secrets"] and any(
                [
                    self._check_if_k8s_secret_exists(
                        self.config["vault"]["root_token_secret"]
                    ),
                    self._check_if_k8s_secret_exists(
                        self.config["vault"]["keys_secret"]
                    ),
                ]
            ):
                logger.critical(
                    "The unsealer has been configured to retain pre-existing secrets via REPLACE_SECRETS env. "
                    f"Please, manually delete them ({self.config['vault']['root_token_secret']}, "
                    f"{self.config['vault']['keys_secret']}) or set REPLACE_SECRETS=True if you wish to proceed. "
                    "Shutting down for now."
                )
                raise SystemExit(1)

        except ApiException:
            logger.critical(
                "Could not verify whether secrets with root token or keys exist. "
                "Thus, it's unsafe to proceed. Shutting down."
            )
            raise SystemExit(1)

        # Trying to init the cluster
        logger.warning(
            "VAULT_INIT is set to True. Starting the initialization process."
        )
        result = hvac_client.sys.initialize(shares, threshold)

        if not hvac_client.sys.is_initialized():
            logger.critical("Failed to initialize the vault cluster. Shutting down.")
            logger.critical(f"Raw response: {result}")
            raise SystemExit(1)

        logger.info("The vault cluster has been initialized.")

        # Preparing root token and keys to be stored in a k8s secret
        root_token = {"token": result["root_token"]}
        keys = {f"KEY{i}": vault_key for i, vault_key in enumerate(result["keys"], 1)}
        # Copying the keys to reconfigure unsealer on the fly as the previous set is not needed anymore
        self.config["vault"]["keys"] = keys.values()

        try:
            self._save_k8s_secret(self.config["vault"]["root_token_secret"], root_token)
            self._save_k8s_secret(self.config["vault"]["keys_secret"], keys)

        except ApiException:
            # The details will be printed by the save_k8s_secret itself
            logger.critical(
                "The set of keys and/or the root token have been lost. "
                "Shutting down the unsealer."
            )
            raise SystemExit(1)

        return True

    def _vault_unseal(self, vault_ip: str) -> bool:
        """Unseals a Vault instance and calls init() if needed.

        Args:
            vault_ip (str): An IP address of a Vault pod.

        Raises:
            SystemExit: It's raised when pod configuration doesn't contain enough keys to pass the unseal threshold.
            hvac.*: Errors implemented in the hvac module.
            requests.*: Errors implemented in the requests module (used by hvac).

        Returns:
            bool: True, if vault is unsealed
        """
        logger = self.logger
        hvac_client = hvac.Client(url=f"http://{vault_ip}:8200")

        try:
            # Init cluster if needed
            if not hvac_client.sys.is_initialized():
                self._vault_init(hvac_client)

            keys = self.config["vault"]["keys"]
            seal_status = hvac_client.seal_status
            threshold = seal_status["t"]

            # Check whether we have enough keys to pass the unseal threshold.
            if len(keys) < threshold:
                logger.critical(
                    f"Only {len(keys)} out of {threshold} vault keys have been supplied. "
                    f"Please, reconfigure the unsealer."
                )
                raise SystemExit(1)

            # Unseal a Vault instance if needed.
            if seal_status["sealed"]:
                unseal_response = hvac_client.sys.submit_unseal_keys(keys)
                if unseal_response["sealed"]:
                    logger.error(
                        f"Could not unseal {vault_ip}, raw unseal response: {unseal_response}"
                    )
                    return False
                else:
                    logger.info(f"{vault_ip} has been unsealed")
            else:
                # Note: This event will take place at least in the following cases:
                #       1. Unsealer starts after Vault instances are initialized;
                #       2. Vault modifies Pod labels other than vault-sealed=true on the fly.
                logger.info(f"{vault_ip} is already unsealed")

        except Exception as e:
            # A workaround to easily catch all exceptions from hvac and requests modules.
            # https://stackoverflow.com/questions/18176602/how-to-get-name-of-exception-that-was-caught-in-python
            module_name = e.__class__.__module__
            if any(["hvac" in module_name, "requests" in module_name]):
                logger.info(f"{module_name}: {e}")
            else:
                raise e

        return True

    def start(self):
        """Starts the unsealer main process.

        Raises:
            SystemExit: Raised when there's an API exception.
        """

        logger = self.logger
        logger.info("Vault unsealer has started")
        api_instance = client.ApiClient(self.config["k8s"]["client"])
        v1 = client.CoreV1Api(api_instance)

        # TODO: move somewhere else?
        # The instance will be used by the init() function
        self.config["k8s"]["v1"] = v1

        # We'll ignore DELETED events, because they will happen after a Vault is unsealed (Vault changes
        # label from vault-sealed=true to vault-sealed=false).
        controlled_events = {"ADDED", "MODIFIED"}

        w = watch.Watch()
        try:
            # Restart a watch stream when an API request times out
            while True:
                logger.debug("Starting a new watch stream")
                for event in w.stream(
                    func=v1.list_namespaced_pod,
                    label_selector="vault-sealed=true",
                    field_selector="status.phase=Running",
                    namespace=self.config["k8s"]["namespace"],
                ):

                    # Filter out irrelevant events
                    # Note: don't use all(), because it'll fail at empty events
                    if (
                        # Ignore irrelevant event types
                        event["type"] in controlled_events
                        # Ignore weird empty events
                        and event["object"].spec
                        # Ignore terminating pods
                        and not event["object"].metadata.deletion_timestamp
                        # Ignore non-ready pods
                        and event["object"].status.container_statuses[0].ready
                    ):
                        self._vault_unseal(event["object"].status.pod_ip)
        except ApiException as e:
            logger.error(f"{type(e).__name__}: {e}")
            raise SystemExit(1)
        finally:
            logger.info("Closing the watch stream")
            w.stop()


def terminate_process(signum: int, frame) -> None:
    """Handles SIGTERM.

    Args:
        signum (int): A signal, such as signal.SIGTERM.
        frame (frame): Current stack frame.

    Raises:
        SystemExit: It's always raised to notify that a SIGTERM has just been received.
    """
    raise SystemExit(
        f"Received {signal.Signals(signum).name}. Shutting down the application."
    )


def main():
    signal.signal(signal.SIGTERM, terminate_process)

    unsealer = VaultUnsealer()
    unsealer.start()


if __name__ == "__main__":
    main()
