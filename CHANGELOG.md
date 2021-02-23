# vault unsealer

## 0.3.3

* Bumped dependencies and base image;
* Switched to a non-root user.

## 0.3.2

* Updated the role manifest (reduced number of verbs).

## 0.3.1

* Fixed logging for hvac/requests exceptions (didn't work in k8s).

## 0.3.0

* Moved everything to a class for simplification.

## 0.2.0

* Optional automatic initialization with saving keys in k8s secrets (vault-root-token and vault-keys);
* Any number of keys can be supplied via environment variables or files (useful when keys are mounted from a k8s secret);
* Bugfix: crash when received an empty event;
* Correct exit codes;
* Better exception handling;
* Code formatting via Black.

## 0.1.0

* Automatic unseal process with keys taken from KEY1..KEY5.
