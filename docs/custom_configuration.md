# Configuration Documentation

This section explains the purpose and structure of the Helm-ET configuration file, which is generated automatically by Helm-ET after each execution and can be passed as a variable to customize the generated policies.

## Overview

The Helm-ET configuration file contains rules that manage communication between components of one or more applications. Each policy includes settings for:
- Component selection
- Ingress and egress rules
- Network interactions between components

A configuration file named `config.yaml` is generated after each Helm-ET execution.

## YAML Structure

### 1. Component Identification
- **ComponentSelector:**  
  Specifies the selector labels for the component. For example, `helmet.io/chart: wordpress` identifies the WordPress component. In real scenarios, this is the set of labels that a component has.

### 2. Traffic Control Rules
- **Egress:**  
  Lists rules controlling outbound (egress) traffic. These rules are divided into:
  - **Allow:** Defines which components and resources the component can communicate with externally.
  - **Deny:** Specifies which external components or resources are blocked.

- **Ingress:**  
  Details rules for inbound traffic. These include:
  - **Allow:** Lists the allowed ports, protocols, and resources that can interact with the component.
  - **Deny:** Sets restrictions on which inbound connections are not allowed.

## Example configuration

```yaml
ComponentSelector:
  helmet.io/chart: wordpress
Egress:
  Allow:
  Components:
  - dns
  - kube_api_server
  Deny:
  Components:
  - private_subnets
Ingress:
  Allow:
  Resources:
  - Ports:
    - port: 443
    protocol: TCP
    - port: 8443
    protocol: TCP
    Selector: null
  Deny:
  Components: null
  Resources: null
Interactions:
- From:
  helmet.io/chart: wordpress
  To:
  helmet.io/chart: wordpress_mariadb
Name: wordpress-policy
```

## Specify custom configuration

To specify a custom Helm-ET configuration, set the `CONFIG_FILE` environment variable (you can also use a `.env` file). When Helm-ET runs in this mode, it will not generate any policies other than those in the configuration file.