/*
Copyright 2025 Helm-ET authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
Copyright 2025 Helm-ET authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package testutils

var WORDPRESS = `---
# Source: wordpress/charts/mariadb/templates/networkpolicy.yaml
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: mychart-mariadb
  namespace: "default"
  labels:
    app.kubernetes.io/instance: mychart
    app.kubernetes.io/managed-by: Helm
    app.kubernetes.io/name: mariadb
    app.kubernetes.io/version: 11.4.2
    helm.sh/chart: mariadb-19.0.1
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/instance: mychart
      app.kubernetes.io/managed-by: Helm
      app.kubernetes.io/name: mariadb
      app.kubernetes.io/version: 11.4.2
      helm.sh/chart: mariadb-19.0.1
  policyTypes:
    - Ingress
    - Egress
  egress:
    - {}
  ingress:
    - ports:
        - port: 3306
        - port: 3306
---
# Source: wordpress/templates/networkpolicy.yaml
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: mychart-wordpress
  namespace: "default"
  labels:
    app.kubernetes.io/instance: mychart
    app.kubernetes.io/managed-by: Helm
    app.kubernetes.io/name: wordpress
    app.kubernetes.io/version: 6.6.0
    helm.sh/chart: wordpress-23.0.9
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/instance: mychart
      app.kubernetes.io/name: wordpress
  policyTypes:
    - Ingress
    - Egress
  egress:
    - {}
  ingress:
    - ports:
        - port: 8080
        - port: 8443
---
# Source: wordpress/charts/mariadb/templates/primary/pdb.yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: mychart-mariadb
  namespace: "default"
  labels:
    app.kubernetes.io/instance: mychart
    app.kubernetes.io/managed-by: Helm
    app.kubernetes.io/name: mariadb
    app.kubernetes.io/version: 11.4.2
    helm.sh/chart: mariadb-19.0.1
    app.kubernetes.io/component: primary
spec:
  maxUnavailable: 1
  selector:
    matchLabels:
      app.kubernetes.io/instance: mychart
      app.kubernetes.io/name: mariadb
      app.kubernetes.io/component: primary
---
# Source: wordpress/templates/pdb.yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: mychart-wordpress
  namespace: "default"
  labels:
    app.kubernetes.io/instance: mychart
    app.kubernetes.io/managed-by: Helm
    app.kubernetes.io/name: wordpress
    app.kubernetes.io/version: 6.6.0
    helm.sh/chart: wordpress-23.0.9
spec:
  maxUnavailable: 1
  selector:
    matchLabels:
      app.kubernetes.io/instance: mychart
      app.kubernetes.io/name: wordpress
---
# Source: wordpress/charts/mariadb/templates/serviceaccount.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: mychart-mariadb
  namespace: "default"
  labels:
    app.kubernetes.io/instance: mychart
    app.kubernetes.io/managed-by: Helm
    app.kubernetes.io/name: mariadb
    app.kubernetes.io/version: 11.4.2
    helm.sh/chart: mariadb-19.0.1
automountServiceAccountToken: false
---
# Source: wordpress/templates/serviceaccount.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: mychart-wordpress
  namespace: "default"
  labels:
    app.kubernetes.io/instance: mychart
    app.kubernetes.io/managed-by: Helm
    app.kubernetes.io/name: wordpress
    app.kubernetes.io/version: 6.6.0
    helm.sh/chart: wordpress-23.0.9
automountServiceAccountToken: false
---
# Source: wordpress/charts/mariadb/templates/secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: mychart-mariadb
  namespace: "default"
  labels:
    app.kubernetes.io/instance: mychart
    app.kubernetes.io/managed-by: Helm
    app.kubernetes.io/name: mariadb
    app.kubernetes.io/version: 11.4.2
    helm.sh/chart: mariadb-19.0.1
type: Opaque
data:
  mariadb-root-password: "em4wazhoR2lzaQ=="
  mariadb-password: "Ulh2eWg3eUZKdQ=="
---
# Source: wordpress/templates/secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: mychart-wordpress
  namespace: "default"
  labels:
    app.kubernetes.io/instance: mychart
    app.kubernetes.io/managed-by: Helm
    app.kubernetes.io/name: wordpress
    app.kubernetes.io/version: 6.6.0
    helm.sh/chart: wordpress-23.0.9
type: Opaque
data:
  wordpress-password: "TGJ4YkVJTXNaSg=="
---
# Source: wordpress/charts/mariadb/templates/primary/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: mychart-mariadb
  namespace: "default"
  labels:
    app.kubernetes.io/instance: mychart
    app.kubernetes.io/managed-by: Helm
    app.kubernetes.io/name: mariadb
    app.kubernetes.io/version: 11.4.2
    helm.sh/chart: mariadb-19.0.1
    app.kubernetes.io/component: primary
data:
  my.cnf: |-
    [mysqld]
    skip-name-resolve
    explicit_defaults_for_timestamp
    basedir=/opt/bitnami/mariadb
    datadir=/bitnami/mariadb/data
    plugin_dir=/opt/bitnami/mariadb/plugin
    port=3306
    socket=/opt/bitnami/mariadb/tmp/mysql.sock
    tmpdir=/opt/bitnami/mariadb/tmp
    max_allowed_packet=16M
    bind-address=*
    pid-file=/opt/bitnami/mariadb/tmp/mysqld.pid
    log-error=/opt/bitnami/mariadb/logs/mysqld.log
    character-set-server=UTF8
    collation-server=utf8_general_ci
    slow_query_log=0
    long_query_time=10.0
    
    [client]
    port=3306
    socket=/opt/bitnami/mariadb/tmp/mysql.sock
    default-character-set=UTF8
    plugin_dir=/opt/bitnami/mariadb/plugin
    
    [manager]
    port=3306
    socket=/opt/bitnami/mariadb/tmp/mysql.sock
    pid-file=/opt/bitnami/mariadb/tmp/mysqld.pid
---
# Source: wordpress/templates/pvc.yaml
kind: PersistentVolumeClaim
apiVersion: v1
metadata:
  name: mychart-wordpress
  namespace: "default"
  labels:
    app.kubernetes.io/instance: mychart
    app.kubernetes.io/managed-by: Helm
    app.kubernetes.io/name: wordpress
    app.kubernetes.io/version: 6.6.0
    helm.sh/chart: wordpress-23.0.9
spec:
  accessModes:
    - "ReadWriteOnce"
  resources:
    requests:
      storage: "10Gi"
---
# Source: wordpress/charts/mariadb/templates/primary/svc.yaml
apiVersion: v1
kind: Service
metadata:
  name: mychart-mariadb
  namespace: "default"
  labels:
    app.kubernetes.io/instance: mychart
    app.kubernetes.io/managed-by: Helm
    app.kubernetes.io/name: mariadb
    app.kubernetes.io/version: 11.4.2
    helm.sh/chart: mariadb-19.0.1
    app.kubernetes.io/component: primary
  annotations:
spec:
  type: ClusterIP
  sessionAffinity: None
  ports:
    - name: mysql
      port: 3306
      protocol: TCP
      targetPort: mysql
      nodePort: null
  selector:
    app.kubernetes.io/instance: mychart
    app.kubernetes.io/name: mariadb
    app.kubernetes.io/component: primary
---
# Source: wordpress/templates/svc.yaml
apiVersion: v1
kind: Service
metadata:
  name: mychart-wordpress
  namespace: "default"
  labels:
    app.kubernetes.io/instance: mychart
    app.kubernetes.io/managed-by: Helm
    app.kubernetes.io/name: wordpress
    app.kubernetes.io/version: 6.6.0
    helm.sh/chart: wordpress-23.0.9
spec:
  type: LoadBalancer
  externalTrafficPolicy: "Cluster"
  sessionAffinity: None
  ports:
    - name: http
      port: 80
      protocol: TCP
      targetPort: http
    - name: https
      port: 443
      protocol: TCP
      targetPort: https
  selector:
    app.kubernetes.io/instance: mychart
    app.kubernetes.io/name: wordpress
---
# Source: wordpress/templates/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mychart-wordpress
  namespace: "default"
  labels:
    app.kubernetes.io/instance: mychart
    app.kubernetes.io/managed-by: Helm
    app.kubernetes.io/name: wordpress
    app.kubernetes.io/version: 6.6.0
    helm.sh/chart: wordpress-23.0.9
spec:
  selector:
    matchLabels:
      app.kubernetes.io/instance: mychart
      app.kubernetes.io/name: wordpress
  strategy:
    type: RollingUpdate
  replicas: 1
  template:
    metadata:
      labels:
        app.kubernetes.io/instance: mychart
        app.kubernetes.io/managed-by: Helm
        app.kubernetes.io/name: wordpress
        app.kubernetes.io/version: 6.6.0
        helm.sh/chart: wordpress-23.0.9
    spec:
      
      automountServiceAccountToken: false
      # yamllint disable rule:indentation
      hostAliases:
        - hostnames:
          - status.localhost
          ip: 127.0.0.1
      # yamllint enable rule:indentation
      affinity:
        podAffinity:
          
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - podAffinityTerm:
                labelSelector:
                  matchLabels:
                    app.kubernetes.io/instance: mychart
                    app.kubernetes.io/name: wordpress
                topologyKey: kubernetes.io/hostname
              weight: 1
        nodeAffinity:
          
      securityContext:
        fsGroup: 1001
        fsGroupChangePolicy: Always
        supplementalGroups: []
        sysctls: []
      serviceAccountName: mychart-wordpress
      initContainers:
        - name: prepare-base-dir
          image: docker.io/bitnami/wordpress:6.6.0-debian-12-r4
          imagePullPolicy: "IfNotPresent"
          resources:
            limits:
              cpu: 375m
              ephemeral-storage: 2Gi
              memory: 384Mi
            requests:
              cpu: 250m
              ephemeral-storage: 50Mi
              memory: 256Mi
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop:
              - ALL
            privileged: false
            readOnlyRootFilesystem: true
            runAsGroup: 1001
            runAsNonRoot: true
            runAsUser: 1001
            seLinuxOptions: {}
            seccompProfile:
              type: RuntimeDefault
          command:
            - /bin/bash
          args:
            - -ec
            - |
              #!/bin/bash

              . /opt/bitnami/scripts/liblog.sh
              . /opt/bitnami/scripts/libfs.sh

              info "Copying base dir to empty dir"
              # In order to not break the application functionality (such as upgrades or plugins) we need
              # to make the base directory writable, so we need to copy it to an empty dir volume
              cp -r --preserve=mode /opt/bitnami/wordpress /emptydir/app-base-dir

              info "Copying symlinks to stdout/stderr"
              # We copy the logs folder because it has symlinks to stdout and stderr
              if ! is_dir_empty /opt/bitnami/apache/logs; then
                cp -r /opt/bitnami/apache/logs /emptydir/apache-logs-dir
              fi

              info "Copying default PHP config"
              cp -r --preserve=mode /opt/bitnami/php/etc /emptydir/php-conf-dir

              info "Copy operation completed"
          volumeMounts:
            - name: empty-dir
              mountPath: /emptydir
      containers:
        - name: wordpress
          image: docker.io/bitnami/wordpress:6.6.0-debian-12-r4
          imagePullPolicy: "IfNotPresent"
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop:
              - ALL
            privileged: false
            readOnlyRootFilesystem: true
            runAsGroup: 1001
            runAsNonRoot: true
            runAsUser: 1001
            seLinuxOptions: {}
            seccompProfile:
              type: RuntimeDefault
          env:
            - name: BITNAMI_DEBUG
              value: "false"
            - name: ALLOW_EMPTY_PASSWORD
              value: "yes"
            - name: WORDPRESS_SKIP_BOOTSTRAP
              value: "no"
            - name: MARIADB_HOST
              value: "mychart-mariadb"
            - name: MARIADB_PORT_NUMBER
              value: "3306"
            - name: WORDPRESS_DATABASE_NAME
              value: "bitnami_wordpress"
            - name: WORDPRESS_DATABASE_USER
              value: "bn_wordpress"
            - name: WORDPRESS_DATABASE_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: mychart-mariadb
                  key: mariadb-password
            - name: WORDPRESS_USERNAME
              value: "user"
            - name: WORDPRESS_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: mychart-wordpress
                  key: wordpress-password
            - name: WORDPRESS_EMAIL
              value: "user@example.com"
            - name: WORDPRESS_FIRST_NAME
              value: "FirstName"
            - name: WORDPRESS_LAST_NAME
              value: "LastName"
            - name: WORDPRESS_HTACCESS_OVERRIDE_NONE
              value: "no"
            - name: WORDPRESS_ENABLE_HTACCESS_PERSISTENCE
              value: "no"
            - name: WORDPRESS_BLOG_NAME
              value: "User's Blog!"
            - name: WORDPRESS_TABLE_PREFIX
              value: "wp_"
            - name: WORDPRESS_SCHEME
              value: "http"
            - name: WORDPRESS_EXTRA_WP_CONFIG_CONTENT
              value: ""
            - name: WORDPRESS_PLUGINS
              value: "none"
            - name: WORDPRESS_OVERRIDE_DATABASE_SETTINGS
              value: "no"
            - name: APACHE_HTTP_PORT_NUMBER
              value: "8080"
            - name: APACHE_HTTPS_PORT_NUMBER
              value: "8443"
          envFrom:
          ports:
            - name: http
              containerPort: 8080
            - name: https
              containerPort: 8443
          livenessProbe:
            failureThreshold: 6
            initialDelaySeconds: 120
            periodSeconds: 10
            successThreshold: 1
            tcpSocket:
              port: http
            timeoutSeconds: 5
          readinessProbe:
            failureThreshold: 6
            httpGet:
              httpHeaders: []
              path: /wp-login.php
              port: 'http'
              scheme: 'HTTP'
            initialDelaySeconds: 30
            periodSeconds: 10
            successThreshold: 1
            timeoutSeconds: 5
          resources:
            limits:
              cpu: 375m
              ephemeral-storage: 2Gi
              memory: 384Mi
            requests:
              cpu: 250m
              ephemeral-storage: 50Mi
              memory: 256Mi
          volumeMounts:
            - name: empty-dir
              mountPath: /opt/bitnami/apache/conf
              subPath: apache-conf-dir
            - name: empty-dir
              mountPath: /opt/bitnami/apache/logs
              subPath: apache-logs-dir
            - name: empty-dir
              mountPath: /opt/bitnami/apache/var/run
              subPath: apache-tmp-dir
            - name: empty-dir
              mountPath: /opt/bitnami/php/etc
              subPath: php-conf-dir
            - name: empty-dir
              mountPath: /opt/bitnami/php/tmp
              subPath: php-tmp-dir
            - name: empty-dir
              mountPath: /opt/bitnami/php/var
              subPath: php-var-dir
            - name: empty-dir
              mountPath: /tmp
              subPath: tmp-dir
            - name: empty-dir
              mountPath: /opt/bitnami/wordpress
              subPath: app-base-dir
            - mountPath: /bitnami/wordpress
              name: wordpress-data
              subPath: wordpress
      volumes:
        - name: empty-dir
          emptyDir: {}
        - name: wordpress-data
          persistentVolumeClaim:
            claimName: mychart-wordpress
---
# Source: wordpress/charts/mariadb/templates/primary/statefulset.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: mychart-mariadb
  namespace: "default"
  labels:
    app.kubernetes.io/instance: mychart
    app.kubernetes.io/managed-by: Helm
    app.kubernetes.io/name: mariadb
    app.kubernetes.io/version: 11.4.2
    helm.sh/chart: mariadb-19.0.1
    app.kubernetes.io/component: primary
spec:
  replicas: 1
  revisionHistoryLimit: 10
  selector:
    matchLabels:
      app.kubernetes.io/instance: mychart
      app.kubernetes.io/name: mariadb
      app.kubernetes.io/component: primary
  serviceName: mychart-mariadb
  updateStrategy:
    type: RollingUpdate
  template:
    metadata:
      annotations:
        checksum/configuration: fd24413d92085396355e35d95106e058b55ee19c2d692df6b0d3a00b81085b75
      labels:
        app.kubernetes.io/instance: mychart
        app.kubernetes.io/managed-by: Helm
        app.kubernetes.io/name: mariadb
        app.kubernetes.io/version: 11.4.2
        helm.sh/chart: mariadb-19.0.1
        app.kubernetes.io/component: primary
    spec:
      
      automountServiceAccountToken: false
      serviceAccountName: mychart-mariadb
      affinity:
        podAffinity:
          
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - podAffinityTerm:
                labelSelector:
                  matchLabels:
                    app.kubernetes.io/instance: mychart
                    app.kubernetes.io/name: mariadb
                    app.kubernetes.io/component: primary
                topologyKey: kubernetes.io/hostname
              weight: 1
        nodeAffinity:
          
      securityContext:
        fsGroup: 1001
        fsGroupChangePolicy: Always
        supplementalGroups: []
        sysctls: []
      initContainers:
        - name: preserve-logs-symlinks
          image: docker.io/bitnami/mariadb:11.4.2-debian-12-r0
          imagePullPolicy: "IfNotPresent"
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop:
              - ALL
            privileged: false
            readOnlyRootFilesystem: true
            runAsGroup: 1001
            runAsNonRoot: true
            runAsUser: 1001
            seLinuxOptions: {}
            seccompProfile:
              type: RuntimeDefault
          resources:
            limits:
              cpu: 375m
              ephemeral-storage: 2Gi
              memory: 384Mi
            requests:
              cpu: 250m
              ephemeral-storage: 50Mi
              memory: 256Mi
          command:
            - /bin/bash
          args:
            - -ec
            - |
              #!/bin/bash

              . /opt/bitnami/scripts/libfs.sh
              # We copy the logs folder because it has symlinks to stdout and stderr
              if ! is_dir_empty /opt/bitnami/mariadb/logs; then
                cp -r /opt/bitnami/mariadb/logs /emptydir/app-logs-dir
              fi
          volumeMounts:
            - name: empty-dir
              mountPath: /emptydir
      containers:
        - name: mariadb
          image: docker.io/bitnami/mariadb:11.4.2-debian-12-r0
          imagePullPolicy: "IfNotPresent"
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop:
              - ALL
            privileged: false
            readOnlyRootFilesystem: true
            runAsGroup: 1001
            runAsNonRoot: true
            runAsUser: 1001
            seLinuxOptions: {}
            seccompProfile:
              type: RuntimeDefault
          env:
            - name: BITNAMI_DEBUG
              value: "false"
            - name: MARIADB_ROOT_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: mychart-mariadb
                  key: mariadb-root-password
            - name: MARIADB_USER
              value: "bn_wordpress"
            - name: MARIADB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: mychart-mariadb
                  key: mariadb-password
            - name: MARIADB_DATABASE
              value: "bitnami_wordpress"
          ports:
            - name: mysql
              containerPort: 3306
          livenessProbe:
            failureThreshold: 3
            initialDelaySeconds: 120
            periodSeconds: 10
            successThreshold: 1
            timeoutSeconds: 1
            exec:
              command:
                - /bin/bash
                - -ec
                - |
                  password_aux="${MARIADB_ROOT_PASSWORD:-}"
                  if [[ -f "${MARIADB_ROOT_PASSWORD_FILE:-}" ]]; then
                      password_aux=$(cat "$MARIADB_ROOT_PASSWORD_FILE")
                  fi
                  mysqladmin status -uroot -p"${password_aux}"
          readinessProbe:
            failureThreshold: 3
            initialDelaySeconds: 30
            periodSeconds: 10
            successThreshold: 1
            timeoutSeconds: 1
            exec:
              command:
                - /bin/bash
                - -ec
                - |
                  password_aux="${MARIADB_ROOT_PASSWORD:-}"
                  if [[ -f "${MARIADB_ROOT_PASSWORD_FILE:-}" ]]; then
                      password_aux=$(cat "$MARIADB_ROOT_PASSWORD_FILE")
                  fi
                  mysqladmin ping -uroot -p"${password_aux}"
          resources:
            limits:
              cpu: 375m
              ephemeral-storage: 2Gi
              memory: 384Mi
            requests:
              cpu: 250m
              ephemeral-storage: 50Mi
              memory: 256Mi
          volumeMounts:
            - name: data
              mountPath: /bitnami/mariadb
            - name: config
              mountPath: /opt/bitnami/mariadb/conf/my.cnf
              subPath: my.cnf
            - name: empty-dir
              mountPath: /tmp
              subPath: tmp-dir
            - name: empty-dir
              mountPath: /opt/bitnami/mariadb/conf
              subPath: app-conf-dir
            - name: empty-dir
              mountPath: /opt/bitnami/mariadb/tmp
              subPath: app-tmp-dir
            - name: empty-dir
              mountPath: /opt/bitnami/mariadb/logs
              subPath: app-logs-dir
      volumes:
        - name: empty-dir
          emptyDir: {}
        - name: config
          configMap:
            name: mychart-mariadb
  volumeClaimTemplates:
    - metadata:
        name: data
        labels:
          app.kubernetes.io/instance: mychart
          app.kubernetes.io/name: mariadb
          app.kubernetes.io/component: primary
      spec:
        accessModes:
          - "ReadWriteOnce"
        resources:
          requests:
            storage: "8Gi"`
