package boundaries

import (
	"context"
	"log"
	"strings"
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"helmet.io/pkg/helm"
	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	testclient "k8s.io/client-go/kubernetes/fake"
	yaml "sigs.k8s.io/yaml"
)

func mockClient() kubernetes.Interface {
	client := testclient.NewSimpleClientset()

	endpoint := &v1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name: "kubernetes",
		},
		Subsets: []v1.EndpointSubset{{
			Addresses: []v1.EndpointAddress{{
				IP: "192.168.64.171",
			}},
			Ports: []v1.EndpointPort{{
				Port: 8443,
			}},
		}},
	}

	lo.Must(client.CoreV1().Endpoints("default").Create(context.TODO(), endpoint, metav1.CreateOptions{}))
	return client
}

var netpols = `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
    creationTimestamp: null
    name: wordpress-policy
spec:
    egress:
        - to:
            - ipBlock:
                cidr: 0.0.0.0/0
                except:
                    - 10.0.0.0/8
                    - 172.16.0.0/12
                    - 192.168.0.0/16
        - ports:
            - port: 53
              protocol: UDP
            - port: 53
              protocol: TCP
          to:
            - namespaceSelector:
                matchLabels:
                    kubernetes.io/metadata.name: kube-system
        - ports:
            - port: 3306
              protocol: TCP
          to:
            - podSelector:
                matchLabels:
                    helmet.io/chart: wordpress_mariadb
        - to:
            - podSelector:
                matchLabels:
                    helmet.io/chart: wordpress
       
    ingress:
        - from:
            - podSelector: {}
          ports:
            - port: 80
              protocol: TCP
            - port: 8080
              protocol: TCP
            - port: 443
              protocol: TCP
            - port: 8443
              protocol: TCP
        - from:
            - podSelector:
                matchLabels:
                    helmet.io/chart: wordpress
    podSelector:
        matchLabels:
            helmet.io/chart: wordpress
    policyTypes:
        - Egress
        - Ingress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
    creationTimestamp: null
    name: wordpress--mariadb-policy
spec:
    egress:
        - to:
            - ipBlock:
                cidr: 0.0.0.0/0
                except:
                    - 10.0.0.0/8
                    - 172.16.0.0/12
                    - 192.168.0.0/16
        - ports:
            - port: 53
              protocol: UDP
            - port: 53
              protocol: TCP
          to:
            - namespaceSelector:
                matchLabels:
                    kubernetes.io/metadata.name: kube-system
        - to:
            - podSelector:
                matchLabels:
                    helmet.io/chart: wordpress_mariadb
       
    ingress:
        - from:
            - podSelector:
                matchLabels:
                    helmet.io/chart: wordpress
          ports:
            - port: 3306
              protocol: TCP
        - from:
            - podSelector:
                matchLabels:
                    helmet.io/chart: wordpress_mariadb
    podSelector:
        matchLabels:
            helmet.io/chart: wordpress_mariadb
    policyTypes:
        - Egress
        - Ingress
`

func TestNetpolToTemplate(t *testing.T) {
	network_configurations := strings.Split(string(netpols), "\n---\n")
	netpols_obj := []netv1.NetworkPolicy{}
	for _, configuration := range network_configurations {
		var netpol_obj netv1.NetworkPolicy

		lo.Must0(yaml.Unmarshal([]byte(configuration), &netpol_obj))
		netpols_obj = append(netpols_obj, netpol_obj)
	}
	depTree := map[string][]string{"wordpress": {"wordpress_mariadb"}}

	template := NetworkPoliciesToTemplate(netpols_obj, depTree)
	assert.Len(t, template, 2)
	expPort := intstr.FromInt(3306)
	httpPort := intstr.FromInt(80)
	httpAltPort := intstr.FromInt(8080)
	httpsPort := intstr.FromInt(443)
	httpsAltPort := intstr.FromInt(8443)
	proto := v1.ProtocolTCP
	mariadb := template[1]
	assert.Equal(t, "wordpress--mariadb-policy", mariadb.Name)
	assert.Equal(t, map[string]string{"helmet.io/chart": "wordpress_mariadb"}, mariadb.ComponentSelector)

	assert.Equal(t, NetworkInterface{Allow: Allow{
		Resources: []Resource{
			{Ports: []netv1.NetworkPolicyPort{{Port: &expPort, Protocol: &proto}}},
		},
	}}, mariadb.Ingress)
	assert.Equal(t, NetworkInterface{Allow: Allow{Components: []string{"dns"}}, Deny: Deny{Components: []string{"private_subnets"}}}, mariadb.Egress)

	wordpress := template[0]
	assert.Equal(t, "wordpress-policy", wordpress.Name)
	assert.Equal(t, map[string]string{"helmet.io/chart": "wordpress"}, wordpress.ComponentSelector)

	assert.Equal(t, NetworkInterface{Allow: Allow{
		Resources: []Resource{
			{Ports: []netv1.NetworkPolicyPort{{Port: &httpPort, Protocol: &proto}, {Port: &httpAltPort, Protocol: &proto}, {Port: &httpsPort, Protocol: &proto}, {Port: &httpsAltPort, Protocol: &proto}}},
		},
	}}, wordpress.Ingress)

	assert.Equal(t, NetworkInterface{Allow: Allow{Components: []string{"dns"}}, Deny: Deny{Components: []string{"private_subnets"}}}, wordpress.Egress)

	assert.Equal(t, []Interaction{{
		From: map[string]string{"helmet.io/chart": "wordpress"},

		To: map[string]string{
			"helmet.io/chart": "wordpress_mariadb",
		},
	}}, wordpress.Interactions)

	assert.Nil(t, mariadb.Interactions)
}

var netpols_reversed = `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
    creationTimestamp: null
    name: wordpress--mariadb-policy
spec:
    egress:
        - to:
            - ipBlock:
                cidr: 0.0.0.0/0
                except:
                    - 10.0.0.0/8
                    - 172.16.0.0/12
                    - 192.168.0.0/16
        - ports:
            - port: 53
              protocol: UDP
            - port: 53
              protocol: TCP
          to:
            - namespaceSelector:
                matchLabels:
                    kubernetes.io/metadata.name: kube-system
        - to:
            - podSelector:
                matchLabels:
                    helmet.io/chart: wordpress_mariadb
       
    ingress:
        - from:
            - podSelector:
                matchLabels:
                    helmet.io/chart: wordpress
          ports:
            - port: 3306
              protocol: TCP
        - from:
            - podSelector:
                matchLabels:
                    helmet.io/chart: wordpress_mariadb
    podSelector:
        matchLabels:
            helmet.io/chart: wordpress_mariadb
    policyTypes:
        - Egress
        - Ingress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
    creationTimestamp: null
    name: wordpress-policy
spec:
    egress:
        - to:
            - ipBlock:
                cidr: 0.0.0.0/0
                except:
                    - 10.0.0.0/8
                    - 172.16.0.0/12
                    - 192.168.0.0/16
        - ports:
            - port: 53
              protocol: UDP
            - port: 53
              protocol: TCP
          to:
            - namespaceSelector:
                matchLabels:
                    kubernetes.io/metadata.name: kube-system
        - ports:
            - port: 3306
              protocol: TCP
          to:
            - podSelector:
                matchLabels:
                    helmet.io/chart: wordpress_mariadb
        - to:
            - podSelector:
                matchLabels:
                    helmet.io/chart: wordpress
       
    ingress:
        - from:
            - podSelector: {}
          ports:
            - port: 80
              protocol: TCP
            - port: 8080
              protocol: TCP
            - port: 443
              protocol: TCP
            - port: 8443
              protocol: TCP
        - from:
            - podSelector:
                matchLabels:
                    helmet.io/chart: wordpress
    podSelector:
        matchLabels:
            helmet.io/chart: wordpress
    policyTypes:
        - Egress
        - Ingress
`

func SkipTestTemplateToNetpol(t *testing.T) {
	network_configurations := strings.Split(string(netpols), "\n---\n")
	netpols_obj := []netv1.NetworkPolicy{}
	for _, configuration := range network_configurations {
		var netpol_obj netv1.NetworkPolicy

		lo.Must0(yaml.Unmarshal([]byte(configuration), &netpol_obj))
		netpols_obj = append(netpols_obj, netpol_obj)
	}
	depTree := map[string][]string{"wordpress": {"wordpress_mariadb"}}
	ancestors := map[string][]string{"wordpress_mariadb": {"wordpress"}}

	template := NetworkPoliciesToTemplate(netpols_obj, depTree)
	policies := TemplatesToNetpol(template, mockClient(), ancestors)

	assert.Len(t, policies, 2)
	assert.Equal(t, "wordpress--mariadb-policy", policies[1].Name)
	assert.Equal(t, helm.SortEgressPolicies(netpols_obj[1].Spec.Egress), helm.SortEgressPolicies(policies[1].Spec.Egress))
	assert.Equal(t, helm.SortIngressPolicies(netpols_obj[1].Spec.Ingress), helm.SortIngressPolicies(policies[1].Spec.Ingress))

	assert.Equal(t, "wordpress-policy", policies[0].Name)
	assert.Equal(t, helm.SortEgressPolicies(netpols_obj[0].Spec.Egress), helm.SortEgressPolicies(policies[0].Spec.Egress))
	assert.ElementsMatch(t, netpols_obj[0].Spec.Ingress, policies[0].Spec.Ingress)
}

func SkipTestTemplateToNetpolReversed(t *testing.T) {
	network_configurations := strings.Split(string(netpols_reversed), "\n---\n")
	netpols_obj := []netv1.NetworkPolicy{}
	for _, configuration := range network_configurations {
		var netpol_obj netv1.NetworkPolicy

		lo.Must0(yaml.Unmarshal([]byte(configuration), &netpol_obj))
		netpols_obj = append(netpols_obj, netpol_obj)
	}
	depTree := map[string][]string{"wordpress": {"wordpress_mariadb"}}
	ancestors := map[string][]string{"wordpress_mariadb": {"wordpress"}}

	template := NetworkPoliciesToTemplate(netpols_obj, depTree)
	policies := TemplatesToNetpol(template, mockClient(), ancestors)

	assert.Len(t, policies, 2)
	assert.Equal(t, "wordpress-policy", policies[1].Name)
	assert.Equal(t, helm.SortEgressPolicies(netpols_obj[1].Spec.Egress), helm.SortEgressPolicies(policies[1].Spec.Egress))
	assert.ElementsMatch(t, netpols_obj[1].Spec.Ingress, policies[1].Spec.Ingress)
	assert.Equal(t, "wordpress--mariadb-policy", policies[0].Name)
	assert.Equal(t, helm.SortEgressPolicies(netpols_obj[0].Spec.Egress), helm.SortEgressPolicies(policies[0].Spec.Egress))
	assert.Equal(t, helm.SortIngressPolicies(netpols_obj[0].Spec.Ingress), helm.SortIngressPolicies(policies[0].Spec.Ingress))
}

var generatedConfig = `
ComponentSelector:
  helmet.io/chart: wordpress_mariadb
Egress:
  Allow:
    Components:
    - dns
    Resources: null
  Deny:
    Components:
    - private_subnets
    Resources: null
Ingress:
  Allow:
    Components: null
    Resources:
    - Ports:
      - port: 3306
        protocol: TCP
      Selector: null
  Deny:
    Components: null
    Resources: null
Interactions: []
Name: wordpress--mariadb-policy

---
ComponentSelector:
  helmet.io/chart: wordpress
Egress:
  Allow:
    Components:
    - dns
    Resources: null
  Deny:
    Components:
    - private_subnets
    Resources: null
Ingress:
  Allow:
    Components: null
    Resources:
    - Ports:
      - port: 80
        protocol: TCP
      - port: 8080
        protocol: TCP
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

---`

func TestGeneratedConfig(t *testing.T) {
	network_configurations := strings.Split(string(netpols), "\n---\n")
	netpols_obj := []netv1.NetworkPolicy{}
	for _, configuration := range network_configurations {
		var netpol_obj netv1.NetworkPolicy

		lo.Must0(yaml.Unmarshal([]byte(configuration), &netpol_obj))
		netpols_obj = append(netpols_obj, netpol_obj)
	}

	depTree := map[string][]string{"wordpress": {"wordpress_mariadb"}}
	template := NetworkPoliciesToTemplate(netpols_obj, depTree)
	var cfg []HelmETConfig
	single_config := strings.Split(string(generatedConfig), "\n---\n")
	for _, configuration := range single_config {
		var helmetConfig HelmETConfig

		lo.Must0(yaml.Unmarshal([]byte(configuration), &helmetConfig))
		cfg = append(cfg, helmetConfig)
	}

	assert.Equal(t, template[0].Name, cfg[1].Name)
	assert.Equal(t, template[0].Interactions[0].From, cfg[1].Interactions[0].From)
	assert.Equal(t, template[0].Interactions[0].To, cfg[1].Interactions[0].To)
}

var customConfig = `
ComponentSelector:
  helmet.io/chart: wordpress_mariadb
Egress:
  Allow:
    Components:
    - dns
    Resources: null
  Deny:
    Components:
    - private_subnets
    Resources: null
Ingress:
  Allow:
    Components: null
    Resources:
    - Ports:
      - port: 3306
        protocol: TCP
      Selector: null
  Deny:
    Components: null
    Resources: null
Interactions: []
Name: wordpress--mariadb-policy

---
ComponentSelector:
  helmet.io/chart: wordpress
Egress:
  Allow:
    Components:
    - dns
    Resources: null
  Deny:
    Components:
    - private_subnets
    Resources: null
Ingress:
  Allow:
    Components: null
    Resources:
    - Ports:
      - port: 80
        protocol: TCP
      - port: 8080
        protocol: TCP
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
- From:
    helmet.io/chart: wordpress_mariadb
  To:
    helmet.io/chart: wordpress 
Name: wordpress-policy

---`

func TestGeneratedCustomConfig(t *testing.T) {
	template := []HelmETConfig{}
	ancestors := map[string][]string{"wordpress_mariadb": {"wordpress"}}
	network_configurations := strings.Split(string(customConfig), "\n---\n")
	for _, configuration := range network_configurations {
		var custom_config HelmETConfig
		lo.Must0(yaml.Unmarshal([]byte(configuration), &custom_config))
		template = append(template, custom_config)
	}
	generated_policies := TemplatesToNetpol(template, mockClient(), ancestors)
	for _, policy := range generated_policies {
		if policy.Name == "wordpress" {
			log.Print(string(lo.Must(yaml.Marshal(policy))))
			assert.Len(t, policy.Spec.Ingress, 2)
		}
	}
}
