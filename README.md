# What is UltraNIO?

UltraNIO is a cutting-edge, eBPF-based overlay networking solution designed specifically for Kubernetes environments. As a Container Network Interface (CNI) solution, similar to Calico, UltraNIO offers advanced, high-performance networking capabilities with a strong focus on security and policy management, making it ideal for small-scale private data centers.

What truly sets UltraNIO apart is its powerful ability to define and enforce granular security policies, including microsegmentation, security groups, and policy-based service chaining. These policies can be configured based on domain names, IAB (Interactive Advertising Bureau) categories, or traditional CIDRs (Classless Inter-Domain Routing), providing flexible and robust security options.

UltraNIO’s virtual switching fabric is inherently Layer 7 (L7)-aware, which allows it to provide detailed, real-time visibility into connection and security events. With domain and IAB categorization, it offers valuable insights into network traffic, enabling organizations to monitor and detect abnormal endpoint behaviors in real time. This level of observability and control not only enhances security but also empowers teams to take proactive measures to safeguard the network.

By leveraging eBPF technology, UltraNIO delivers high-performance networking without compromising on security or flexibility, making it an ideal choice for modern Kubernetes-based workloads in private data centers.

# What is UltraNIO based on ?

UltraNIO leverages eBPF, a revolutionary technology that enables high-performance and programmable networking within the Linux kernel. By allowing custom packet processing at the kernel level, eBPF minimizes latency and maximizes flexibility, making it an ideal foundation for modern, scalable overlay networking solutions. eBPFs are immune to Linux kernel versions/upgrades thereby simplifying the kernel compatibility matrix.

All UltraNIO eBPF code is licensed under GPL version 2.1 and is fully open-source.

# Features and Capabilities

- Virtual Private Clouds (VPCs):

  - UltraNIO provides robust VPC support, enabling secure, isolated networking environments.

- Network Security and Policy Control:

  - Features include microsegmentation, security groups, and categories.

  - Policies are L7-aware, supporting domain name-based security configurations and visualization.

  - Configurable 5-tuple rules (source/destination IPs, ports, and protocol) for incoming and outgoing traffic.

  - Symmetric security policies for granular control of source and destination rules.

  - Endpoint-level security allows separate rules per NIC, with flexible default and exception configurations.

  - Supports both CIDR and FQDN-based destination definitions, including IAB categories.

  - Traffic flows only if allowed by both source and destination policies.

- Policy-Based Routing and NAT:

  - Supports policy-based routing and policy-based NAT or non-NAT’ed egress.

  - Distributed NAT/NAT;ess connection state across Kubernetes hosts ensures resilience against host failures.

  - Egress traffic supports Equal-Cost Multi-Path (ECMP) routing by default, with no single point of failure.

- Service Chaining:

  - Enables policy-based service chaining for both incoming and outgoing connections.

  - Policies can be standard 5-tuple, FQDN, or IAB category-based.

- Network Load Balancing:

  - Built-in network load balancer with configurable target selection policies.

- Firewall Designation:

  - Allows designating a specific container or VM as a firewall for a subnet or a subset of containers/VMs.

- MAC-Based Routing:

  - Supports MAC-based packet routing within subnets, including raw packets without IP headers.

- Scalability and Resilience:

  - UltraNIO can handle millions of network security policies with real-time evaluation. For example, in large-scale enterprise environments such as multi-tenant cloud infrastructures or large Kubernetes clusters, this scalability allows UltraNIO to enforce precise security policies for each tenant or workload without compromising performance or manageability. In a complex enterprise deployment, UltraNIO can easily scale to several thousands of rules per endpoint (NIC) without users having sacrifice network security due to scale limitations.

  - Typically selects the best LPM (Longest Prefix Match) policy from two million entries in about 3 microseconds.

  - UltraNIO's CPU path length is very small as evidenced by it's lightning fast evaluation of LPM based network security policies thereby significantly reducing the CPU overhead of UltraNIO overlay network solution.

  - Maintains connection maps, evaluating policies only once per connection.

# Management and Visualization

- Granular Reporting:

  - Real-time security reporting of allowed or denied connections, including the policy responsible for each decision, on a per end-point basis

  - Provides detailed network connection statistics per endpoint to detect anomalies and threats.

    - Report provied details information about URL/IAB category of domain visited, bytes ingressed/egressed, time stamps, and real-time state of connection.

- L7 Awareness:

  - Reports include FQDN or IAB category details wherever applicable.

- QoS support

  - UltraNio allow creation of QoS policies to shape traffic based on destination CIDR, protocol, ports, as well as destination IAB category or domain name.

  - UltraNio connection statistics report allows easy L7 aware visualization of all incoming/outgoing traffic.

# Kubernetes Integration

  - UltraNIO functions as a Container Network Interface (CNI) provider and can be deployed as a pod to provide overlay networking for Kubernetes clusters.

  - By acting as a CNI provider, UltraNIO seamlessly integrates with Kubernetes to manage networking for containerized workloads. This enables consistent and automated deployment of overlay networking across clusters, enhancing operational efficiency. UltraNIO simplifies networking management while delivering advanced capabilities such as policy-based routing, security, and scalability, tailored to Kubernetes environments. Users benefit from streamlined configuration and centralized control, ensuring robust and efficient networking for all Kubernetes workloads.

  - Currently supports classic Kubernetes deployments but not MicroK8s, Kind, or similar setups.

  - To download and install the Ultra CNI, simply download this bootstrap CNI installer and run it: [_wget https://github.com/keshpa/UltraNIO/blob/main/ultra-bootstrap_](https://github.com/keshpa/UltraNIO/blob/main/ultra-bootstrap)

# Summary

UltraNIO is a cutting-edge solution for overlay networking and security, combining unparalleled scalability, performance, and flexibility. With its advanced features and open-source nature, UltraNIO empowers enterprises to deploy secure and highly efficient networking infrastructures tailored for modern containerized and virtualized environments.

