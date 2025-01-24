ethtool -K $1 rx-checksumming off
ethtool -K $1 tx-checksumming off
ethtool -K $1 tcp-segmentation-offload off
ethtool -K $1 generic-segmentation-offload off
