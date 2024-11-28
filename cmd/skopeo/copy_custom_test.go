package main

import "testing"

func TestRunCustom(t *testing.T) {
	ImageSync("registry.kubeease.cn/dockerhub/nginx", "registry://10.102.12.54")
}
