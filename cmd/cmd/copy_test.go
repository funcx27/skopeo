package cmd

import (
	"fmt"
	"testing"
)

func TestRunCustom(t *testing.T) {
	dest := "registry://127.0.0.1"
	src := []string{
		"nginx",
	}
	err := ImageSync(dest, src...)
	fmt.Println(err)
}
