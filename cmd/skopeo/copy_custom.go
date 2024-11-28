package main

import (
	"bufio"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/docker/distribution/configuration"
	dcontext "github.com/docker/distribution/context"
	"github.com/docker/distribution/registry"
	_ "github.com/docker/distribution/registry/storage/driver/filesystem"
	"github.com/funcx27/skopeo/version"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
)

var customExampleStr = `
skopeo copy file://imagelist.txt registry://127.0.0.1
skopeo copy file://imagelist.txt registry://127.0.0.1/test
skopeo copy docker.io/nginx registry-dir:///var/lib/registry   #将镜像同步至目录
skopeo copy file://imagelist.txt        #dest为空,默认下载地址为: registry-dir:///var/lib/registry
skopeo copy http://xx.xx.com/xx/imagelist.txt
`
var defaultDestRegistry = "registry-dir:///var/lib/registry"

func ImageSync(args ...string) {
	NewOpts().runCustom(args, os.Stdout)
}
func NewOpts() *copyOptions {
	cmd, global := createApp()
	_, sharedOpts := sharedImageFlags()
	_, deprecatedTLSVerifyOpt := deprecatedTLSVerifyFlags()
	srcFlag, srcOpts := imageFlags(global, sharedOpts, deprecatedTLSVerifyOpt, "src-", "screds")
	destFlag, destOpts := imageDestFlags(global, sharedOpts, deprecatedTLSVerifyOpt, "dest-", "dcreds")
	_, retryOpts := retryFlags()
	cmd.Flags().AddFlagSet(&srcFlag)
	cmd.Flags().AddFlagSet(&destFlag)
	cmd.Flags().VisitAll(overrideFlagFunc)
	return &copyOptions{global: global,
		deprecatedTLSVerify: deprecatedTLSVerifyOpt,
		srcImage:            srcOpts,
		destImage:           destOpts,
		retryOpts:           retryOpts,
	}
}

func (opts *copyOptions) runCustom(args []string, stdout io.Writer) (retErr error) {
	_, err := os.Stat(os.Getenv("XDG_RUNTIME_DIR"))
	if err != nil {
		os.Setenv("XDG_RUNTIME_DIR", "/tmp/")
	}
	if len(args) == 0 {
		return errorShouldDisplayUsage{errors.New("Exactly one arguments expected")}
	}
	rx, _ := regexp.Compile("^http(|s)://|file://")
	if rx.MatchString(args[0]) {
		if len(args) == 1 {
			args = append(args, defaultDestRegistry)
		}
		return opts.runListFile(args, stdout)

	}
	if !strings.HasPrefix(args[0], "docker://") && !strings.HasPrefix(args[len(args)-1], "registry://") {
		args = append(args, defaultDestRegistry)
	}
	if strings.HasPrefix(args[len(args)-1], "registry://") || strings.HasPrefix(args[len(args)-1], "registry-dir://") {
		opts.copyImages(args[:len(args)-1], args[len(args)-1], stdout)
		return
	}
	return opts.run(args, stdout)
}

func (opts *copyOptions) runListFile(args []string, stdout io.Writer) (retErr error) {
	var ir io.Reader
	rx, _ := regexp.Compile("^http(|s)://")
	if rx.MatchString(args[0]) {
		resp, err := http.Get(args[0])
		if err != nil {
			log.Panic(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			log.Fatal("http error code:", resp.StatusCode)
		}
		ir = resp.Body
	} else {
		listFilePath := strings.TrimPrefix(args[0], "file://")
		var err error
		ir, err = os.Open(listFilePath)
		if err != nil {
			return errors.New("open image list file error: " + listFilePath)
		}
	}
	var images []string
	scanner := bufio.NewScanner(ir)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || len(line) == 0 {
			continue
		}
		images = append(images, line)
	}
	opts.copyImages(images, args[1], stdout)
	return
}

func (opts *copyOptions) copyImages(images []string, destRegistry string, stdout io.Writer) {
	if strings.HasPrefix(destRegistry, "registry-dir://") {
		registryPath := strings.TrimPrefix(destRegistry, "registry-dir://")
		log.Infof("starting registry on path %s ...\n", registryPath)
		var addr = "127.0.0.1:50001"
		go startRegistry(addr, registryPath)
		destRegistry = "registry://" + addr
	}
	var errImage, errImageWithError []string
	for _, src := range images {
		dest := destImage(src, destRegistry)
		log.Infof("copying image docker://%s to %s ...\n", src, dest)
		err := opts.run([]string{"docker://" + src, dest}, stdout)
		if err != nil {
			errArray := strings.Split(err.Error(), ":")
			errImageWithError = append(errImageWithError, src+" error: "+errArray[len(errArray)-1])
			errImage = append(errImage, src)
			log.Errorf("copy image error: %s\n", err)
		}
	}
	if len(errImage) > 0 {
		if log.GetLevel() == log.DebugLevel {
			log.Error("\nerror image list:\n", strings.Join(errImageWithError, "\n"))
		} else {
			log.Error("\nerror image list:\n", strings.Join(errImage, "\n"))
		}
	}
}
func destImage(src, dest string) (destImg string) {
	srcArray := strings.SplitN(strings.TrimPrefix(src, "docker://"), "/", 2)
	var err error
	if len(srcArray) == 1 {
		destImg, err = url.JoinPath(dest, srcArray...)
		if err != nil {
			log.Fatal("dest image path error", err)
		}
	} else {
		destImg, err = url.JoinPath(dest, srcArray[1:]...)
		if err != nil {
			log.Fatal("dest image path error", err)
		}
	}
	return strings.Replace(destImg, "registry://", "docker://", 1)

}

func overrideFlagFunc(f *pflag.Flag) {
	if strings.Contains(f.Name, "-tls-verify") {
		f.Value.Set("false")
	}
	if strings.Contains(f.Name, "insecure-policy") {
		f.Value.Set("true")
	}
}

func startRegistry(registryAddr, path string) {
	ctx := dcontext.WithVersion(dcontext.Background(), version.Version)
	defautConfig := &configuration.Configuration{}
	defautConfig.Log.Fields = map[string]interface{}{"service": "registry"}
	defautConfig.Log.AccessLog.Disabled = true
	defautConfig.Log.Level = "error"
	defautConfig.Storage = configuration.Storage{
		"cache":      configuration.Parameters{"blobdescriptor": "inmemory"},
		"filesystem": configuration.Parameters{"rootdirectory": path},
	}
	defautConfig.HTTP.Addr = registryAddr
	registry, err := registry.NewRegistry(ctx, defautConfig)
	if err != nil {
		log.Fatalln(err)
	}

	if err = registry.ListenAndServe(); err != nil {
		log.Fatalln(err)
	}
}
