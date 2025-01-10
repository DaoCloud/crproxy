module github.com/daocloud/crproxy

go 1.23

toolchain go1.23.4

require (
	github.com/denverdino/aliyungo v0.0.0
	github.com/distribution/reference v0.6.0
	github.com/docker/distribution v2.8.2+incompatible
	github.com/emicklei/go-restful-openapi/v2 v2.11.0
	github.com/emicklei/go-restful/v3 v3.12.1
	github.com/go-openapi/spec v0.20.9
	github.com/go-sql-driver/mysql v1.8.1
	github.com/google/go-containerregistry v0.20.2
	github.com/gorilla/handlers v1.5.2
	github.com/huaweicloud/huaweicloud-sdk-go-obs v3.24.6+incompatible
	github.com/opencontainers/go-digest v1.0.0
	github.com/spf13/cobra v1.8.1
	github.com/wzshiming/cmux v0.4.2
	github.com/wzshiming/geario v0.0.0-20240308093553-a996e3817533
	github.com/wzshiming/hostmatcher v0.0.3
	github.com/wzshiming/httpseek v0.1.0
	github.com/wzshiming/imc v0.0.0-20250106051804-1cb884b5184a
	golang.org/x/crypto v0.28.0
)

replace (
	github.com/denverdino/aliyungo => github.com/wzshiming/aliyungo v0.0.0-20241126040137-4b8c22b50cd3
	github.com/docker/distribution => github.com/distribution/distribution v2.8.3+incompatible
)

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/aws/aws-sdk-go v1.48.10 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/docker/cli v27.1.1+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.7.0 // indirect
	github.com/docker/go-metrics v0.0.1 // indirect
	github.com/docker/libtrust v0.0.0-20150114040149-fa567046d9b1 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-openapi/jsonpointer v0.19.5 // indirect
	github.com/go-openapi/jsonreference v0.20.0 // indirect
	github.com/go-openapi/swag v0.19.15 // indirect
	github.com/gorilla/mux v1.8.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/mailru/easyjson v0.7.6 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/opencontainers/image-spec v1.1.0-rc3 // indirect
	github.com/opentracing/opentracing-go v1.2.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus/client_golang v1.19.1 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.55.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/rogpeppe/go-internal v1.12.0 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/wzshiming/trie v0.3.1 // indirect
	golang.org/x/net v0.30.0 // indirect
	golang.org/x/sys v0.26.0 // indirect
	golang.org/x/text v0.19.0 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)
