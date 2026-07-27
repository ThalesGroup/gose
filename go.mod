module github.com/ThalesGroup/gose

go 1.25.0

toolchain go1.26.4

require (
	github.com/ThalesGroup/crypto11 v1.6.4
	github.com/google/uuid v1.6.0
	github.com/stretchr/testify v1.11.1
)

require (
	github.com/miekg/pkcs11 v1.1.2 // indirect
	github.com/thales-e-security/pool v0.0.2 // indirect
)

replace github.com/ThalesGroup/crypto11 v1.7.0-rc1 => ../crypto11.github.com.ThalesGroup

replace github.com/eclipse-keypont/pkcs11-go v1.0.0 => ../pkcs11-go

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/eclipse-keypont/pkcs11-go v1.0.0
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/objx v0.5.3 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
