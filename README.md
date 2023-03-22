<p align="center">
  <img width="300" height="300" src="images/logo.png">
</p>

<p align="center">
<a href="https://pkg.go.dev/"><img src="https://img.shields.io/badge/%F0%9F%93%9A%20godoc-pkg-informational.svg" alt="Go Doc"></a> <a href="https://goreportcard.com/"><img src="https://img.shields.io/badge/%F0%9F%93%9D%20goreport-X+-success.svg" alt="Go Report"></a> <a href="https://gocover.io/"><img src="https://img.shields.io/badge/%F0%9F%94%8E%20gocover-X%25-success.svg" alt="Coverage Status"></a> <a href="https://travis-ci.com/"><img src="https://img.shields.io/badge/%E2%9A%99%20build-X-success.svg" alt="Build Status"></a> 

# Alterix

Alterix is a tool that converts Sigma rules to the query language of CRYPTTECH's next-generation SIEM product.

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [Acknowledgement](#acknowledgement)
- [License](#license)

## Overview

Sigma is an open-source project that provides a rule format and a set of tools for the creation and sharing of detection rules for security operations. CRYPTTECH's SIEM product uses a proprietary query language for searching through logs and identifying security events. Alterix serves as a bridge between the two, allowing security teams to leverage their existing Sigma rule sets with the advanced capabilities of CRYPTTECH's SIEM product.

## Installation

To use Alterix, you will need to have Go installed on your system. You can download and install Go from the official website: https://golang.org/dl/

Once Go is installed, you can install Alterix using the following command:

```go get github.com/mtnmunuklu/alterix```


This will download and install the Alterix tool to your $GOPATH/bin directory.

## Usage

To use Alterix, you will need Sigma rules and a configuration file for CRYPTTECH's SIEM product. Sigma rules are written in YAML format and can be found in the Sigma GitHub repository: https://github.com/Neo23x0/sigma/tree/master/rules

The configuration file for CRYPTTECH's SIEM product should be obtained from your system administrator.

To convert Sigma rules to the query language of CRYPTTECH's SIEM product, you can use the following command:
```alterix -filepath <path-to-rules> -config <path-to-config>```


The `filepath` flag specifies the location of the Sigma rules. This can be a file or directory path.

The `config` flag specifies the location of the configuration file for CRYPTTECH's SIEM product.

Alterix will output the queries in the query language of CRYPTTECH's SIEM product to the console.

## Contributing

Contributions to Alterix are welcome and encouraged! To contribute to the project, please follow these steps:

1. Fork the repository.
2. Create a new branch for your changes.
3. Make your changes and commit them.
4. Push your changes to your fork.
5. Submit a pull request.

Please make sure your code follows the Go code style guidelines and includes appropriate tests.

## Acknowledgements

This project was inspired by the work of Bradley Kemp, whose original repository can be found [here](https://github.com/bradleyjkemp/sigma-go). We would like to thank Bradley for his valuable contribution to the community and for making his code available to us.

We also want to thank the creators of the Sigma project, whose rule format we use in this project. More information about Sigma can be found [here](https://github.com/Neo23x0/sigma).

## License

Alterix is licensed under the MIT License. See [LICENSE](LICENSE) for the full text of the license.

## Buy me a coffee

Whether you use this project, learn from it or like it, please consider supporting me with a coffee so I can spend more time on open source projects like this.

<a href="https://www.buymeacoffee.com/mtnmunuklu" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 60px !important;width: 217px !important;" ></a>

