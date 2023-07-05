<p align="center">
  <img width="300" height="300" src="images/logo.png">
</p>

<p align="center">
<a href="https://pkg.go.dev/github.com/mtnmunuklu/alterix"><img src="https://img.shields.io/badge/%F0%9F%93%9A%20godoc-pkg-informational.svg" alt="Go Doc"></a> <a href="https://goreportcard.com/report/github.com/mtnmunuklu/alterix"><img src="https://img.shields.io/badge/%F0%9F%93%9D%20goreport-A+-success.svg" alt="Go Report"></a> <a href="https://travis-ci.com/"><img src="https://img.shields.io/badge/%E2%9A%99%20build-X-success.svg" alt="Build Status"></a> 

# Alterix

Alterix is a tool that converts Sigma rules to the query language of CRYPTTECH's next-generation SIEM product.

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [Acknowledgement](#acknowledgement)
- [Sponsors](#sponsors)
- [License](#license)

## Overview

Sigma is an open-source project that provides a rule format and a set of tools for the creation and sharing of detection rules for security operations. CRYPTTECH's SIEM product uses a proprietary query language for searching through logs and identifying security events. Alterix serves as a bridge between the two, allowing security teams to leverage their existing Sigma rule sets with the advanced capabilities of CRYPTTECH's SIEM product.

## Installation

Alterix provides precompiled ZIP files for different platforms. You can download the appropriate ZIP file for your platform from the following links:

- [Windows](https://github.com/mtnmunuklu/alterix/releases/latest/download/alterix-windows-latest.zip)
- [Linux](https://github.com/mtnmunuklu/alterix/releases/latest/download/alterix-linux-latest.zip)
- [macOS](https://github.com/mtnmunuklu/alterix/releases/latest/download/alterix-macos-latest.zip)

Once you have downloaded the ZIP file for your platform, extract it to a directory of your choice. The extracted files will include the Alterix executable.

Make sure the directory containing the Alterix executable is added to your system's PATH environment variable, so you can run Alterix from any location in the command line.

That's it! You have successfully installed Alterix on your system. You can now proceed to the [Usage](#usage) section to learn how to use Alterix.

If you prefer to build Alterix from source, you can refer to the [Build Instructions](BUILD.md) for detailed steps on how to build and install it on your platform.

Please note that Alterix requires Go to be installed on your system. You can download and install Go from the official website: [https://golang.org/dl/](https://golang.org/dl/)


## Usage

To use Alterix, you will need Sigma rules and a configuration file for CRYPTTECH's SIEM product. Sigma rules are written in YAML format and can be found in the Sigma GitHub repository: https://github.com/Neo23x0/sigma/tree/master/rules

The configuration file for CRYPTTECH's SIEM product should be obtained from your system administrator.

To convert Sigma rules to the query language of CRYPTTECH's SIEM product, you can use the following command:

```alterix -filepath <path-to-rules> -config <path-to-config> [-json] [-output <output-directory>]```

The `filepath` flag specifies the location of the Sigma rules. This can be a file or directory path.

The `config` flag specifies the location of the configuration file for CRYPTTECH's SIEM product.

The `json` flag indicates that the output should be in JSON format.

The `output` flag specifies the directory where the output files should be written.

If the json flag is provided, Alterix will convert the Sigma rules to JSON format. If the output flag is provided, Alterix will save the output files to the specified directory. If neither flag is provided, the output will be displayed in the console.

## Contributing

Contributions to Alterix are welcome and encouraged! Please read the [contribution guidelines](contributing.md) before making any contributions to the project.

## Acknowledgements

This project was inspired by the work of Bradley Kemp, whose original repository can be found [here](https://github.com/bradleyjkemp/sigma-go). We would like to thank Bradley for his valuable contribution to the community and for making his code available to us.

We also want to thank the creators of the Sigma project, whose rule format we use in this project. More information about Sigma can be found [here](https://github.com/Neo23x0/sigma).

## Sponsors

We would like to express our gratitude to the following sponsors for their generous support:

<div align="center">
  <a href="https://github.com/tolgaakkapulu">
    <img src="https://github.com/tolgaakkapulu.png" alt="tolgaakkapulu" width="50" height="50" style="border-radius: 50%">
  </a>
  <a href="https://github.com/mkdemir">
    <img src="https://github.com/mkdemir.png" alt="mkdemir" width="50" height="50" style="border-radius: 50%">
  </a>
  <!-- Diğer sponsorlar -->
</div>


If you are interested in becoming a sponsor, please visit our [GitHub Sponsors](https://github.com/sponsors) page.

## License

Alterix is licensed under the MIT License. See [LICENSE](LICENSE) for the full text of the license.
