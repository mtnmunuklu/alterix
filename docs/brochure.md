# Alterix: Empower Your Security Operations

Unlock the Power of Sigma Rules with Alterix

Supercharge your security operations with Alterix, the ultimate tool that seamlessly converts Sigma rules to CRYPTTECH's advanced SIEM query language. Say goodbye to manual translations and hello to enhanced threat detection and response.

## Why Choose Alterix?

- **Maximize Rule Set Potential**: Don't let your Sigma rules gather dust! Alterix empowers you to leverage the full potential of your rule sets by seamlessly integrating them with CRYPTTECH's advanced SIEM product.

- **Advanced Threat Detection**: Stay one step ahead of cyber threats with CRYPTTECH's powerful log search and security event identification capabilities. Alterix bridges the gap between Sigma rules and CRYPTTECH's advanced SIEM, giving you unparalleled threat visibility.

- **Effortless Workflow**: Save time and effort by using Alterix to adapt your existing Sigma rules to CRYPTTECH's query language. No more manual rewriting or reinventing the wheel. Streamline your workflow and focus on what matters most - securing your organization.

## Simple Installation, Powerful Results

Getting started with Alterix is a breeze. Here's how:

1. **Download**: Get the Alterix ZIP file for your platform from our GitHub repository.

   - [Windows](https://github.com/mtnmunuklu/alterix/releases/latest/download/alterix-windows-latest.zip)
   - [Linux](https://github.com/mtnmunuklu/alterix/releases/latest/download/alterix-linux-latest.zip)
   - [macOS](https://github.com/mtnmunuklu/alterix/releases/latest/download/alterix-macos-latest.zip)

2. **Extract**: Unzip the downloaded file to your preferred directory.

3. **Configure**: Add the Alterix executable directory to your system's PATH environment variable. This ensures easy access to Alterix from anywhere in the command line.

4. **Empower Your Security Operations**: Congratulations! You're now equipped with Alterix. Start converting your Sigma rules and harness the power of CRYPTTECH's advanced SIEM.

## Simple Steps, Powerful Conversion

With Alterix, converting Sigma rules to CRYPTTECH's query language is a breeze. Here's how:

1. **Access Sigma Rules**: Obtain Sigma rules written in YAML format from the [Sigma GitHub repository](https://github.com/Neo23x0/sigma/tree/master/rules).

2. **Configuration**: Obtain the configuration file for CRYPTTECH's SIEM product from your system administrator.

3. **Command Line**: Open your command line interface and run the following command:
    ```
    alterix -filepath <path-to-rules> -config <path-to-config> [-json]  [-output <output-directory>]
    ```

    - Replace `<path-to-rules>` with the location of the Sigma rules file or    directory.
    - Replace `<path-to-config>` with the location of the CRYPTTECH SIEM    configuration file.
    - Use the `-json` flag to output the converted rules in JSON format.
    - Use the `-output <output-directory>` flag to specify the directory for     the output files.

4. **Conversion Magic**: Sit back, relax, and let Alterix perform its magic. Watch as your Sigma rules seamlessly transform into CRYPTTECH's powerful query language. Customize your output options and let Alterix do the heavy lifting.

## Join the Alterix Community

Become a part of the Alterix community and shape the future of security operations. We welcome contributions and invite you to read our [contribution guidelines](contributing.md) to get started.

## Get Started Today

Don't miss out on the power of Alterix. Download, convert, and take your security operations to the next level. Visit our GitHub repository to get started: [Alterix on GitHub](https://github.com/mtnmunuklu/alterix)