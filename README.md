# SBOM4Python

The SBOM4Python is a free, open source tool to generate a
SBOM (Software Bill of Materials) for an installed Python module in a number of formats including
[SPDX](https://www.spdx.org) and [CycloneDX](https://www.cyclonedx.org).
It identifies all of the dependent components which are
explicity defined (typically via requirements.txt file) or implicitly as a
hidden dependency.

It can also be used to create a SBOM from a requirements.txt file. In this case no transitive components will be identified.

It is intended to be used as part of a continuous integration system to enable accurate records of SBOMs to be maintained
and also to support subsequent audit needs to determine if a particular component (and version) has been used.

## Installation

To install use the following command:

`pip install sbom4python`

Alternatively, just clone the repo and install dependencies using the following command:

`pip install -U -r requirements.txt`

The tool requires Python 3 (3.7+). It is recommended to use a virtual python environment especially
if you are using different versions of python. `virtualenv` is a tool for setting up virtual python environments which
allows you to have all the dependencies for the tool set up in a single environment, or have different environments set
up for testing using different versions of Python.

### Issues with Windows Installation

When running on Windows, if you get the following error

`ImportError: failed to find libmagic.  Check your installation`

This is because of a mismatch with the installation of the magic library. To resolve, please issue the following commands

```bash
pip uninstall python-magic
pip uninstall python-magic-bin

pip install python-magic
pip install python-magic-bin
```


## Usage

```bash
usage: sbom4python [-h] [-m MODULE] [--system] [--exclude-license] [--include-file] [-d] [--sbom {spdx,cyclonedx}] [--format {tag,json,yaml}] [-o OUTPUT_FILE] [-g GRAPH] [-V]

SBOM4Python generates a Software Bill of Materials for the specified installed Python module identifying all of the dependent components which are explicity defined (typically via requirements.txt file)
or implicitly as a hidden dependency.

options:
  -h, --help            show this help message and exit
  -V, --version         show program's version number and exit

Input:
  -m MODULE, --module MODULE
                        identity of python module
  -r REQUIREMENT, --requirement REQUIREMENT
                        name of requirements.txt file
  --system              include all installed python modules within system
  --exclude-license     suppress detecting the license of components
  --include-file        include reporting files associated with module

Output:
  -d, --debug           add debug information
  --sbom {spdx,cyclonedx}
                        specify type of sbom to generate (default: spdx)
  --format {tag,json,yaml}
                        specify format of software bill of materials (sbom) (default: tag)
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        output filename (default: output to stdout)
  -g GRAPH, --graph GRAPH
                        filename for dependency graph
```
						
## Operation

The `--module` option is used to identify the Python module. The `--system` option is used to indicate that the SBOM is to include all installed
Python modules. The `--requirement` option is used to create an SBOM from a requirements.txt file. In this case, no transitive dependencies will be
identified if this option is specified.

One of `--module`,  `--requirement` or `--system` must be specified. If multiple options are specified, the order of priority is `--module`, `--system` and `--requirement`.

The `--sbom` option is used to specify the format of the generated SBOM (the default is SPDX). The `--format` option
can be used to specify the formatting of the SBOM (the default is Tag Value format for a SPDX SBOM). JSON format is supported for both
SPDX and CycloneDX SBOMs).

The `--output-file` option is used to control the destination of the output generated by the tool. The
default is to report to the console but can be stored in a file (specified using `--output-file` option).

The tool attempts to determine the license of each module. This can be suppressed using the `--exclude-license` option in
which case all licences are reported as 'NOASSERTION'.

The tool can optionally include the files associated with the installed module. This can be specified using the `--include-file` option. As the filenames are
relative to the directory in which the tool is invoked, it is recommended that the tool is launched in a directory where the source files are available.

The `--graph` option is used to generate a dependency graph of the components within the SBOM. The format of the graph
file is compatible with the [DOT language](https://graphviz.org/doc/info/lang.html) used by the
[GraphViz](https://graphviz.org/) application.

## Licence

Licenced under the Apache 2.0 Licence.

The tool uses a local copy of the [SPDX Licenses List](https://github.com/spdx/license-list-data) which is released under
[Creative Commons Attribution 3.0 (CC-BY-3.0)](http://creativecommons.org/licenses/by/3.0/).

## Limitations

This tool is meant to support software development and security audit functions. However the usefulness of the tool is dependent on the SBOM data
which is provided to the tool. Unfortunately, the tool is unable to determine the validity or completeness of such a SBOM file; users of the tool
are therefore reminded that they should assert the quality of any data which is provided to the tool.

The `--requirement` option will only process modules in the file which have pinned versions. Any modules which not specify a version will be ignored.

When processing and validating licenses, the application will use a set of synonyms to attempt to map some license identifiers to the correct [SPDX License Identifiers](https://spdx.org/licenses/). However, the
user of the tool is reminded that they should assert the quality of any data which is provided by the tool particularly where the license identifier has been modified.

Whilst [PURL](https://github.com/package-url/purl-spec) and [CPE](https://nvd.nist.gov/products/cpe) references are automatically generated for each Python module, the accuracy
of such references cannot be guaranteed as they are dependent on the validity of the data associated with the Python module.

Network access is required to populate some of the package metadata.

## Feedback and Contributions

Bugs and feature requests can be made via GitHub Issues.
