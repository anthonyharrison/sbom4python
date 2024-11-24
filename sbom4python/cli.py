# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import argparse
import sys
import textwrap
from collections import ChainMap

from lib4sbom.generator import SBOMGenerator
from lib4sbom.output import SBOMOutput
from lib4sbom.sbom import SBOM
from sbom2dot.dotgenerator import DOTGenerator

from sbom4python.scanner import SBOMScanner
from sbom4python.version import VERSION

# CLI processing


def main(argv=None):

    argv = argv or sys.argv
    app_name = "sbom4python"
    parser = argparse.ArgumentParser(
        prog=app_name,
        description=textwrap.dedent(
            """
            SBOM4Python generates a Software Bill of Materials for the
            specified installed Python module identifying all of the dependent
            components which are explicity defined (typically via requirements.txt
            file) or implicitly as a hidden dependency.
            """
        ),
    )
    input_group = parser.add_argument_group("Input")
    input_group.add_argument(
        "-m",
        "--module",
        action="store",
        default="",
        help="identity of python module",
    )
    input_group.add_argument(
        "-r",
        "--requirement",
        action="store",
        default="",
        help="name of requirements.txt file",
    )
    input_group.add_argument(
        "--system",
        action="store_true",
        help="include all installed python modules within system",
    )
    input_group.add_argument(
        "--exclude-license",
        action="store_true",
        help="suppress detecting the license of components",
    )
    input_group.add_argument(
        "--include-file",
        action="store_true",
        default=False,
        help="include reporting files associated with module",
    )
    input_group.add_argument(
        "--include-service",
        action="store_true",
        default=False,
        help="include reporting of endpoints",
    )
    input_group.add_argument(
        "--use-pip",
        action="store_true",
        default=False,
        help="use pip for package management",
    )

    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "-d",
        "--debug",
        action="store_true",
        default=False,
        help="add debug information",
    )
    output_group.add_argument(
        "--sbom",
        action="store",
        default="spdx",
        choices=["spdx", "cyclonedx"],
        help="specify type of sbom to generate (default: spdx)",
    )
    output_group.add_argument(
        "--format",
        action="store",
        default="tag",
        choices=["tag", "json", "yaml"],
        help="specify format of software bill of materials (sbom) (default: tag)",
    )

    output_group.add_argument(
        "-o",
        "--output-file",
        action="store",
        default="",
        help="output filename (default: output to stdout)",
    )

    output_group.add_argument(
        "-g",
        "--graph",
        action="store",
        default="",
        help="filename for dependency graph",
    )

    parser.add_argument("-V", "--version", action="version", version=VERSION)

    defaults = {
        "module": "",
        "requirement": "",
        "include_file": False,
        "include_service": False,
        "exclude_license": False,
        "use_pip": False,
        "system": False,
        "output_file": "",
        "sbom": "spdx",
        "debug": False,
        "format": "tag",
        "graph": "",
    }

    raw_args = parser.parse_args(argv[1:])
    args = {key: value for key, value in vars(raw_args).items() if value}
    args = ChainMap(args, defaults)

    # Validate CLI parameters

    module_name = args["module"]

    # Ensure format is aligned with type of SBOM
    bom_format = args["format"]
    if args["sbom"] == "cyclonedx":
        # Only JSON format valid for CycloneDX
        if bom_format != "json":
            bom_format = "json"

    if args["debug"]:
        print("Exclude Licences:", args["exclude_license"])
        print("Include Files:", args["include_file"])
        print("Include Services:", args["include_service"])
        print("Use Pip:", args["use_pip"])
        print("Module", module_name)
        print("Requirements file", args["requirement"])
        print("System", args["system"])
        print("SBOM type:", args["sbom"])
        print("Format:", bom_format)
        print("Output file:", args["output_file"])
        print("Graph file:", args["graph"])
        print(f"Analysing {module_name}")

    sbom_scan = SBOMScanner(
        args["debug"],
        args["include_file"],
        args["exclude_license"],
        include_service=args["include_service"],
        use_pip=args["use_pip"],
    )

    if len(module_name) > 0:
        sbom_scan.process_python_module(module_name)
    elif args["system"]:
        sbom_scan.process_system()
    elif len(args["requirement"]) > 0:
        sbom_scan.process_requirements(args["requirement"])
    else:
        print("[ERROR] Nothing to process")
        return -1

    # Generate SBOM file
    python_sbom = SBOM()
    python_sbom.add_document(sbom_scan.get_document())
    python_sbom.add_files(sbom_scan.get_files())
    python_sbom.add_packages(sbom_scan.get_packages())
    python_sbom.add_relationships(sbom_scan.get_relationships())

    sbom_gen = SBOMGenerator(
        sbom_type=args["sbom"], format=bom_format, application=app_name, version=VERSION
    )
    sbom_gen.generate(
        project_name=sbom_scan.get_parent(),
        sbom_data=python_sbom.get_sbom(),
        filename=args["output_file"],
    )

    if len(args["graph"]) > 0:
        sbom_dot = DOTGenerator(python_sbom.get_sbom()["packages"])
        sbom_dot.generatedot(python_sbom.get_sbom()["relationships"])
        dot_out = SBOMOutput(args["graph"], "dot")
        dot_out.generate_output(sbom_dot.getDOT())

    return 0


if __name__ == "__main__":
    sys.exit(main())
