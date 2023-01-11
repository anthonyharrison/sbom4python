# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import argparse
import sys
import textwrap
from collections import ChainMap

from sbom4python.dotgenerator import DOTGenerator
from sbom4python.generator import SBOMGenerator
from sbom4python.output import SBOMOutput
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
        "--exclude-license",
        action="store_true",
        help="suppress detecting the license of components",
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
        choices=["tag", "json", "xml"],
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
        "exclude_license": False,
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
    if args["sbom"] == "spdx":
        # XML not valid for SPDX
        if bom_format == "xml":
            bom_format = "tag"
    else:
        # Tag not valid for CycloneDX
        if bom_format == "tag":
            bom_format = "json"

    if args["debug"]:
        print("Exclude Licences:", args["exclude_license"])
        print("SBOM type:", args["sbom"])
        print("Format:", bom_format)
        print("Output file:", args["output_file"])
        print("Graph file:", args["graph"])
        print(f"Analysing {module_name}")

    sbom_scan = SBOMScanner(args["debug"])
    sbom_scan.set_module(module_name)
    sbom_scan.process_module()

    # If module not found, abort processing
    if not sbom_scan.valid_module():
        return -1

    sbom_scan.add(
        [
            "-",
            sbom_scan.get("Name"),
            sbom_scan.get("Version"),
            sbom_scan.get("Author") + " " + sbom_scan.get("Author-email"),
            sbom_scan.get("License"),
        ]
    )
    sbom_scan.analyze(sbom_scan.get("Name"), sbom_scan.get("Requires"))

    # Generate SBOM file
    sbom_gen = SBOMGenerator(
        args["exclude_license"], args["sbom"], bom_format, app_name, VERSION, "pypi"
    )
    sbom_out = SBOMOutput(args["output_file"], bom_format)

    if args["sbom"] == "spdx":
        sbom_gen.generate_spdx(module_name, sbom_scan.get_record())
        sbom_out.generate_output(sbom_gen.get_spdx())
    else:
        sbom_gen.generate_cyclonedx(module_name, sbom_scan.get_record())
        sbom_out.generate_output(sbom_gen.get_cyclonedx())

    if len(args["graph"]) > 0:
        sbom_dot = DOTGenerator()
        sbom_dot.generatedot(sbom_gen.get_relationships())
        dot_out = SBOMOutput(args["graph"], "dot")
        dot_out.generate_output(sbom_dot.getDOT())

    return 0


if __name__ == "__main__":
    sys.exit(main())
