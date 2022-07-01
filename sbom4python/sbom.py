# Copyright (C) 2022 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import argparse
import subprocess
import sys
import textwrap
import uuid
from datetime import datetime
from collections import ChainMap

VERSION = "0.1a"


class SPDXGenerator:
    """
    Generate SPDX Tag/Value SBOM.
    """

    SPDX_VERSION = "SPDX-2.2"
    DATA_LICENCE = "CC0-1.0"
    SPDX_NAMESPACE = "http://spdx.org/spdxdocs/"
    SPDX_LICENCE_VERSION = "3.9"
    SPDX_PROJECT_ID = "SPDXRef-DOCUMENT"
    NAME = "SBOM4PYTHON_Generator"
    VERSION = "0.1"
    PACKAGE_PREAMBLE = "SPDXRef-Package-"
    LICENSE_PREAMBLE = "LicenseRef-"

    def __init__(self, include_license: False):
        self.doc = []
        self.package_id = 0
        self.include_license = include_license
        self.licence = LicenceScanner()
        self.relationship = []

    def show(self, message):
        self.doc.append(message)

    def getBOM(self):
        return self.doc

    def generateTag(self, tag, value):
        self.show(tag + ": " + value)

    def generateComment(self, comment):
        self.show("##### " + comment)

    def generateTime(self):
        # Generate data/time label in format YYYY-MM-DDThh:mm:ssZ
        return datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    def generateDocumentHeader(self, project_name):
        # SPDX Document Header
        self.generateTag("SPDXVersion", self.SPDX_VERSION)
        self.generateTag("DataLicense", self.DATA_LICENCE)
        self.generateTag("SPDXID", self.SPDX_PROJECT_ID)
        # Project name mustn't have spaces in. Covert spaces to '-'
        self.generateTag("DocumentName", project_name.replace(" ", "-"))
        self.generateTag(
            "DocumentNamespace",
            self.SPDX_NAMESPACE
            + project_name.replace(" ", "-")
            + "-"
            + str(uuid.uuid4()),
        )
        self.generateTag("LicenseListVersion", self.SPDX_LICENCE_VERSION)
        self.generateTag("Creator: Tool", self.NAME + "-" + self.VERSION)
        self.generateTag("Created", self.generateTime())
        self.generateTag(
            "CreatorComment",
            "<text>This document has been automatically generated.</text>",
        )
        return self.SPDX_PROJECT_ID

    def package_ident(self, id):
        # Only add preamble if not parent document
        if id != self.SPDX_PROJECT_ID:
            return self.PACKAGE_PREAMBLE + str(id)
        return str(id)

    def licence_ident(self, licence):
        if not self.include_license:
            if licence != "UNKNOWN":
                derived_licence = self.licence.find_licence(licence)
                if derived_licence != "UNKNOWN":
                    #return self.LICENSE_PREAMBLE + derived_licence
                    return derived_licence
        return "NOASSERTION"

    def generatePackageDetails(self, package, id, version, supplier, licence, parent_id, relationship):
        self.generateTag("\nPackageName", package)
        package_id = self.package_ident(id)
        self.generateTag("SPDXID", package_id)
        # Attempt to detect an organization
        if len(supplier.split()) > 2:
            self.generateTag("PackageSupplier: Organization", supplier)
        else:
            self.generateTag("PackageSupplier: Person", supplier)
        self.generateTag("PackageVersion", version)
        self.generateTag("PackageDownloadLocation", "NOASSERTION")
        self.generateTag("FilesAnalyzed", "false")
        self.generateComment("Reported licence " + licence)
        self.generateTag("PackageLicenseConcluded", self.licence_ident(licence))
        self.generateTag("PackageLicenseDeclared", self.licence_ident(licence))
        self.generateTag("PackageCopyrightText", "NOASSERTION")
        self.generateRelationship(self.package_ident(parent_id), package_id, relationship)

    def generateRelationship(self, from_id, to_id, relationship_type):
        #self.generateTag("\nRelationship", from_id + relationship_type + to_id)
        self.relationship.append([from_id, to_id, relationship_type])

    def showRelationship(self):
        self.relationship.sort()
        for r in self.relationship:
            self.generateTag("Relationship", r[0] + r[2] + r[1])

class CycloneDXGenerator:
    """
    Generate CycloneDX JSON SBOM.
    """
    import uuid

    CYCLONEDX_VERSION = "1.4"
    DATA_LICENCE = "CC0-1.0"
    SPDX_NAMESPACE = "http://spdx.org/spdxdocs/"
    SPDX_LICENCE_VERSION = "3.9"
    SPDX_PROJECT_ID = "SPDXRef-DOCUMENT"
    NAME = "SBOM4PYTHON_Generator"
    VERSION = "0.1"
    PACKAGE_PREAMBLE = "SPDXRef-Package-"
    LICENSE_PREAMBLE = "LicenseRef-"

    def __init__(self):
        self.doc = []
        self.package_id = 0
        # self.include_license = include_license
        # self.licence = LicenceScanner()
        # self.relationship = []
        self.doc = None
        self.component = []
        self.bom = None

    def show(self, message):
        self.doc.append(message)

    def getBOM(self):
        if self.bom is None:
            self.doc["components"] = self.component
            self.bom = True
        #json.dump(data, f, indent=2)
        return self.doc

    def generateTag(self, tag, value):
        self.show(tag + ": " + value)

    def geneateDocumentHeader(self, project_name):
        self.show()

        # Generate file
        #urn = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"
        urn = "urn:uuid" + uuid.uuid4()
        self.doc = {"bomFormat": "CycloneDX", "specVersion": self.CYCLONEDX_VERSION, "serialNumber": urn,"version": 1}

    def generateComponent(self, type, name, supplier, version):
        component = dict()
        component["type"] =  type
        component["name"] = name
        component["version"] = version
        component["cpe"] = f"cpe:/a:{supplier}:{name}:{version}"
        self.component.append(component)


class SBOMGenerator:
    """
    Simple SBOM File Generator.
    """

    def __init__(self, include_license: False):
        self.bom = SPDXGenerator(include_license)

    def generate_spdx(self, project_name, packages):
        project_id = self.bom.generateDocumentHeader(project_name)
        #self.bom.show("\n\n##### Package")
        # Process list of packages
        id = 1
        package_set = {}
        for package in packages:
            product = package[1]
            version = package[2]
            supplier = package[3]
            licence = package[4]
            parent = package[0].lower()
            if product not in package_set:
                package_set[product] = str(id) + "-" + product
                if parent == "-":
                    parent_id = project_id
                    relationship = " DESCRIBES "
                else:
                    parent_id = package_set[parent]
                    relationship = " CONTAINS "
                self.bom.generatePackageDetails(
                    product, str(id) + "-" + product, version, supplier, licence, parent_id, relationship
                )
                id = id + 1
            else:
                if parent == "-":
                    parent_id = project_id
                    relationship = " DESCRIBES "
                else:
                    relationship = " CONTAINS "
                    try:
                        parent_id = package_set[parent]
                    except:
                        #parent_id = package_set[parent.replace('_','-')]
                    #finally:
                        print("Unable to find parent id:", parent, "for product", product)
                        parent_id = None
                if parent_id is not None:
                    self.bom.generateRelationship(self.bom.package_ident(parent_id), self.bom.package_ident(package_set[product]), relationship)

    def show_spdx(self):
        self.bom.showRelationship()
        for line in self.bom.getBOM():
            print(line)

    def get_spdx(self):
        return self.bom.getBOM()

class SBOMScanner:
    """
    Simple SBOM File Scanner.
    """

    def __init__(self):
        self.record = []

    def set_module(self, module):
        self.module = module

    def run_program(self, command_line):
        # Remove any null bytes
        command_line = command_line.replace("\x00", "")
        # print (command_line)
        # Split command line into individual elements
        params = command_line.split()
        # print(params)
        res = subprocess.run(params, capture_output=True, text=True)
        # print(res)
        return res.stdout.splitlines()

    def process_module(self):
        out = self.run_program(f"pip show {self.module}")
        self.metadata = {}
        for line in out:
            entry = line.split(":")
            self.metadata[entry[0]] = entry[1].lstrip()

    def add(self, entry):
        if entry not in self.record:
            self.record.append(entry)

    def get(self, attribute):
        if attribute in self.metadata:
            return self.metadata[attribute].lstrip()
        return ""

    def get_record(self):
        return self.record

    def show_record(self):
        for r in self.record:
            print (r)

    def doit(self, parent, dependencies):
        if len(dependencies) == 0:
            return
        else:
            for r in dependencies.split(","):
                self.set_module(r)
                self.process_module()
                # print("Parent", parent)
                # print("Name", s.get("Name"))
                # print("Version", s.get("Version"))
                # print("License", s.get("License"))
                self.add([parent.lower().replace('_','-'), self.get("Name").lower().replace('_','-'), self.get("Version"), self.get("Author"), self.get("License")])
                self.doit(r.strip(),self.get("Requires"))

class LicenceScanner:

    THRESHOLD = 95

    def __init__(self):
        # Load licences
        #self.licences = [["Apache 2.0", "Apache_2.0"], ["MIT", "MIT"]]

        import json
        licfile = open("spdx_licence.json")
        self.licences = json.load(licfile)
        # for lic in self.licences["licenses"]:
        #     print (f'{lic["name"]} , {lic["licenseId"]}')

        self.threshold = self.THRESHOLD

    def get_threshold(self):
        return self.threshold

    def set_threshold(self, value):
        self.threshold = value

    def find_licence(self, licence):
        # Search list of licences and find best match which meets threshold
        # Uses fuzzy matching
        import Levenshtein as lev
        from fuzzywuzzy import fuzz
        # Distance = lev.distance(Str1.lower(), Str2.lower()),
        # print(Distance)
        # Ratio = lev.ratio(Str1.lower(), Str2.lower())
        # print(Ratio)
        default_licence = "UNKNOWN"
        best_ratio = 0
        for lic in self.licences["licenses"]:
            ratio = int(lev.ratio(lic["name"].lower(), licence.lower()) * 100.0)
            ratio_spdx = int(lev.ratio(lic["licenseId"].lower(), licence.lower()) * 100.0)
            ratio_fuzz = fuzz.ratio(lic["name"].lower(), licence.lower())
            ratio_fuzz2 = fuzz.partial_ratio(lic["name"].lower(), licence.lower())
            #max_ratio = max([ratio, ratio_spdx, ratio_fuzz, ratio_fuzz2])
            #max_ratio = max([ratio, ratio_spdx])
            max_ratio = max([ratio_fuzz, ratio_spdx, ratio_fuzz2])
            if max_ratio > self.threshold:
                # Add licence
                if max_ratio > best_ratio:
                    #print(licence, lic['name'], ratio, ratio_spdx, ratio_fuzz, ratio_fuzz2, max_ratio)
                    best_ratio = max_ratio
                    #print(licence, lic["name"], ratio)
                    default_licence = lic["licenseId"]
                    #if best_ratio == 100:
                    #    break
        return default_licence

# CLI processing
def main(argv = None):

    argv = argv or sys.argv
    parser = argparse.ArgumentParser(
        prog="sbom4python",
        description=textwrap.dedent(
            """
            The SBOM4Python generates a Software Bill of Materials for the specified installed
            Python module identifying all of the dependent components which are explicity defined
            (typically via requirements.txt file) or implicitly as a hidden dependency.
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
        "-q", "--quiet", action="store_true", default=False, help="suppress output"
    )
    output_group.add_argument(
        "--sbom",
        action="store",
        default="spdx",
        choices=["spdx", "cyclonedx"],
        help="specify type of software bill of materials (sbom) (default: spdx)"
    )
    output_group.add_argument(
        "-o",
        "--output-file",
        action="store",
        default="",
        help="output filename (default: output to stdout)",
    )

    parser.add_argument("-V", "--version", action="version", version=VERSION)

    defaults = {
        "module": "",
        "exclude_license": False,
        "output_file": "",
        "sbom" : "spdx",
        "quiet" : False,
    }

    raw_args = parser.parse_args(argv[1:])
    args = {key: value for key, value in vars(raw_args).items() if value}
    args = ChainMap(args, defaults)

    # TODO Validate CLI parameters
    # print ("Exclude Licences", args["exclude_license"])
    # print ("SBOM type", args["sbom"])
    # print ("Output file", args["output_file"])

    module_name = args["module"]
    #print (f"Analysing {module_name}")
    s = SBOMScanner()
    s.set_module(module_name)
    s.process_module()

    s.add(["-", s.get("Name"), s.get("Version"), s.get("Author"), s.get("License")])
    s.doit(s.get("Name"), s.get("Requires"))

    # Generate SPDX format file
    sbom_gen = SBOMGenerator(args["exclude_license"])
    #s.show_record()
    sbom_gen.generate_spdx(module_name, s.get_record())
    sbom_gen.show_spdx()
    return 0

sys.exit(main())

