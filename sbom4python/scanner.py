# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import pathlib
import re
import subprocess
import unicodedata

from lib4sbom.data.package import SBOMPackage
from lib4sbom.data.relationship import SBOMRelationship
from lib4sbom.license import LicenseScanner
from sbom4files.filescanner import FileScanner


class SBOMScanner:
    """
    Simple SBOM Generator for Python module.
    """

    def __init__(self, debug, include_file=False, exclude_license=False):
        self.record = []
        self.debug = debug
        self.include_file = include_file
        self.include_license = exclude_license
        self.sbom_package = SBOMPackage()
        self.sbom_relationship = SBOMRelationship()
        self.file_scanner = FileScanner()
        self.license = LicenseScanner()
        self.sbom_files = {}
        self.sbom_packages = {}
        self.sbom_relationships = []
        self.parent = "NOT_DEFINED"

    def set_parent(self, module):
        self.parent = f"Python-{module}"

    def run_program(self, command_line):
        # Remove any null bytes
        command_line = command_line.replace("\x00", "")
        # Split command line into individual elements
        params = command_line.split()
        res = subprocess.run(params, capture_output=True, text=True)
        return res.stdout.splitlines()

    def _format_supplier(self, supplier_info, include_email=True):
        # See https://stackoverflow.com/questions/1207457/convert-a-unicode-string-to-a-string-in-python-containing-extra-symbols
        # And convert byte object to a string
        name_str = (
            unicodedata.normalize("NFKD", supplier_info)
            .encode("ascii", "ignore")
            .decode("utf-8")
        )
        if " " in name_str:
            # Get names assumed to be at least two names <first> <surname>
            names = re.findall(r"[a-zA-Z\.\]+ [A-Za-z]+ ", name_str)
        else:
            # Handle case where only single name provided
            names = [name_str]
        # Get email addresses
        # Use RFC-5322 compliant regex (https://regex101.com/library/6EL6YF)
        emails = re.findall(
            r"((?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\]))",
            supplier_info,
        )
        supplier = " ".join(n for n in names)
        if include_email and len(emails) > 0:
            # Only one email can be specified, so choose last one
            supplier = supplier + "(" + emails[-1] + ")"
        return re.sub(" +", " ", supplier.strip())

    def process_module(self, module, parent="-"):
        if self.debug:
            print(f"Process Module {module}")
        out = self.run_program(f"pip show {module}")
        # If: module not found, no metadata returned
        if len(out) > 0:
            self.metadata = {}
            for line in out:
                entry = line.split(":")
                # If: this line contain an non empty entry delimited by ':'
                if (len(entry) == 2) and (entry[1] and not (entry[1].isspace())):
                    # then: store all data after keyword
                    self.metadata[entry[0]] = (
                        line.split(f"{entry[0]}:", 1)[1].strip().rstrip("\n")
                    )
            if self.debug:
                print(f"Metadata for {module}\n{self.metadata}")
            self.sbom_package.initialise()
            package = self.get("Name").lower().replace("_", "-")
            version = self.get("Version")
            self.sbom_package.set_name(package)
            self.sbom_package.set_property("language", "Python")
            self.sbom_package.set_version(version)
            if parent == "-":
                self.sbom_package.set_type("application")
            self.sbom_package.set_filesanalysis(self.include_file)
            license = self.license.find_license(self.get("License"))
            # Report license as reported by metadata. If not valid SPDX, report NOASSERTION
            if license != self.get("License"):
                self.sbom_package.set_licensedeclared("NOASSERTION")
            else:
                self.sbom_package.set_licensedeclared(license)
            # Report license if valid SPDX identifier
            self.sbom_package.set_licenseconcluded(license)
            # Add comment if metadata license was modified
            license_comment = ""
            if len(self.get("License")) > 0 and license != self.get("License"):
                license_comment = f"{self.get('Name')} declares {self.get('License')} which is not currently a valid SPDX License identifier or expression."
            # Report if license is deprecated
            if self.license.deprecated(license):
                deprecated_comment = f"{license} is now deprecated."
                if len(license_comment) > 0:
                    license_comment = f"{license_comment} {deprecated_comment}"
                else:
                    license_comment = deprecated_comment
            if len(license_comment) > 0:
                self.sbom_package.set_licensecomments(license_comment)
            supplier = self.get("Author") + " " + self.get("Author-email")
            if len(supplier.split()) > 3:
                self.sbom_package.set_supplier(
                    "Organization", self._format_supplier(supplier)
                )
            elif len(supplier) > 1:
                self.sbom_package.set_supplier(
                    "Person", self._format_supplier(supplier)
                )
            else:
                self.sbom_package.set_supplier("UNKNOWN", "NOASSERTION")
            if self.get("Home-page") != "":
                self.sbom_package.set_homepage(self.get("Home-page"))
            if self.get("Summary") != "":
                self.sbom_package.set_summary(self.get("Summary"))
            self.sbom_package.set_downloadlocation(
                f'https://pypi.org/project/{self.get("Name")}/{version}'
            )
            # External references
            self.sbom_package.set_externalreference(
                "PACKAGE-MANAGER", "purl", f"pkg:pypi/{package}@{version}"
            )
            if len(supplier) > 1:
                component_supplier = self._format_supplier(
                    supplier, include_email=False
                )
                self.sbom_package.set_externalreference(
                    "SECURITY",
                    "cpe23Type",
                    f"cpe:2.3:a:{component_supplier.replace(' ', '_').lower()}:{package}:{version}:*:*:*:*:*:*:*",
                )
            # Store package data
            self.sbom_packages[
                (self.sbom_package.get_name(), self.sbom_package.get_value("version"))
            ] = self.sbom_package.get_package()
            # Add relationship
            self.sbom_relationship.initialise()
            if parent != "-":
                self.sbom_relationship.set_relationship(
                    parent.lower(), "DEPENDS_ON", package
                )
            else:
                self.sbom_relationship.set_relationship(
                    self.parent, "DESCRIBES", package
                )
            self.sbom_relationships.append(self.sbom_relationship.get_relationship())
            if self.include_file:
                directory_location = f'{self.get("Location")}/{self.get("Name").lower().replace("-","_")}'
                file_dir = pathlib.Path(directory_location)
                if file_dir.exists():
                    filtered = [
                        x for x in file_dir.glob("**/*") if x.name.endswith(".py")
                    ]
                else:
                    # Module is only a single file
                    filtered = [
                        pathlib.Path(
                            f'{self.get("Location")}/{self.get("Name").lower().replace("-","_")}.py'
                        )
                    ]
                for entry in filtered:
                    if self.debug:
                        print(f"Analyse file in {entry}")
                    if self.file_scanner.scan_file(entry):
                        self.sbom_files[
                            self.file_scanner.get_name()
                        ] = self.file_scanner.get_file()
                        # Add relationship
                        self.sbom_relationship.initialise()
                        self.sbom_relationship.set_relationship(
                            package, "CONTAINS", self.file_scanner.get_name()
                        )
                        self.sbom_relationship.set_relationship_id(
                            self.sbom_package.get_value("id"),
                            self.file_scanner.get_value("id"),
                        )
                        self.sbom_relationship.set_target_type("file")
                        self.sbom_relationships.append(
                            self.sbom_relationship.get_relationship()
                        )
        elif self.debug:
            print(f"Module {module} not found")
        return len(out) > 0

    def get(self, attribute):
        return self.metadata.get(attribute, "").lstrip()

    def get_files(self):
        return self.sbom_files

    def get_packages(self):
        return self.sbom_packages

    def get_relationships(self):
        if self.debug:
            print(self.sbom_relationships)
        return self.sbom_relationships

    def get_parent(self):
        return self.parent

    def analyze(self, parent, dependencies):
        if len(dependencies) == 0:
            return
        else:
            for r in dependencies.split(","):
                if self.process_module(r, parent):
                    self.analyze(r.strip(), self.get("Requires"))

    def process_python_module(self, module_name):
        self.set_parent(module_name)
        if self.process_module(module_name):
            self.analyze(self.get("Name"), self.get("Requires"))
