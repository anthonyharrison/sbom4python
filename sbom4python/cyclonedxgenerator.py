# Copyright (C) 2022 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import uuid

from sbom4python.license import LicenseScanner

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
    # VERSION = "0.1"
    PACKAGE_PREAMBLE = "SPDXRef-Package-"
    LICENSE_PREAMBLE = "LicenseRef-"

    def __init__(self, include_license: False, cyclonedx_format="json"):
        self.doc = []
        self.package_id = 0
        self.include_license = include_license
        self.license = LicenseScanner()
        self.format = cyclonedx_format
        if self.format == "xml":
            self.doc = []
        else:
            self.doc = {}
            self.component = []
        self.relationship = []
        self.sbom_complete = False

    def store(self, message):
        self.doc.append(message)

    def getBOM(self):
        if not self.sbom_complete:
            if self.format == "xml":
                self.store("<\\components>")
                # Now process dependencies
                self.store("<dependencies>")
                for element in self.relationship:
                    item=element["ref"]
                    self.store(f'<dependency ref="{item}">')
                    for depends in element["dependsOn"]:
                        self.store(f'<dependency ref="{depends}"/>')
                    self.store("<\\dependency>")
                self.store("<\\dependencies>")
                self.store("<\\bom>")
            else:
                # Add set of detected components to SBOM
                self.doc["components"] = self.component
                self.doc["dependencies"] = self.relationship
            self.sbom_complete = True
        return self.doc

    def generateDocumentHeader(self, project_name):
        if self.format == "xml":
            self.generateXMLDocumentHeader(project_name)
        else:
            self.generateJSONDocumentHeader(project_name)

    def generateJSONDocumentHeader(self, project_name):
        urn = "urn:uuid" + str(uuid.uuid4())
        self.doc = {
            "bomFormat": "CycloneDX",
            "specVersion": self.CYCLONEDX_VERSION,
            "serialNumber": urn,
            "version": 1,
        }

    def generateXMLDocumentHeader(self, project_name):
        urn = "urn:uuid" + str(uuid.uuid4())
        self.store("<?xml version='1.0' encoding='UTF-8'?>")
        self.store("<bom xmlns='http://cyclonedx.org/schema/bom/1.4'")
        self.store(f'serialNumber="{urn}"')
        self.store('version="1">')
        self.store("<components>")

    def generateRelationship(self, parent_id, package_id):
        # Check if entry exists. If so, update list of dependencies
        element_found = False
        for element in self.relationship:
            if element["ref"] == parent_id:
                # Update list of dependencies
                element["dependsOn"].append(package_id)
                element_found = True
                break
        if not element_found:
            # New item found
            dependency = dict()
            dependency["ref"] = parent_id
            dependency["dependsOn"] = [package_id]
            self.relationship.append(dependency)

    def generateComponent(self, id, type, name, supplier, version, licence):
        if self.format == "xml":
            self.generateXMLComponent(id, type, name, supplier, version, licence)
        else:
            self.generateJSONComponent(id, type, name, supplier, version, licence)

    def generateJSONComponent(self, id, type, name, supplier, version, identified_licence):
        component = dict()
        component["type"] = type
        component["bom-ref"] = id
        component["name"] = name
        component["version"] = version
        component["cpe"] = f"cpe:/a:{supplier}:{name}:{version}"
        if identified_licence != "":
            license = dict()
            license["id"] = self.license.find_license(identified_licence)
            item = dict()
            item["license"] = license
            component["licenses"] = [ item ]
        self.component.append(component)

    def generateXMLComponent(self, id, type, name, supplier, version, identified_licence):
        self.store(f'<component type="{type}" bom-ref="{id}">')
        self.store(f"<name>{name}<\\name>")
        self.store(f"<version>{version}<\\version>")
        self.store(f"<cpe>cpe:/a:{supplier}:{name}:{version}<\\cpe>")
        if identified_licence != "":
            self.store("<licenses>")
            self.store("<license>")
            self.store(f"<id>{self.license.find_license(identified_licence)}<\\id>")
            self.store("<\\license>")
            self.store("<\\licenses>")
        self.store("<\\component>")