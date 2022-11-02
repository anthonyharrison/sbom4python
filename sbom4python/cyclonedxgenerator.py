# Copyright (C) 2022 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import uuid
from datetime import datetime

from sbom4python.license import LicenseScanner


class CycloneDXGenerator:
    """
    Generate CycloneDX SBOM.
    """

    CYCLONEDX_VERSION = "1.4"
    DATA_LICENCE = "CC0-1.0"
    SPDX_NAMESPACE = "http://spdx.org/spdxdocs/"
    SPDX_PROJECT_ID = "SPDXRef-DOCUMENT"
    NAME = "SBOM4PYTHON_Generator"
    PACKAGE_PREAMBLE = "SPDXRef-Package-"
    LICENSE_PREAMBLE = "LicenseRef-"

    def __init__(
        self,
        include_license: False,
        cyclonedx_format="json",
        application="sbom4python",
        version="0.1",
    ):
        self.doc = []
        self.package_id = 0
        self.include_license = include_license
        self.license = LicenseScanner()
        self.format = cyclonedx_format
        self.application = application
        self.application_version = version
        if self.format == "xml":
            self.doc = []
        else:
            self.doc = {}
            self.component = []
        self.relationship = []
        self.sbom_complete = False
        self.include_purl = False

    def set_purl(self, package_manager):
        self.include_purl = True
        self.package_manager = package_manager

    def store(self, message):
        self.doc.append(message)

    def getBOM(self):
        if not self.sbom_complete:
            if self.format == "xml":
                self.store("</components>")
                # Now process dependencies
                self.store("<dependencies>")
                for element in self.relationship:
                    item = element["ref"]
                    self.store(f'<dependency ref="{item}">')
                    for depends in element["dependsOn"]:
                        self.store(f'<dependency ref="{depends}"/>')
                    self.store("</dependency>")
                self.store("</dependencies>")
                self.store("</bom>")
            else:
                # Add set of detected components to SBOM
                self.doc["components"] = self.component
                self.doc["dependencies"] = self.relationship
            self.sbom_complete = True
        return self.doc

    def getRelationships(self):
        # Only required for relationships graph. Reformat data
        relationship_graph = []
        for relationship in self.relationship:
            from_id = relationship["ref"]
            if len(relationship_graph) == 0:
                # Add root element
                relationship_graph.append([from_id, from_id, " DESCRIBES "])
            for depend in relationship["dependsOn"]:
                relationship_graph.append([from_id, depend, " CONTAINS "])
        return relationship_graph

    def generateTime(self):
        # Generate data/time label in format YYYY-MM-DDThh:mm:ssZ
        return datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    def generateDocumentHeader(self, project_name):
        if self.format == "xml":
            self.generateXMLDocumentHeader(project_name)
        else:
            self.generateJSONDocumentHeader(project_name)

    def generateJSONDocumentHeader(self, project_name):
        urn = "urn:uuid" + str(uuid.uuid4())
        self.doc = {
            "$schema": "http://cyclonedx.org/schema/bom-1.4.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": self.CYCLONEDX_VERSION,
            "serialNumber": urn,
            "version": 1,
            "metadata": {
                "timestamp": self.generateTime(),
                "tools": [
                    {
                        "name": self.application,
                        "version": self.application_version,
                    }
                ],
            },
        }

    def generateXMLDocumentHeader(self, project_name):
        urn = "urn:uuid" + str(uuid.uuid4())
        self.store("<?xml version='1.0' encoding='UTF-8'?>")
        self.store("<bom xmlns='http://cyclonedx.org/schema/bom/1.4'")
        self.store(f'serialNumber="{urn}"')
        self.store('version="1">')
        self.store("<metadata>")
        self.store(f"<timestamp>{self.generateTime()}</timestamp>")
        self.store("<tools>")
        self.store(f"<name>{self.application}</name>")
        self.store(f"<version>{self.application_version}</version>")
        self.store("</tools>")
        self.store("</metadata>")
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

    def generateJSONComponent(
        self, id, type, name, supplier, version, identified_licence
    ):
        component = dict()
        component["type"] = type
        component["bom-ref"] = id
        component["name"] = name
        component["version"] = version
        if supplier != "UNKNOWN" and len(supplier) > 0:
            component["author"] = supplier
            # Supplier name mustn't have spaces in. Covert spaces to '_'
            component["cpe"] = f"cpe:/a:{supplier.replace(' ', '_').lower()}:{name}:{version}"
        if identified_licence != "":
            license_id = self.license.find_license(identified_licence)
            # Only include if valid license
            if license_id != "UNKNOWN":
                license = dict()
                license["id"] = license_id
                license_url = self.license.get_license_url(license["id"])
                if license_url is not None:
                    license["url"] = license_url
                item = dict()
                item["license"] = license
                component["licenses"] = [item]
        if self.include_purl:
            component["purl"] = f"pkg:{self.package_manager}/{name}@{version}"
        self.component.append(component)

    def generateXMLComponent(
        self, id, type, name, supplier, version, identified_licence
    ):
        self.store(f'<component type="{type}" bom-ref="{id}">')
        self.store(f"<name>{name}</name>")
        self.store(f"<version>{version}</version>")
        if supplier != "UNKNOWN" and len(supplier) > 0:
            self.store(f"<author>{supplier}</supplier>")
            # Supplier name mustn't have spaces in. Covert spaces to '_'
            self.store(f"<cpe>cpe:/a:{supplier.replace(' ', '_').lower()}:{name}:{version}</cpe>")
        if identified_licence != "":
            license_id = self.license.find_license(identified_licence)
            # Only include if valid license
            if license_id != "UNKNOWN":
                self.store("<licenses>")
                self.store("<license>")
                self.store(f'<id>"{license_id}"</id>')
                license_url = self.license.get_license_url(license_id)
                if license_url is not None:
                    self.store(f'<url>"{license_url}"</url>')
                self.store("</license>")
                self.store("</licenses>")
        if self.include_purl:
            self.store(f"<purl>pkg:{self.package_manager}/{name}@{version}</purl>")
        self.store("</component>")
