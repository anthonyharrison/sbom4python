# Copyright (C) 2022 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import uuid
from datetime import datetime

from sbom4python.license import LicenseScanner


class SPDXGenerator:
    """
    Generate SPDX Tag/Value SBOM.
    """

    SPDX_VERSION = "SPDX-2.2"
    DATA_LICENSE = "CC0-1.0"
    SPDX_NAMESPACE = "http://spdx.org/spdxdocs/"
    SPDX_LICENSE_VERSION = "3.9"
    SPDX_PROJECT_ID = "SPDXRef-DOCUMENT"
    PACKAGE_PREAMBLE = "SPDXRef-Package-"
    LICENSE_PREAMBLE = "LicenseRef-"

    def __init__(
        self,
        include_license: False,
        spdx_format="tag",
        application="sbom4python",
        version="0.1",
    ):

        self.package_id = 0
        self.include_license = include_license
        self.license = LicenseScanner()
        self.relationship = []
        self.format = spdx_format
        self.application = application
        self.application_version = version
        if self.format == "tag":
            self.doc = []
        else:
            self.doc = {}
            self.component = []
            self.relationships = []
        self.include_purl = False

    def set_purl(self, package_manager):
        self.include_purl = True
        self.package_manager = package_manager

    def show(self, message):
        self.doc.append(message)

    def getBOM(self):
        if self.format != "tag":
            # Add subcomponents to SBOM
            self.doc["packages"] = self.component
            self.doc["relationships"] = self.relationships
        return self.doc

    def getRelationships(self):
        return self.relationship

    def generateTag(self, tag, value):
        self.show(tag + ": " + value)

    def generateComment(self, comment):
        self.show("##### " + comment)

    def generateTime(self):
        # Generate data/time label in format YYYY-MM-DDThh:mm:ssZ
        return datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    def generateTagDocumentHeader(self, project_name):
        # Geerate SPDX Document Header
        self.generateTag("SPDXVersion", self.SPDX_VERSION)
        self.generateTag("DataLicense", self.DATA_LICENSE)
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
        self.generateTag("LicenseListVersion", self.license.get_license_version())
        self.generateTag(
            "Creator: Tool", self.application + "-" + self.application_version
        )
        self.generateTag("Created", self.generateTime())
        self.generateTag(
            "CreatorComment",
            "<text>This document has been automatically generated.</text>",
        )
        return self.SPDX_PROJECT_ID

    def generateJSONDocumentHeader(self, project_name):
        # Generate SPDX Document Header
        self.doc["SPDXID"] = self.SPDX_PROJECT_ID
        self.doc["spdxVersion"] = self.SPDX_VERSION
        creation_info = dict()
        creation_info["comment"] = "This document has been automatically generated."
        creation_info["creators"] = [
            "Tool: " + self.application + "-" + self.application_version
        ]
        creation_info["created"] = self.generateTime()
        creation_info["licenseListVersion"] = self.license.get_license_version()
        self.doc["creationInfo"] = creation_info
        # Project name mustn't have spaces in. Covert spaces to '-'
        self.doc["name"] = project_name.replace(" ", "-")
        self.doc["dataLicense"] = self.DATA_LICENSE
        self.doc["documentNamespace"] = (
            self.SPDX_NAMESPACE
            + project_name.replace(" ", "-")
            + "-"
            + str(uuid.uuid4())
        )
        # self.doc["documentDescribes"]=[self.SPDX_PROJECT_ID]
        return self.SPDX_PROJECT_ID

    def generateDocumentHeader(self, project_name):
        if self.format == "tag":
            return self.generateTagDocumentHeader(project_name)
        else:
            return self.generateJSONDocumentHeader(project_name)

    def package_ident(self, id):
        # Only add preamble if not parent document
        if id != self.SPDX_PROJECT_ID:
            return self.PACKAGE_PREAMBLE + str(id)
        return str(id)

    def license_ident(self, license):
        if not self.include_license:
            if license != "UNKNOWN":
                derived_license = self.license.find_license(license)
                if derived_license != "UNKNOWN":
                    return derived_license
        return "NOASSERTION"

    def generateTagPackageDetails(
        self, package, id, version, supplier, license, parent_id, relationship
    ):
        self.generateComment("\n")
        self.generateTag("PackageName", package)
        package_id = self.package_ident(id)
        self.generateTag("SPDXID", package_id)
        # Attempt to detect an organization
        if len(supplier.split()) > 2:
            # Supplier name mustn't have spaces in. Covert spaces to '_'
            self.generateTag(
                "PackageSupplier: Organization", supplier.replace(" ", "_")
            )
        elif len(supplier) > 0:
            # Supplier name mustn't have spaces in. Covert spaces to '_'
            self.generateTag("PackageSupplier: Person", supplier.replace(" ", "_"))
        else:
            self.generateTag("PackageSupplier", "NOASSERTION")
        self.generateTag("PackageVersion", version)
        self.generateTag("PackageDownloadLocation", "NOASSERTION")
        self.generateTag("FilesAnalyzed", "false")
        self.generateComment("Reported license " + license)
        self.generateTag("PackageLicenseConcluded", self.license_ident(license))
        self.generateTag("PackageLicenseDeclared", self.license_ident(license))
        self.generateTag("PackageCopyrightText", "NOASSERTION")
        if self.include_purl:
            self.generateTag(
                "ExternalRef",
                f"PACKAGE-MANAGER purl pkg:{self.package_manager}/{package}@{version}",
            )
        self.generateRelationship(
            self.package_ident(parent_id), package_id, relationship
        )

    def generateJSONPackageDetails(
        self, package, id, version, supplier, license, parent_id, relationship
    ):
        component = dict()
        package_id = self.package_ident(id)
        component["SPDXID"] = package_id
        component["name"] = package
        component["versionInfo"] = version
        # Attempt to detect an organization
        if len(supplier.split()) > 2:
            # Supplier name mustn't have spaces in. Covert spaces to '_'
            component["supplier"] = "Organization: " + supplier.replace(" ", "_")
        elif len(supplier) >0:
            # Supplier name mustn't have spaces in. Covert spaces to '_'
            component["supplier"] = "Person: " + supplier.replace(" ", "_")
        else:
            component["supplier"] = "NOASSERTION"
        component["downloadLocation"] = "NONE"
        component["filesAnalyzed"] = False
        component["licenseConcluded"] = self.license_ident(license)
        component["licenseDeclared"] = self.license_ident(license)
        component["copyrightText"] = "NOASSERTION"
        if self.include_purl:
            purl_data = dict()
            purl_data["referenceCategory"] = "PACKAGE-MANAGER"
            purl_data[
                "referenceLocator"
            ] = f"pkg:{self.package_manager}/{package}@{version}"
            purl_data["referenceType"] = "purl"
            component["externalRefs"] = [purl_data]
        self.component.append(component)
        self.generateRelationship(
            self.package_ident(parent_id), package_id, relationship
        )

    def generatePackageDetails(
        self, package, id, version, supplier, license, parent_id, relationship
    ):
        if self.format == "tag":
            self.generateTagPackageDetails(
                package, id, version, supplier, license, parent_id, relationship
            )
        else:
            self.generateJSONPackageDetails(
                package, id, version, supplier, license, parent_id, relationship
            )

    def generateRelationship(self, from_id, to_id, relationship_type):
        self.relationship.append([from_id, to_id, relationship_type])

    def showRelationship(self):
        self.relationship.sort()
        for r in self.relationship:
            if self.format == "tag":
                self.generateTag("Relationship", r[0] + r[2] + r[1])
            else:
                relation = dict()
                relation["spdxElementId"] = r[0]
                relation["relatedSpdxElement"] = r[1]
                relation["relationshipType"] = r[2].strip()
                self.relationships.append(relation)
