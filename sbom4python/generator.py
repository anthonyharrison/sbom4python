# Copyright (C) 2022 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

from sbom4python.cyclonedxgenerator import CycloneDXGenerator
from sbom4python.spdxgenerator import SPDXGenerator


class SBOMGenerator:
    """
    Simple SBOM Generator.
    """

    def __init__(self, include_license: False, sbom_type="spdx", format="tag"):
        if sbom_type == "spdx":
            self.bom = SPDXGenerator(include_license, format)
        else:
            self.bom = CycloneDXGenerator(include_license)

    def generate_spdx(self, project_name, packages):
        self.sbom_complete = False
        project_id = self.bom.generateDocumentHeader(project_name)
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
                    product,
                    str(id) + "-" + product,
                    version,
                    supplier,
                    licence,
                    parent_id,
                    relationship,
                )
                id = id + 1
            else:
                if parent == "-":
                    parent_id = project_id
                    relationship = " DESCRIBES "
                else:
                    relationship = " CONTAINS "
                    parent_id = package_set[parent]
                if parent_id is not None:
                    self.bom.generateRelationship(
                        self.bom.package_ident(parent_id),
                        self.bom.package_ident(package_set[product]),
                        relationship,
                    )

    def get_spdx(self):
        if not self.sbom_complete:
            self.bom.showRelationship()
            self.sbom_complete = True
        return self.bom.getBOM()

    def get_relationships(self):
        return self.bom.getRelationships()

    def get_cyclonedx(self):
        return self.bom.getBOM()

    def generate_cyclonedx(self, project_name, packages):
        # project_id = self.bom.generateDocumentHeader(project_name)
        # Process list of packages
        id = 1
        package_set = {}
        for package in packages:
            product = package[1]
            version = package[2]
            supplier = package[3]
            # licence = package[4]
            parent = package[0].lower()
            if product not in package_set:
                package_set[product] = str(id) + "-" + product
                if parent == "-":
                    # parent_id = project_id
                    # relationship = " DESCRIBES "
                    type = "application"
                else:
                    # parent_id = package_set[parent]
                    # relationship = " CONTAINS "
                    type = "library"
                self.bom.generateComponent(type, product, supplier, version)
                id = id + 1
