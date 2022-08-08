# Copyright (C) 2022 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0


import json
import os


class LicenseScanner:

    APACHE_SYNOYMNS = ["Apache Software License", "Apache License, Version 2.0", "Apache 2.0", "Apache 2"]

    def __init__(self):
        # Load licenses
        license_dir, filename = os.path.split(__file__)
        license_path = os.path.join(license_dir, "license_data", "spdx_licenses.json")
        licfile = open(license_path)
        self.licenses = json.load(licfile)

    def check_synoymn(self, license, synoymns, value):
        return value if license in synoymns else None

    def find_license(self, license):
        # Search list of licenses to find match

        default_license = "UNKNOWN"
        for lic in self.licenses["licenses"]:
            # Comparisons ignore case of provided license text
            if lic["licenseId"].lower() == license.lower():
                return lic["licenseId"]
            elif lic["name"].lower() == license.lower():
                return lic["licenseId"]
        license_id = self.check_synoymn(license, self.APACHE_SYNOYMNS, "Apache-2.0")
        return license_id if license_id is not None else default_license
